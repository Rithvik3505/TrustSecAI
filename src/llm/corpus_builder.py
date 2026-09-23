"""Build the TrustSecAI pilot SFT corpus from existing evidence artifacts."""

from __future__ import annotations

import argparse
import json
from copy import deepcopy
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

from .curriculum import get_level, iter_levels
from .export_jsonl import write_jsonl, write_pretty_json
from .diversity_analyzer import analyze_diversity, write_diversity_report
from .prompt_library import PROMPT_TEMPLATES, get_template, iter_templates
from .quality_checks import validate_records
from .statistics import (
    compute_statistics,
    write_final_corpus_report,
    write_generation_report,
    write_statistics_report,
    write_training_readiness_report,
)
from .synthetic_generator import (
    generate_output,
    limit_graph_context,
    make_ids_input,
    make_multiturn_output,
    make_shap_input,
)


DEFAULT_RETRIEVAL_DIR = Path("artifacts/retrieval")
DEFAULT_SHAP_PATH = Path("artifacts/shap/sample_explanations.json")
DEFAULT_OUTPUT_DIR = Path("artifacts/corpus")
DEFAULT_REPORTS_DIR = Path("reports")
PILOT_TARGET = 240
FINAL_TARGET = 5000


def load_json(path: Path) -> Any:
    """Load a UTF-8 JSON file."""

    return json.loads(path.read_text(encoding="utf-8"))


def load_retrieval_contexts(path: Path = DEFAULT_RETRIEVAL_DIR) -> List[Dict[str, Any]]:
    """Load retrieval contexts, excluding summary files."""

    contexts: List[Dict[str, Any]] = []
    for file_path in sorted(path.glob("*.json")):
        if file_path.name == "validation_summary.json":
            continue
        data = load_json(file_path)
        if isinstance(data, dict) and data.get("prediction"):
            data["_source_path"] = file_path.as_posix()
            contexts.append(data)
    return contexts


def fallback_features(prediction: str) -> List[Dict[str, Any]]:
    """Return deterministic fallback SHAP-like features for labels without local SHAP samples."""

    feature_sets = {
        "PortScan": [
            ("Destination Port", 80, 0.041),
            ("Flow Packets/s", 312.4, 0.033),
            ("SYN Flag Count", 1, 0.029),
            ("Total Fwd Packets", 7, 0.021),
            ("Flow Duration", 10321, 0.018),
        ],
        "FTP-Patator": [
            ("Destination Port", 21, 0.052),
            ("Flow Duration", 20492, 0.031),
            ("Total Fwd Packets", 12, 0.025),
            ("ACK Flag Count", 1, 0.019),
            ("Init_Win_bytes_forward", 8192, 0.017),
        ],
        "Bot": [
            ("Flow Bytes/s", 1520.1, 0.038),
            ("Destination Port", 443, 0.028),
            ("Flow Duration", 78231, 0.026),
            ("Total Backward Packets", 5, 0.02),
            ("Packet Length Mean", 88.2, 0.016),
        ],
        "Web Attack - Sql Injection": [
            ("Destination Port", 80, 0.046),
            ("Flow Duration", 34102, 0.029),
            ("Total Length of Fwd Packets", 892, 0.024),
            ("PSH Flag Count", 1, 0.019),
            ("Average Packet Size", 121.5, 0.017),
        ],
    }
    rows = feature_sets.get(
        prediction,
        [
            ("Destination Port", 80, 0.02),
            ("Flow Duration", 10000, 0.018),
            ("Total Fwd Packets", 5, 0.015),
            ("Packet Length Mean", 100.0, 0.012),
            ("ACK Flag Count", 1, 0.01),
        ],
    )
    return [
        {"feature": feature, "value": value, "shap_value": shap_value}
        for feature, value, shap_value in rows
    ]


def load_shap_by_label(path: Path = DEFAULT_SHAP_PATH) -> Dict[str, List[Dict[str, Any]]]:
    """Load local SHAP examples by multiclass label."""

    if not path.exists():
        return {}
    samples = load_json(path)
    by_label: Dict[str, List[Dict[str, Any]]] = {}
    for sample in samples:
        label = sample.get("multiclass_label")
        if label:
            by_label.setdefault(label, []).append(sample)
    return by_label


def choose_shap(
    prediction: str, shap_by_label: Mapping[str, List[Dict[str, Any]]], index: int
) -> Dict[str, Any]:
    """Choose an available SHAP sample or deterministic fallback for a prediction."""

    candidates = shap_by_label.get(prediction) or shap_by_label.get("BENIGN") or []
    if candidates:
        sample = deepcopy(candidates[index % len(candidates)])
        sample["shap_source"] = "artifacts/shap/sample_explanations.json"
        return sample
    return {
        "sample_id": f"fallback-{prediction}",
        "prediction_name": "ATTACK",
        "confidence": 0.85,
        "source_file": "graph_retrieval_context",
        "top_features": fallback_features(prediction),
        "shap_source": "deterministic_fallback",
    }


def confidence_for_variant(base_index: int, variant: str, difficulty: str) -> float:
    """Return deterministic classifier confidence."""

    if variant == "negative":
        return 0.42 if base_index % 2 == 0 else 0.55
    if variant == "agreement":
        return 0.96 if base_index % 2 == 0 else 0.58
    if difficulty == "expert":
        return 0.71
    if difficulty == "hard":
        return 0.78
    if difficulty == "medium":
        return 0.88
    return 0.96


def build_input(
    seed: Mapping[str, Any],
    graph_context: Mapping[str, Any],
    confidence: float,
    difficulty: str,
) -> Dict[str, Any]:
    """Build the approved schema input object."""

    return {
        "ids": make_ids_input(seed, confidence),
        "shap": make_shap_input(seed),
        "graph_context": graph_context,
        "analyst_constraints": {
            "use_only_supplied_context": True,
            "cite_provenance": True,
            "difficulty": difficulty,
            "output_format": "structured_json",
        },
    }


def source_ids(graph_context: Mapping[str, Any]) -> Dict[str, Any]:
    """Collect key source IDs for metadata."""

    attack = graph_context.get("attack", {})
    technique = attack.get("technique", {})
    return {
        "technique": technique.get("id"),
        "tactics": [item.get("id") for item in attack.get("tactics", [])],
        "capec": [item.get("id") for item in graph_context.get("capec", [])],
        "cwes": [item.get("id") for item in graph_context.get("cwes", [])],
        "cves": [item.get("id") for item in graph_context.get("cves", [])],
    }


def build_record(
    example_id: str,
    template_id: str,
    context: Mapping[str, Any],
    seed: Mapping[str, Any],
    difficulty: str,
    variant: str,
    sequence_index: int,
    split: str = "pilot",
) -> Dict[str, Any]:
    """Build one unified SFT record."""

    template = get_template(template_id)
    level = get_level(difficulty)
    confidence = confidence_for_variant(sequence_index, variant, difficulty)
    limited_context = limit_graph_context(context, level.context_limits)
    input_obj = build_input(seed, limited_context, confidence, difficulty)

    if variant == "multi_turn":
        instruction = (
            "Continue the grounded SOC analyst conversation using only the supplied "
            "TrustSecAI context. Answer the incident report, evidence explanation, "
            "and mitigation follow-up without adding unsupported facts."
        )
        output = make_multiturn_output(
            input_obj["ids"], input_obj["shap"], limited_context, sequence_index
        )
        task_type = "multi_turn_security_analysis"
    else:
        instruction = template.instruction
        output = generate_output(
            template_id,
            input_obj["ids"],
            input_obj["shap"],
            limited_context,
            difficulty,
            variant,
            sequence_index,
        )
        task_type = template.task_type
        if variant == "negative" and "unsupported" not in json.dumps(output).lower():
            output["uncertainty_caveat"] = (
                "Unsupported conclusions should be avoided; use only supplied IDS, SHAP, "
                "graph context, and provenance."
            )

    if variant == "multi_turn":
        input_obj["conversation"] = [
            {"role": "user", "content": "Create an incident report for this alert."},
            {"role": "user", "content": "Explain the evidence supporting the assessment."},
            {"role": "user", "content": "Discuss the most relevant mitigations."},
        ]

    return {
        "instruction": instruction,
        "input": input_obj,
        "output": output,
        "metadata": {
            "example_id": example_id,
            "category": "synthetic_sft",
            "task_type": task_type,
            "template_id": template_id,
            "difficulty": difficulty,
            "variant": variant,
            "source_datasets": ["CICIDS2017", "ATT&CK", "CAPEC", "NVD"],
            "source_ids": source_ids(limited_context),
            "generation_method": "deterministic_template_plus_retrieval_context",
            "quality_checks": [
                "malformed_json",
                "duplicate_examples",
                "missing_provenance",
                "invented_security_ids",
                "unsupported_attribution",
            ],
            "provenance_required": True,
            "created_at": date.today().isoformat(),
            "trustsecai_version": "week2-final",
            "split": split,
        },
    }


def variant_plan() -> List[str]:
    """Return deterministic variant mix."""

    return ["standard", "negative", "agreement"]


def generate_pilot_records(
    target: int = PILOT_TARGET,
    example_prefix: str = "trustsecai-pilot",
    split: str = "pilot",
) -> List[Dict[str, Any]]:
    """Generate the deterministic pilot corpus records."""

    contexts = load_retrieval_contexts()
    if not contexts:
        raise FileNotFoundError("No retrieval contexts found under artifacts/retrieval")
    shap_by_label = load_shap_by_label()
    records: List[Dict[str, Any]] = []
    counter = 1

    multi_turn_target = min(max(len(contexts) * 3, target // 10), max(len(contexts), target // 4))
    remainder = multi_turn_target % len(contexts)
    if remainder:
        multi_turn_target += len(contexts) - remainder
    standard_target = target - multi_turn_target

    standard_groups = [
        (level.name, template.template_id, variant)
        for template in iter_templates()
        for level in iter_levels()
        for variant in variant_plan()
    ]
    group_count = standard_target // len(contexts)
    selected_group_indexes = [
        int(index * len(standard_groups) / group_count)
        for index in range(group_count)
    ]
    for group_index in selected_group_indexes:
        difficulty, template_id, variant = standard_groups[group_index]
        for context_index, context in enumerate(contexts):
            prediction = context["prediction"]
            seed = choose_shap(prediction, shap_by_label, context_index)
            seed["prediction"] = prediction
            seed.setdefault("source_file", context.get("_source_path", "graph_retrieval_context"))
            records.append(
                build_record(
                    example_id=f"{example_prefix}-{counter:06d}",
                    template_id=template_id,
                    context=context,
                    seed=seed,
                    difficulty=difficulty,
                    variant=variant,
                    sequence_index=counter,
                    split=split,
                )
            )
            counter += 1

    multi_turn_difficulties = ("medium", "hard", "expert")
    while len(records) < target:
        offset = len(records) - standard_target
        context_index = offset % len(contexts)
        difficulty = multi_turn_difficulties[offset % len(multi_turn_difficulties)]
        context = contexts[context_index]
        prediction = context["prediction"]
        seed = choose_shap(prediction, shap_by_label, context_index)
        seed["prediction"] = prediction
        records.append(
            build_record(
                example_id=f"{example_prefix}-{counter:06d}",
                template_id="incident_report",
                context=context,
                seed=seed,
                difficulty=difficulty,
                variant="multi_turn",
                sequence_index=counter,
                split=split,
            )
        )
        counter += 1
    return records


def write_quality_report(quality: Mapping[str, Any], path: Path) -> None:
    """Write quality report JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(quality, indent=2, sort_keys=True), encoding="utf-8")


def run(target: int = PILOT_TARGET, final: bool = False) -> Dict[str, Any]:
    """Generate, validate, export, and report on a corpus."""

    records = generate_pilot_records(
        target=target,
        example_prefix="trustsecai-final" if final else "trustsecai-pilot",
        split="final" if final else "pilot",
    )
    quality = validate_records(records)
    if quality["rejected"]:
        rejected = {item["index"] for item in quality["errors"]}
        records = [record for index, record in enumerate(records) if index not in rejected]
        quality = validate_records(records)

    DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if final:
        jsonl_path = DEFAULT_OUTPUT_DIR / "final_dataset.jsonl"
        pretty_path = DEFAULT_OUTPUT_DIR / "final_dataset_pretty.json"
        quality_path = DEFAULT_OUTPUT_DIR / "final_quality_report.json"
    else:
        jsonl_path = DEFAULT_OUTPUT_DIR / "pilot_dataset.jsonl"
        pretty_path = DEFAULT_OUTPUT_DIR / "pilot_dataset_pretty.json"
        quality_path = DEFAULT_OUTPUT_DIR / "quality_report.json"
    write_jsonl(records, jsonl_path)
    write_pretty_json(records, pretty_path)
    write_quality_report(quality, quality_path)

    stats = compute_statistics(records, quality)
    diversity = analyze_diversity(records)
    write_diversity_report(diversity, DEFAULT_REPORTS_DIR / "dataset_diversity_report.md")
    if final:
        write_final_corpus_report(stats, diversity, DEFAULT_REPORTS_DIR / "final_corpus_report.md")
        write_training_readiness_report(
            stats, diversity, DEFAULT_REPORTS_DIR / "training_readiness.md"
        )
    else:
        write_statistics_report(stats, DEFAULT_REPORTS_DIR / "corpus_statistics.md")
        write_generation_report(stats, DEFAULT_REPORTS_DIR / "corpus_generation_report.md")
    return {
        "records": len(records),
        "quality": quality,
        "statistics": stats,
        "diversity": diversity,
        "outputs": {
            "jsonl": jsonl_path.as_posix(),
            "pretty": pretty_path.as_posix(),
            "quality": quality_path.as_posix(),
        },
    }


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=int, default=PILOT_TARGET, help="Pilot dataset size")
    parser.add_argument(
        "--final",
        action="store_true",
        help=f"Write final corpus artifacts; default target should be {FINAL_TARGET}",
    )
    return parser.parse_args()


def main() -> None:
    """CLI entry point."""

    args = parse_args()
    result = run(target=args.target, final=args.final)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
