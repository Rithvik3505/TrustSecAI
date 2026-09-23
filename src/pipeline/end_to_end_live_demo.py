"""Review-safe TrustSecAI end-to-end local demo.

The classifier step runs live. LoRA text is loaded from frozen HPC evaluation
artifacts, so this module does not require a GPU or local Llama model.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import pandas as pd

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.analysis.agreement import analyze_agreement
from src.analysis.attack_chain import predict_attack_chain
from src.llm.integration.lora_client import DEFAULT_GENERATIONS_FILE, LoraClient, load_jsonl
from src.llm.integration.prompt_builder import extract_supplied_context
from src.llm.integration.response_parser import parse_lora_output
from src.pipeline.classifier_live_predict import (
    SAMPLE_PATH,
    binary_ground_truth,
    load_classifier_artifacts,
    load_demo_samples,
    load_model,
    predict_sample,
    prepare_feature_frame,
    select_sample,
)
from src.pipeline.trustsecai_demo import compact_graph_summary
from src.reporting.security_report_builder import build_security_report


DEFAULT_OUTPUT_DIR = Path("artifacts/demo/live_end_to_end")
DEMO_EXAMPLE_BY_LABEL = {
    "Web Attack - Sql Injection": "trustsecai-gold-v1-00575",
    "PortScan": "trustsecai-gold-v1-00178",
    "FTP-Patator": "trustsecai-gold-v1-00810",
    "Bot": "trustsecai-gold-v1-00381",
    "DDoS": "trustsecai-gold-v1-00128",
}


def parse_feature_overrides(items: list[str] | None) -> dict[str, float]:
    """Parse CLI feature overrides in `Feature Name=value` format."""

    overrides: dict[str, float] = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"Invalid override `{item}`. Expected `Feature Name=value`.")
        feature, value = item.split("=", 1)
        feature = feature.strip()
        if not feature:
            raise ValueError(f"Invalid override `{item}`. Feature name is empty.")
        try:
            overrides[feature] = float(value.strip())
        except ValueError as exc:
            raise ValueError(f"Invalid numeric value in override `{item}`.") from exc
    return overrides


def _safe_key(value: str) -> str:
    return value.replace("/", "_").replace("\\", "_").replace(" ", "_")


def _label_from_lora_row(row: dict[str, Any]) -> str | None:
    metadata = row.get("metadata", {})
    return row.get("ids_label") or metadata.get("ids_label")


def resolve_lora_row(example_id: str | None, label: str | None, generations_file: Path) -> dict[str, Any] | None:
    """Resolve a frozen LoRA row by example_id or known demo label."""

    client = LoraClient(generations_file=generations_file, mode="offline")
    if example_id:
        return client.get_generation(example_id=example_id)
    if label and label in DEMO_EXAMPLE_BY_LABEL:
        return client.get_generation(example_id=DEMO_EXAMPLE_BY_LABEL[label])
    if label:
        for row in load_jsonl(generations_file):
            if _label_from_lora_row(row) == label:
                return row
    return None


def _try_live_shap(model: Any, feature_frame: pd.DataFrame, max_features: int = 5) -> tuple[dict[str, Any] | None, str | None]:
    """Best-effort live local SHAP calculation for one row."""

    try:
        import shap
    except ImportError:
        return None, "Live SHAP unavailable; package `shap` is not installed."

    try:
        explainer = shap.TreeExplainer(model)
        values = explainer.shap_values(feature_frame)
        if isinstance(values, list):
            row_values = values[1][0] if len(values) > 1 else values[0][0]
        else:
            row_values = values[0]
        features = []
        for feature, shap_value, raw_value in zip(feature_frame.columns, row_values, feature_frame.iloc[0], strict=False):
            value = float(shap_value)
            features.append(
                {
                    "feature": feature,
                    "value": raw_value.item() if hasattr(raw_value, "item") else raw_value,
                    "shap_value": round(value, 4),
                    "direction": "supports_attack" if value > 0 else "supports_benign",
                }
            )
        features = sorted(features, key=lambda item: abs(float(item["shap_value"])), reverse=True)[:max_features]
        return {"source": "live_shap", "top_features": features}, None
    except Exception as exc:  # noqa: BLE001 - live SHAP is optional in this demo.
        return None, f"Live SHAP unavailable; using stored evidence if available. Reason: {exc}"


def _stored_shap_from_lora(row: dict[str, Any] | None) -> dict[str, Any]:
    if not row:
        return {"source": "unavailable", "top_features": []}
    context = extract_supplied_context(row)
    shap_context = context.get("shap", {}) if isinstance(context, dict) else {}
    if shap_context:
        shap_context = dict(shap_context)
        shap_context.setdefault("source", "frozen_lora_prompt_context")
        return shap_context
    return {"source": "unavailable", "top_features": []}


def _select_classifier_row(
    samples: pd.DataFrame,
    requested_label: str | None,
    row_number: int | None,
    random_sample: bool,
) -> pd.Series:
    """Select a classifier sample for live inference."""

    if requested_label:
        try:
            return select_sample(samples, row_number=None, label=requested_label, random_sample=False)
        except ValueError:
            pass
    return select_sample(samples, row_number=row_number, label=None, random_sample=random_sample)


def build_end_to_end_payload(
    example_id: str | None = None,
    label: str | None = None,
    row_number: int | None = None,
    random_sample: bool = False,
    generations_file: Path = DEFAULT_GENERATIONS_FILE,
    use_graph_attack_chain: bool = True,
    prefer_live_shap: bool = True,
    feature_overrides: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Run live classifier inference and compose the end-to-end demo payload."""

    os.environ.setdefault("NEO4J_URI", "bolt://127.0.0.1:7687")
    lora_row = resolve_lora_row(example_id=example_id, label=label, generations_file=generations_file)
    lora_label = _label_from_lora_row(lora_row) if lora_row else None
    requested_label = label or lora_label

    artifacts = load_classifier_artifacts()
    model = load_model(artifacts.model_path)
    samples = load_demo_samples()
    sample_row = _select_classifier_row(samples, requested_label, row_number=row_number, random_sample=random_sample)
    if feature_overrides:
        unknown = sorted(set(feature_overrides) - set(artifacts.feature_columns))
        if unknown:
            raise ValueError(f"Unknown model feature override(s): {unknown}")
        sample_row = sample_row.copy()
        for feature, value in feature_overrides.items():
            sample_row[feature] = value
    feature_frame, missing, extra = prepare_feature_frame(sample_row, artifacts.feature_columns)
    if missing:
        raise ValueError(f"Feature mismatch. Missing columns: {missing}. Extra columns: {extra[:20]}")

    live_prediction = predict_sample(model, feature_frame)
    true_binary = binary_ground_truth(sample_row.get("label"), sample_row.get("binary_label"))
    binary_correct = None if true_binary is None else live_prediction["prediction_value"] == true_binary

    lora_context = extract_supplied_context(lora_row) if lora_row else {}
    live_shap, shap_warning = _try_live_shap(model, feature_frame) if prefer_live_shap else (None, "Live SHAP disabled.")
    shap_evidence = live_shap or _stored_shap_from_lora(lora_row)
    if shap_warning:
        shap_evidence["fallback_note"] = shap_warning

    graph_summary = compact_graph_summary(lora_context, lora_row or {}) if lora_row else {
        "technique": {},
        "tactics": [],
        "mitigation_ids": [],
        "capec_ids": [],
        "cwe_ids": [],
        "cve_ids": [],
        "provenance_type": "unavailable",
        "has_cve": False,
    }
    graph_summary["context_mode"] = "cached_frozen_lora_context" if lora_row else "unavailable"

    parsed_llm = (
        parse_lora_output(lora_row.get("generation", ""))
        if lora_row
        else {
            "parse_ok": False,
            "ids_label": requested_label,
            "sample_id": sample_row.get("sample_id"),
            "classifier_evidence": None,
            "shap_evidence": None,
            "graph_interpretation": "No frozen LoRA output available for this selected sample.",
            "limitations": ["No frozen LoRA output is available for the selected sample."],
            "provenance_summary": [],
            "recommended_actions": [],
            "raw_output": "",
        }
    )

    classifier_evidence = {
        "ids_label": requested_label or sample_row.get("label"),
        "model_prediction": live_prediction["prediction"],
        "model_confidence": live_prediction["confidence"],
        "attack_probability": live_prediction["attack_probability"],
        "benign_probability": live_prediction["benign_probability"],
        "confidence_band": (
            "high" if live_prediction["confidence"] >= 0.9 else "medium" if live_prediction["confidence"] >= 0.5 else "low"
        ),
        "sample_id": sample_row.get("sample_id", f"row-{int(sample_row.name) + 1}"),
        "source_file": sample_row.get("source_file"),
        "true_ids_label": sample_row.get("label"),
        "binary_ground_truth": true_binary,
        "binary_correct": binary_correct,
        "feature_count": len(artifacts.feature_columns),
        "model_path": str(artifacts.model_path),
        "sample_data_path": str(SAMPLE_PATH),
        "excluded_from_prediction": ["label", "binary_label", "source_file", "sample_id"],
        "feature_overrides": feature_overrides or {},
    }
    evidence_flags = {
        "has_real_shap": bool(shap_evidence.get("top_features")),
        "has_cve": bool(graph_summary.get("cve_ids")),
        "requires_vulnerability_context": False,
    }
    agreement = analyze_agreement(
        classifier_prediction=live_prediction["prediction"],
        classifier_confidence=live_prediction["confidence"],
        ids_label=classifier_evidence["ids_label"],
        parsed_llm_output=parsed_llm,
        evidence_flags=evidence_flags,
    )
    attack_chain = predict_attack_chain(
        classifier_evidence["ids_label"],
        graph_summary,
        use_graph=use_graph_attack_chain,
    )
    graph_mode = "live_neo4j_attack_chain" if attack_chain.get("mode") == "graph" else "cached_context_static_fallback"
    limitations = [
        "Live demo runs classifier inference, response parsing, agreement analysis, attack-chain logic, and report assembly.",
        "LoRA text generation is cached from HPC compact evaluation outputs and is not executed locally.",
        "Graph context in the report is contextual intelligence, not proof of compromise or attribution.",
    ]
    report = build_security_report(
        classifier_evidence=classifier_evidence,
        shap_evidence=shap_evidence,
        graph_context_summary=graph_summary,
        llm_secondary_assessment=parsed_llm,
        agreement_result=agreement,
        attack_chain_prediction=attack_chain,
        limitations=limitations,
    )

    return {
        "demo_mode": "end_to_end_live_local",
        "neo4j_uri": os.getenv("NEO4J_URI"),
        "live_components": ["classifier", "feature_extraction", "report_assembly", "agreement_analysis", "attack_chain_logic"],
        "cached_components": ["lora_text_generation_from_hpc_evaluation", "graph_context_from_frozen_lora_prompt"],
        "lora_generation_available": bool(lora_row),
        "lora_generation_file": str(generations_file),
        "selected_lora_example_id": (lora_row or {}).get("example_id") or (lora_row or {}).get("metadata", {}).get("example_id"),
        "graph_context_mode": graph_mode,
        "classifier_evidence": classifier_evidence,
        "shap_evidence": shap_evidence,
        "graph_context_summary": graph_summary,
        "llm_secondary_assessment": parsed_llm,
        "agreement_result": agreement,
        "attack_chain_prediction": attack_chain,
        "limitations": limitations,
        "markdown_report": report,
    }


def save_payload(payload: dict[str, Any], output_dir: Path, key: str) -> dict[str, str]:
    """Save JSON and Markdown demo outputs."""

    output_dir.mkdir(parents=True, exist_ok=True)
    safe = _safe_key(key)
    json_path = output_dir / f"end_to_end_{safe}.json"
    md_path = output_dir / f"end_to_end_{safe}.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(payload["markdown_report"], encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Run local TrustSecAI end-to-end demo with live classifier and cached LoRA output.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--example-id", type=str)
    group.add_argument("--label", type=str)
    group.add_argument("--row-number", type=int)
    group.add_argument("--random", action="store_true")
    parser.add_argument("--lora-generations-file", type=Path, default=DEFAULT_GENERATIONS_FILE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--no-graph-attack-chain", action="store_true", help="Disable Neo4j attack-chain traversal.")
    parser.add_argument(
        "--override-feature",
        action="append",
        default=[],
        help='Override one model feature, for example --override-feature "Destination Port=443".',
    )
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    try:
        payload = build_end_to_end_payload(
            example_id=args.example_id,
            label=args.label,
            row_number=args.row_number,
            random_sample=args.random,
            generations_file=args.lora_generations_file,
            use_graph_attack_chain=not args.no_graph_attack_chain,
            feature_overrides=parse_feature_overrides(args.override_feature),
        )
        key = (
            args.example_id
            or args.label
            or f"row_{args.row_number}"
            or "random"
        )
        paths = save_payload(payload, args.output_dir, key)
    except Exception as exc:  # noqa: BLE001 - CLI should be reviewer-safe.
        print(f"End-to-end live demo failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(json.dumps({
        "json": paths["json"],
        "markdown": paths["markdown"],
        "live_prediction": payload["classifier_evidence"].get("model_prediction"),
        "confidence": payload["classifier_evidence"].get("model_confidence"),
        "lora_cached": payload["lora_generation_available"],
        "attack_chain_mode": payload["attack_chain_prediction"].get("mode"),
    }, indent=2))


if __name__ == "__main__":
    main()
