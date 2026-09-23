"""Export real evidence contexts for TrustSecAI gold-candidate v1.

The pipeline is intentionally conservative: it will not fabricate classifier
outputs, confidence scores, SHAP values, or graph evidence. If the selected IDS
model artifact is unavailable, the script writes discovery reports and stops.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

try:
    import shap
except Exception:  # pragma: no cover - reported at runtime
    shap = None

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.utils.paths import ARTIFACTS_DIR, MODELS_DIR, PROCESSED_DIR, PROJECT_ROOT, REPORTS_DIR


TARGET_LABELS = ["Bot", "DDoS", "FTP-Patator", "PortScan", "Web Attack - Sql Injection"]
EXCLUDED_COLUMNS = {"label", "binary_label", "source_file"}
OUTPUT_DIR = ARTIFACTS_DIR / "gold_candidates" / "evidence_expansion"
RETRIEVAL_FILES = {
    "Bot": ARTIFACTS_DIR / "retrieval" / "Bot.json",
    "DDoS": ARTIFACTS_DIR / "retrieval" / "DDoS.json",
    "FTP-Patator": ARTIFACTS_DIR / "retrieval" / "FTP_Patator.json",
    "PortScan": ARTIFACTS_DIR / "retrieval" / "PortScan.json",
    "Web Attack - Sql Injection": ARTIFACTS_DIR / "retrieval" / "Web_Attack___Sql_Injection.json",
}


@dataclass(frozen=True)
class Discovery:
    """Artifact discovery result."""

    cleaned_dataset: Path
    xgboost_model_candidates: list[Path]
    feature_metadata_candidates: list[Path]
    shap_artifacts: list[Path]
    retrieval_contexts: dict[str, Path]
    attack_label_mapping: Path
    missing: list[str]
    assumptions: list[str]
    feature_order_recoverable: bool
    model_inference_safe: bool
    shap_computable: bool
    blocker: str | None


def rel(path: Path) -> str:
    """Return a readable project-relative path."""

    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def read_json(path: Path) -> Any:
    """Read UTF-8 JSON."""

    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any, pretty: bool = True) -> None:
    """Write UTF-8 JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    kwargs = {"indent": 2, "ensure_ascii": False} if pretty else {"separators": (",", ":"), "ensure_ascii": False}
    path.write_text(json.dumps(obj, **kwargs), encoding="utf-8")


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    """Write JSONL records."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def discover_artifacts(model_path: Path | None = None) -> Discovery:
    """Locate artifacts required for evidence expansion."""

    cleaned_dataset = PROCESSED_DIR / "cleaned_cicids.parquet"
    model_candidates = []
    search_roots = [MODELS_DIR / "xgboost", MODELS_DIR]
    suffixes = {".joblib", ".pkl", ".pickle", ".json", ".ubj", ".model"}
    if model_path:
        model_candidates.append(model_path)
    for root in search_roots:
        if root.exists():
            model_candidates.extend(
                path
                for path in root.rglob("*")
                if path.is_file()
                and path.suffix.lower() in suffixes
                and ("xgb" in path.name.lower() or path.name.lower().startswith("xgboost"))
            )
    model_candidates = sorted(set(model_candidates))

    feature_metadata_candidates = []
    for root in [MODELS_DIR / "xgboost", ARTIFACTS_DIR / "processed", ARTIFACTS_DIR / "metrics"]:
        if root.exists():
            feature_metadata_candidates.extend(path for path in root.rglob("*") if path.is_file() and any(token in path.name.lower() for token in ["feature", "xgboost_metrics"]))

    shap_artifacts = [
        path
        for path in [
            ARTIFACTS_DIR / "shap" / "global_feature_importance.csv",
            ARTIFACTS_DIR / "shap" / "sample_explanations.json",
        ]
        if path.exists()
    ]
    retrieval_contexts = {label: path for label, path in RETRIEVAL_FILES.items() if path.exists()}
    attack_mapping = ARTIFACTS_DIR / "attack_label_mapping.json"

    missing = []
    if not cleaned_dataset.exists():
        missing.append(rel(cleaned_dataset))
    if not model_candidates or not any(path.exists() for path in model_candidates):
        missing.append("models/xgboost saved XGBoost model artifact")
    if not feature_metadata_candidates:
        missing.append("explicit XGBoost feature-order metadata")
    for label, path in RETRIEVAL_FILES.items():
        if not path.exists():
            missing.append(f"retrieval context for {label}: {rel(path)}")
    if not attack_mapping.exists():
        missing.append(rel(attack_mapping))

    assumptions = [
        "The Week 1 XGBoost script trained a binary classifier and did not persist a model artifact in the current repository state.",
        "Feature order can be reconstructed from cleaned_cicids.parquet by excluding label, binary_label, and source_file, but exact model compatibility cannot be verified without the saved XGBoost artifact.",
        "For a binary IDS model, model_prediction is BENIGN/ATTACK; IDS sub-label retrieval must be linked using the real CICIDS ground-truth label, not invented multiclass probabilities.",
    ]
    feature_order_recoverable = cleaned_dataset.exists()
    model_inference_safe = bool(model_candidates and all(path.exists() for path in model_candidates[:1]) and feature_order_recoverable)
    shap_computable = model_inference_safe and shap is not None
    blocker = None
    if not model_inference_safe:
        blocker = "Saved XGBoost model artifact is missing; real model predictions and SHAP cannot be exported safely."
    elif shap is None:
        blocker = "Python SHAP package is unavailable; local SHAP cannot be computed."

    return Discovery(
        cleaned_dataset=cleaned_dataset,
        xgboost_model_candidates=model_candidates,
        feature_metadata_candidates=sorted(set(feature_metadata_candidates)),
        shap_artifacts=shap_artifacts,
        retrieval_contexts=retrieval_contexts,
        attack_label_mapping=attack_mapping,
        missing=missing,
        assumptions=assumptions,
        feature_order_recoverable=feature_order_recoverable,
        model_inference_safe=model_inference_safe,
        shap_computable=shap_computable,
        blocker=blocker,
    )


def write_artifact_inventory(discovery: Discovery) -> None:
    """Write the Phase 1 artifact inventory report."""

    lines = [
        "# Evidence Expansion Artifact Inventory",
        "",
        f"Created: {date.today().isoformat()}",
        "",
        "## Found Artifacts",
        "",
        f"- Cleaned CICIDS dataset: {'found' if discovery.cleaned_dataset.exists() else 'missing'} `{rel(discovery.cleaned_dataset)}`",
        f"- XGBoost model candidates: {', '.join(rel(p) for p in discovery.xgboost_model_candidates) if discovery.xgboost_model_candidates else 'none found'}",
        f"- Feature metadata candidates: {', '.join(rel(p) for p in discovery.feature_metadata_candidates) if discovery.feature_metadata_candidates else 'none found'}",
        f"- SHAP artifacts: {', '.join(rel(p) for p in discovery.shap_artifacts) if discovery.shap_artifacts else 'none found'}",
        f"- Retrieval contexts: {len(discovery.retrieval_contexts)} of {len(TARGET_LABELS)} target labels",
        f"- Attack label mapping: {'found' if discovery.attack_label_mapping.exists() else 'missing'} `{rel(discovery.attack_label_mapping)}`",
        "",
        "## Missing Artifacts",
        "",
    ]
    lines.extend(f"- {item}" for item in discovery.missing)
    lines.extend(
        [
            "",
            "## Safety Assessment",
            "",
            f"- Feature ordering recoverable: {discovery.feature_order_recoverable}",
            f"- Model inference can be run safely: {discovery.model_inference_safe}",
            f"- SHAP can be computed for selected model: {discovery.shap_computable}",
            f"- Blocking issue: {discovery.blocker or 'none'}",
            "",
            "## Assumptions",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in discovery.assumptions)
    (REPORTS_DIR / "evidence_expansion_artifact_inventory.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_blocked_outputs(discovery: Discovery) -> None:
    """Write blocked-state reports when critical evidence cannot be generated."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    quality = {
        "status": "blocked",
        "passed": False,
        "blocker": discovery.blocker,
        "missing_artifacts": discovery.missing,
        "generated_predictions": 0,
        "generated_shap_explanations": 0,
        "expanded_base_contexts": 0,
    }
    write_json(OUTPUT_DIR / "evidence_expansion_quality_report.json", quality)
    write_json(
        OUTPUT_DIR / "evidence_expansion_inventory.json",
        {
            "status": "blocked",
            "blocker": discovery.blocker,
            "found_retrieval_contexts": {label: rel(path) for label, path in discovery.retrieval_contexts.items()},
            "unavailable_evidence_not_synthesized": [
                "classifier predictions",
                "classifier confidence scores",
                "local SHAP explanations for selected rows",
            ],
        },
    )
    for filename in [
        "classifier_examples.jsonl",
        "model_predictions.jsonl",
        "local_shap_expanded.jsonl",
        "expanded_base_contexts.jsonl",
        "gold_v1_source_contexts.jsonl",
    ]:
        (OUTPUT_DIR / filename).write_text("", encoding="utf-8")
    write_json(OUTPUT_DIR / "local_shap_expanded_pretty.json", [])
    write_json(OUTPUT_DIR / "expanded_base_contexts_pretty.json", [])

    reports = {
        "evidence_expansion_sampling_report.md": "No sampling was performed because model inference is blocked.",
        "evidence_expansion_inference_report.md": f"Inference blocked: {discovery.blocker}",
        "evidence_expansion_shap_report.md": f"SHAP generation blocked: {discovery.blocker}",
        "evidence_expansion_inventory.md": f"Evidence expansion blocked: {discovery.blocker}",
        "evidence_expansion_quality_report.md": f"# Evidence Expansion Quality Report\n\n- Status: blocked\n- Passed: false\n- Blocker: {discovery.blocker}\n",
        "gold_candidate_v1_generation_plan.md": (
            "# Gold-Candidate v1 Generation Plan\n\n"
            "Generation should not proceed until a saved XGBoost model artifact with feature order is available.\n\n"
            "Expected command after the model is saved:\n\n"
            "```powershell\npython -m src.llm.evidence_expansion --model-path models/xgboost/xgboost_model.joblib\n```\n\n"
            "After successful evidence expansion, use the exported `artifacts/gold_candidates/evidence_expansion/gold_v1_source_contexts.jsonl` as the v1 builder input.\n"
        ),
    }
    for filename, body in reports.items():
        (REPORTS_DIR / filename).write_text(body + "\n", encoding="utf-8")


def load_model_artifact(model_path: Path) -> tuple[Any, list[str], dict[str, Any]]:
    """Load a saved model artifact with feature metadata."""

    artifact = joblib.load(model_path)
    if isinstance(artifact, dict):
        model = artifact.get("model")
        feature_columns = list(artifact.get("feature_columns") or [])
        metadata = {key: value for key, value in artifact.items() if key != "model"}
    else:
        model = artifact
        feature_columns = []
        metadata = {}
    if model is None:
        raise ValueError(f"No model object found in {model_path}")
    return model, feature_columns, metadata


def recover_feature_columns(dataframe: pd.DataFrame, artifact_features: list[str]) -> list[str]:
    """Recover and validate model feature columns."""

    if artifact_features:
        missing = [column for column in artifact_features if column not in dataframe.columns]
        if missing:
            raise ValueError(f"Feature columns missing from dataframe: {missing[:10]}")
        return artifact_features
    return [column for column in dataframe.columns if column not in EXCLUDED_COLUMNS]


def sample_candidate_rows(dataframe: pd.DataFrame, max_per_label: int, random_state: int) -> pd.DataFrame:
    """Select diverse real CICIDS rows by label/source without fabricating labels."""

    selected = []
    for label in TARGET_LABELS:
        label_frame = dataframe[dataframe["label"] == label].copy()
        if label_frame.empty:
            continue
        grouped = []
        for _, source_group in label_frame.groupby("source_file", dropna=False):
            grouped.append(source_group.sample(n=min(max(1, max_per_label // 3), len(source_group)), random_state=random_state))
        merged = pd.concat(grouped, axis=0).drop_duplicates()
        if len(merged) < max_per_label:
            remaining = label_frame.drop(index=merged.index, errors="ignore")
            if not remaining.empty:
                merged = pd.concat(
                    [merged, remaining.sample(n=min(max_per_label - len(merged), len(remaining)), random_state=random_state)],
                    axis=0,
                )
        selected.append(merged.head(max_per_label))
    if not selected:
        return pd.DataFrame(columns=dataframe.columns)
    return pd.concat(selected, axis=0).sort_index()


def prediction_label(prediction: int) -> str:
    """Return binary prediction label."""

    return "ATTACK" if int(prediction) == 1 else "BENIGN"


def band(confidence: float) -> str:
    """Map confidence to high/medium/low."""

    if confidence >= 0.9:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"


def graph_summary(label: str) -> dict[str, Any]:
    """Summarize saved retrieval context for a label."""

    path = RETRIEVAL_FILES[label]
    graph = read_json(path)
    attack = graph.get("attack", {})
    technique = attack.get("technique", {}) if isinstance(attack, dict) else {}
    provenance = graph.get("provenance", [])
    return {
        "retrieval_context_path": rel(path),
        "attack_technique_id": technique.get("id"),
        "tactic_ids": [item.get("id") for item in attack.get("tactics", [])],
        "mitigation_ids": [item.get("id") for item in attack.get("mitigations", [])],
        "capec_ids": [item.get("id") for item in graph.get("capec", [])],
        "cwe_ids": [item.get("id") for item in graph.get("cwes", [])],
        "cve_ids": [item.get("id") or item.get("cve_id") for item in graph.get("cves", [])],
        "product_ids": [item.get("id") or item.get("name") for item in graph.get("products", [])],
        "provenance_type": "mixed_direct_and_inferred" if any(item.get("inferred") for item in provenance) else "direct",
        "has_inferred_edges": any(item.get("inferred") for item in provenance),
    }


def compute_shap_rows(model: Any, x: pd.DataFrame) -> np.ndarray:
    """Compute local SHAP values for selected rows."""

    if shap is None:
        raise RuntimeError("SHAP package is unavailable")
    explainer = shap.TreeExplainer(model)
    values = explainer.shap_values(x)
    if isinstance(values, list):
        return np.asarray(values[1])
    values_array = np.asarray(values)
    if values_array.ndim == 3:
        return values_array[:, :, 1]
    return values_array


def run_expansion(args: argparse.Namespace) -> None:
    """Run the full evidence expansion after artifact discovery passes."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model, artifact_features, model_metadata = load_model_artifact(args.model_path)
    metadata_columns = ["label", "binary_label", "source_file"]
    dataframe = pd.read_parquet(PROCESSED_DIR / "cleaned_cicids.parquet")
    feature_columns = recover_feature_columns(dataframe, artifact_features)
    if hasattr(model, "n_features_in_") and int(model.n_features_in_) != len(feature_columns):
        raise ValueError(f"Feature count mismatch: model expects {model.n_features_in_}, dataframe has {len(feature_columns)}")

    candidate_rows = sample_candidate_rows(dataframe[feature_columns + metadata_columns], args.max_per_label, args.random_state)
    x = candidate_rows[feature_columns]
    predictions = model.predict(x)
    probabilities = model.predict_proba(x) if hasattr(model, "predict_proba") else None
    shap_values = compute_shap_rows(model, x)

    classifier_records = []
    prediction_records = []
    shap_records = []
    base_contexts = []
    for row_pos, (row_index, row) in enumerate(candidate_rows.iterrows()):
        probability_row = probabilities[row_pos] if probabilities is not None else None
        confidence = float(np.max(probability_row)) if probability_row is not None else None
        pred = int(predictions[row_pos])
        ground_truth = str(row["label"])
        sample_id = int(row_index)
        base_context_id = f"evx-{ground_truth.lower().replace(' ', '_').replace('-', '_')}-{sample_id}"
        selected_features = {feature: float(row[feature]) for feature in feature_columns[:12]}
        classifier_record = {
            "stable_sample_id": sample_id,
            "ids_label_ground_truth": ground_truth,
            "model_prediction": prediction_label(pred),
            "model_confidence": confidence,
            "confidence_band": band(confidence) if confidence is not None else "unavailable",
            "source_file": str(row["source_file"]),
            "selected_feature_values": selected_features,
            "base_context_id": base_context_id,
        }
        classifier_records.append(classifier_record)
        prediction_records.append(
            {
                **classifier_record,
                "binary_prediction": pred,
                "binary_ground_truth": int(row["binary_label"]),
                "correct_prediction": pred == int(row["binary_label"]),
                "class_probabilities": probability_row.astype(float).tolist() if probability_row is not None else None,
                "model_artifact": rel(args.model_path),
            }
        )
        shap_row = shap_values[row_pos]
        top_indices = np.argsort(np.abs(shap_row))[::-1][: args.top_shap_features]
        top_features = [
            {
                "feature": feature_columns[i],
                "value": float(row[feature_columns[i]]),
                "shap_value": float(shap_row[i]),
                "direction": "supports_attack" if float(shap_row[i]) > 0 else "supports_benign",
            }
            for i in top_indices
        ]
        shap_record = {
            "stable_sample_id": sample_id,
            "base_context_id": base_context_id,
            "ids_label_ground_truth": ground_truth,
            "model_prediction": prediction_label(pred),
            "model_confidence": confidence,
            "source_file": str(row["source_file"]),
            "top_features": top_features,
        }
        shap_records.append(shap_record)
        graph = graph_summary(ground_truth)
        base_contexts.append(
            {
                **classifier_record,
                "shap_top_features": top_features,
                **graph,
                "retrieval_label_basis": "ground_truth_ids_label_for_binary_model",
                "evidence_completeness": {
                    "has_real_shap": True,
                    "has_classifier_confidence": confidence is not None,
                    "has_capec": bool(graph["capec_ids"]),
                    "has_cwe": bool(graph["cwe_ids"]),
                    "has_cve": bool(graph["cve_ids"]),
                    "has_products": bool(graph["product_ids"]),
                    "has_inferred_edges": graph["has_inferred_edges"],
                    "has_asset_exposure_evidence": False,
                },
            }
        )

    write_jsonl(OUTPUT_DIR / "classifier_examples.jsonl", classifier_records)
    write_jsonl(OUTPUT_DIR / "model_predictions.jsonl", prediction_records)
    write_jsonl(OUTPUT_DIR / "local_shap_expanded.jsonl", shap_records)
    write_json(OUTPUT_DIR / "local_shap_expanded_pretty.json", shap_records)
    write_jsonl(OUTPUT_DIR / "expanded_base_contexts.jsonl", base_contexts)
    write_json(OUTPUT_DIR / "expanded_base_contexts_pretty.json", base_contexts)
    write_jsonl(OUTPUT_DIR / "gold_v1_source_contexts.jsonl", base_contexts)
    write_success_reports(classifier_records, prediction_records, shap_records, base_contexts, feature_columns, model_metadata)


def write_success_reports(
    classifier_records: list[dict[str, Any]],
    prediction_records: list[dict[str, Any]],
    shap_records: list[dict[str, Any]],
    base_contexts: list[dict[str, Any]],
    feature_columns: list[str],
    model_metadata: dict[str, Any],
) -> None:
    """Write reports for a successful evidence expansion run."""

    label_counts = Counter(item["ids_label_ground_truth"] for item in base_contexts)
    confidence_counts = Counter(item["confidence_band"] for item in base_contexts)
    source_counts = Counter(item["source_file"] for item in base_contexts)
    shap_patterns = defaultdict(set)
    for item in shap_records:
        shap_patterns[item["ids_label_ground_truth"]].add(tuple(feature["feature"] for feature in item["top_features"][:4]))
    quality_flags = []
    duplicate_samples = [sample for sample, count in Counter(item["stable_sample_id"] for item in base_contexts).items() if count > 1]
    duplicate_contexts = [ctx for ctx, count in Counter(item["base_context_id"] for item in base_contexts).items() if count > 1]
    missing_prediction = [item["base_context_id"] for item in base_contexts if not item.get("model_prediction")]
    missing_confidence = [item["base_context_id"] for item in base_contexts if item.get("model_confidence") is None]
    missing_shap = [item["base_context_id"] for item in base_contexts if not item["evidence_completeness"].get("has_real_shap")]
    unsupported = [item["base_context_id"] for item in base_contexts if item.get("ids_label_ground_truth") not in TARGET_LABELS]
    missing_retrieval = [item["base_context_id"] for item in base_contexts if not item.get("retrieval_context_path")]
    shap_profile_counts = Counter(
        tuple(feature["feature"] for feature in item["shap_top_features"][:5])
        for item in base_contexts
    )
    repeated_shap_profiles = [
        {"features": list(features), "count": count}
        for features, count in shap_profile_counts.items()
        if count > 5
    ]
    source_total = len(base_contexts)
    excessive_source_files = [
        {"source_file": source, "count": count, "percentage": round(count / max(1, source_total) * 100, 3)}
        for source, count in source_counts.items()
        if count / max(1, source_total) > 0.35
    ]
    leakage_risk_indicators = {
        "same_source_file_per_label": {
            label: sorted({item["source_file"] for item in base_contexts if item["ids_label_ground_truth"] == label})
            for label in label_counts
        },
        "note": "CICIDS attack labels are often concentrated in one capture day/source_file. v1 train/validation/test splits must group by base_context_id and should consider source_file-aware review.",
    }
    if duplicate_samples:
        quality_flags.append(f"Duplicate sample IDs: {duplicate_samples[:10]}")
    if duplicate_contexts:
        quality_flags.append(f"Duplicate base_context_ids: {duplicate_contexts[:10]}")
    if missing_prediction:
        quality_flags.append(f"Missing classifier predictions: {len(missing_prediction)}")
    if missing_confidence:
        quality_flags.append(f"Missing confidence values where inference succeeded: {len(missing_confidence)}")
    if missing_shap:
        quality_flags.append(f"Missing SHAP explanations where SHAP succeeded: {len(missing_shap)}")
    if unsupported:
        quality_flags.append(f"Unsupported IDS labels: {len(unsupported)}")
    if missing_retrieval:
        quality_flags.append(f"Missing retrieval contexts: {len(missing_retrieval)}")
    if repeated_shap_profiles:
        quality_flags.append(f"Repeated SHAP profiles above threshold: {len(repeated_shap_profiles)}")
    if excessive_source_files:
        quality_flags.append(f"Source-file concentration above 35 percent: {len(excessive_source_files)}")
    if not quality_flags:
        quality_flags.append("No duplicate IDs, missing required fields, unsupported labels, or retrieval gaps detected.")

    inventory = {
        "candidate_samples_scanned": len(classifier_records),
        "selected_base_contexts": len(base_contexts),
        "base_contexts_per_ids_label": dict(label_counts),
        "confidence_band_distribution": dict(confidence_counts),
        "source_file_distribution": dict(source_counts),
        "shap_coverage_per_label": dict(Counter(item["ids_label_ground_truth"] for item in shap_records)),
        "distinct_shap_top_feature_patterns_per_label": {label: len(patterns) for label, patterns in shap_patterns.items()},
        "graph_coverage_per_label": {
            label: {
                "has_retrieval": True,
                "contexts": count,
            }
            for label, count in label_counts.items()
        },
        "cve_present_count": sum(1 for item in base_contexts if item["evidence_completeness"]["has_cve"]),
        "cve_absent_count": sum(1 for item in base_contexts if not item["evidence_completeness"]["has_cve"]),
        "direct_provenance_count": sum(1 for item in base_contexts if item["provenance_type"] == "direct"),
        "mixed_inferred_provenance_count": sum(1 for item in base_contexts if item["provenance_type"] == "mixed_direct_and_inferred"),
        "unavailable_evidence_not_synthesized": ["asset exposure", "actor attribution", "multiclass probabilities from binary IDS model"],
    }
    write_json(OUTPUT_DIR / "evidence_expansion_inventory.json", inventory)
    quality = {
        "status": "complete",
        "passed": not (duplicate_samples or duplicate_contexts or missing_prediction or missing_confidence or missing_shap or unsupported or missing_retrieval),
        "feature_count": len(feature_columns),
        "model_metadata_keys": sorted(model_metadata.keys()),
        "duplicate_sample_ids": duplicate_samples,
        "duplicate_base_context_ids": duplicate_contexts,
        "missing_classifier_prediction_count": len(missing_prediction),
        "missing_confidence_count": len(missing_confidence),
        "missing_shap_count": len(missing_shap),
        "unsupported_ids_label_count": len(unsupported),
        "missing_retrieval_context_count": len(missing_retrieval),
        "repeated_identical_shap_profiles": repeated_shap_profiles[:25],
        "excessive_duplicate_rows_from_same_source_file": excessive_source_files,
        "train_validation_test_leakage_risk_indicators": leakage_risk_indicators,
        "quality_flags": quality_flags,
    }
    write_json(OUTPUT_DIR / "evidence_expansion_quality_report.json", quality)

    (REPORTS_DIR / "evidence_expansion_sampling_report.md").write_text(
        f"# Evidence Expansion Sampling Report\n\n- Selected base contexts: {len(base_contexts)}\n- Labels: {dict(label_counts)}\n- Sources: {dict(source_counts)}\n",
        encoding="utf-8",
    )
    (REPORTS_DIR / "evidence_expansion_inference_report.md").write_text(
        f"# Evidence Expansion Inference Report\n\n- Predictions: {len(prediction_records)}\n- Confidence bands: {dict(confidence_counts)}\n- Binary model note: retrieval labels use real CICIDS ground-truth sub-labels.\n",
        encoding="utf-8",
    )
    (REPORTS_DIR / "evidence_expansion_shap_report.md").write_text(
        f"# Evidence Expansion SHAP Report\n\n- Local SHAP explanations: {len(shap_records)}\n- Distinct top-feature patterns: { {label: len(patterns) for label, patterns in shap_patterns.items()} }\n",
        encoding="utf-8",
    )
    (REPORTS_DIR / "evidence_expansion_inventory.md").write_text(
        "# Evidence Expansion Inventory\n\n```json\n" + json.dumps(inventory, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    (REPORTS_DIR / "evidence_expansion_quality_report.md").write_text(
        "# Evidence Expansion Quality Report\n\n```json\n" + json.dumps(quality, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    expected_size = len(base_contexts) * 8
    (REPORTS_DIR / "gold_candidate_v1_generation_plan.md").write_text(
        f"""# Gold-Candidate v1 Generation Plan

- Expanded base contexts: {len(base_contexts)}
- Recommended task variants per base context: 6-10
- Expected v1 size: approximately {len(base_contexts) * 6} to {expected_size} examples
- Split strategy: group by base_context_id with 70/15/15 train/validation/test allocation.
- Review strategy: sample at least 250 examples stratified by IDS label, task family, confidence band, source file, provenance type, and CVE availability.
- Limitations: binary IDS predictions do not provide multiclass probabilities; retrieval label linkage uses the real CICIDS sub-label.
""",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Expand real evidence contexts for TrustSecAI gold-candidate v1.")
    parser.add_argument("--model-path", type=Path, default=None, help="Saved XGBoost joblib artifact containing model and feature_columns.")
    parser.add_argument("--max-per-label", type=int, default=25)
    parser.add_argument("--top-shap-features", type=int, default=10)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--allow-blocked", action="store_true", help="Return exit code 0 even if critical artifacts are missing.")
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    discovery = discover_artifacts(args.model_path)
    write_artifact_inventory(discovery)
    if discovery.blocker:
        write_blocked_outputs(discovery)
        if not args.allow_blocked:
            raise SystemExit(2)
        return
    run_expansion(args)


if __name__ == "__main__":
    main()
