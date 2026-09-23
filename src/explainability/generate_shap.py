"""Generate SHAP explanations for the Random Forest IDS baseline."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import joblib

os.environ.setdefault("MPLCONFIGDIR", str(Path("artifacts") / "matplotlib_cache"))

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.utils.logging import get_logger
from src.utils.paths import PROCESSED_DIR, PROJECT_ROOT, RF_MODEL_DIR, SHAP_DIR, ensure_project_dirs


LOGGER = get_logger(__name__)
EXCLUDED_COLUMNS = {"label", "binary_label", "source_file"}


def get_class_shap_values(shap_values: Any, class_index: int = 1) -> np.ndarray:
    """Return SHAP values for the requested class across SHAP versions."""

    if isinstance(shap_values, list):
        return np.asarray(shap_values[class_index])

    values = np.asarray(shap_values)
    if values.ndim == 3:
        return values[:, :, class_index]
    return values


def write_attack_label_mapping(path: Path) -> None:
    """Write initial high-confidence CICIDS label to ATT&CK mappings."""

    mapping = {
        "PortScan": {
            "attack_id": "T1046",
            "attack_name": "Network Service Discovery",
            "confidence": "high",
            "rationale": "Port scanning aligns directly with network service discovery behavior.",
        },
        "DDoS": {
            "attack_id": "T1498",
            "attack_name": "Network Denial of Service",
            "confidence": "high",
            "rationale": "Distributed denial-of-service traffic aligns with network denial-of-service impact.",
        },
        "DoS Hulk": {
            "attack_id": "T1499",
            "attack_name": "Endpoint Denial of Service",
            "confidence": "medium",
            "rationale": "CICIDS DoS Hulk is a denial-of-service scenario; exact ATT&CK sub-technique depends on target/service context.",
        },
        "DoS GoldenEye": {
            "attack_id": "T1499",
            "attack_name": "Endpoint Denial of Service",
            "confidence": "medium",
            "rationale": "GoldenEye is represented as a DoS scenario; mapped conservatively to endpoint denial of service.",
        },
        "DoS Slowhttptest": {
            "attack_id": "T1499",
            "attack_name": "Endpoint Denial of Service",
            "confidence": "medium",
            "rationale": "Slow HTTP DoS behavior maps to service/resource exhaustion under endpoint denial of service.",
        },
        "DoS slowloris": {
            "attack_id": "T1499",
            "attack_name": "Endpoint Denial of Service",
            "confidence": "medium",
            "rationale": "Slowloris is a DoS scenario; mapped conservatively to endpoint denial of service.",
        },
        "FTP-Patator": {
            "attack_id": "T1110",
            "attack_name": "Brute Force",
            "confidence": "high",
            "rationale": "FTP-Patator is a password brute-force attack against FTP credentials.",
        },
        "SSH-Patator": {
            "attack_id": "T1110",
            "attack_name": "Brute Force",
            "confidence": "high",
            "rationale": "SSH-Patator is a password brute-force attack against SSH credentials.",
        },
        "Web Attack - Brute Force": {
            "attack_id": "T1110",
            "attack_name": "Brute Force",
            "confidence": "high",
            "rationale": "The label explicitly identifies brute-force web authentication behavior.",
        },
        "Web Attack - XSS": {
            "attack_id": "T1189",
            "attack_name": "Drive-by Compromise",
            "confidence": "low",
            "rationale": "XSS is an application attack pattern; ATT&CK mapping is context-dependent and should be refined during GraphRAG mapping.",
        },
        "Web Attack - Sql Injection": {
            "attack_id": "T1190",
            "attack_name": "Exploit Public-Facing Application",
            "confidence": "medium",
            "rationale": "SQL injection commonly exploits a public-facing web application, but exact ATT&CK mapping depends on deployment context.",
        },
        "Bot": {
            "attack_id": "T1105",
            "attack_name": "Ingress Tool Transfer",
            "confidence": "low",
            "rationale": "Bot traffic may involve command/control or tool transfer; mapping requires more incident context.",
        },
        "Infiltration": {
            "attack_id": "T1190",
            "attack_name": "Exploit Public-Facing Application",
            "confidence": "low",
            "rationale": "The CICIDS label is broad; mapped only as an initial placeholder for later contextual refinement.",
        },
        "Heartbleed": {
            "attack_id": "T1190",
            "attack_name": "Exploit Public-Facing Application",
            "confidence": "medium",
            "rationale": "Heartbleed exploitation targets a vulnerable exposed service.",
        },
    }
    path.write_text(json.dumps(mapping, indent=2, sort_keys=True), encoding="utf-8")
    LOGGER.info("Wrote attack label mapping: %s", path)


def generate_local_explanations(
    model: Any,
    explainer: shap.TreeExplainer,
    dataframe: pd.DataFrame,
    feature_columns: list[str],
    sample_size: int,
    random_state: int,
) -> list[dict[str, Any]]:
    """Generate local explanations for 10 correct attacks and 10 correct benign samples."""

    candidate = dataframe.sample(n=min(sample_size, len(dataframe)), random_state=random_state)
    x_candidate = candidate[feature_columns]
    predictions = model.predict(x_candidate)
    probabilities = model.predict_proba(x_candidate)

    candidate = candidate.copy()
    candidate["_prediction"] = predictions
    candidate["_confidence"] = probabilities.max(axis=1)
    correct = candidate[candidate["_prediction"].astype(int) == candidate["binary_label"].astype(int)]
    selected = pd.concat(
        [
            correct[correct["binary_label"] == 1].head(10),
            correct[correct["binary_label"] == 0].head(10),
        ],
        axis=0,
    )
    if len(selected) < 20:
        raise ValueError(f"Only found {len(selected)} correctly classified local explanation samples.")

    local_values = get_class_shap_values(explainer.shap_values(selected[feature_columns]), class_index=1)
    explanations: list[dict[str, Any]] = []

    for row_position, (index, row) in enumerate(selected.iterrows()):
        shap_row = local_values[row_position]
        top_indices = np.argsort(np.abs(shap_row))[::-1][:10]
        explanations.append(
            {
                "sample_id": int(index),
                "true_label": int(row["binary_label"]),
                "multiclass_label": str(row["label"]),
                "prediction": int(row["_prediction"]),
                "prediction_name": "ATTACK" if int(row["_prediction"]) == 1 else "BENIGN",
                "confidence": float(row["_confidence"]),
                "source_file": str(row["source_file"]),
                "top_features": [
                    {
                        "feature": feature_columns[i],
                        "value": float(row[feature_columns[i]]),
                        "shap_value": float(shap_row[i]),
                    }
                    for i in top_indices
                ],
            }
        )

    return explanations


def generate_shap(
    model_path: Path = RF_MODEL_DIR / "random_forest_model.joblib",
    input_path: Path = PROCESSED_DIR / "cleaned_cicids.parquet",
    output_dir: Path = SHAP_DIR,
    global_sample_size: int = 2000,
    local_candidate_size: int = 50000,
    random_state: int = 42,
) -> None:
    """Generate global and local SHAP outputs."""

    ensure_project_dirs()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not model_path.exists():
        raise FileNotFoundError(f"Random Forest model artifact not found: {model_path}")

    artifact = joblib.load(model_path)
    model = artifact["model"]
    feature_columns = list(artifact["feature_columns"])

    columns = feature_columns + ["label", "binary_label", "source_file"]
    dataframe = pd.read_parquet(input_path, columns=columns)
    global_sample = dataframe.sample(n=min(global_sample_size, len(dataframe)), random_state=random_state)
    x_global = global_sample[feature_columns]

    LOGGER.info("Computing SHAP values for %s global samples", len(x_global))
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(x_global)
    shap_values_attack = get_class_shap_values(shap_values, class_index=1)

    importance = pd.DataFrame(
        {
            "feature": feature_columns,
            "mean_abs_shap_value": np.abs(shap_values_attack).mean(axis=0),
        }
    ).sort_values("mean_abs_shap_value", ascending=False)
    importance["rank"] = range(1, len(importance) + 1)
    importance.head(20).to_csv(output_dir / "global_feature_importance.csv", index=False)
    LOGGER.info("Wrote global feature importance: %s", output_dir / "global_feature_importance.csv")

    plt.figure()
    shap.summary_plot(shap_values_attack, x_global, plot_type="bar", show=False, max_display=20)
    plt.tight_layout()
    plt.savefig(output_dir / "shap_summary_bar.png", dpi=200, bbox_inches="tight")
    plt.close()

    plt.figure()
    shap.summary_plot(shap_values_attack, x_global, show=False, max_display=20)
    plt.tight_layout()
    plt.savefig(output_dir / "shap_summary_beeswarm.png", dpi=200, bbox_inches="tight")
    plt.close()
    LOGGER.info("Wrote SHAP plots to %s", output_dir)

    explanations = generate_local_explanations(
        model=model,
        explainer=explainer,
        dataframe=dataframe,
        feature_columns=feature_columns,
        sample_size=local_candidate_size,
        random_state=random_state,
    )
    (output_dir / "sample_explanations.json").write_text(
        json.dumps(explanations, indent=2),
        encoding="utf-8",
    )
    LOGGER.info("Wrote local explanations: %s", output_dir / "sample_explanations.json")

    write_attack_label_mapping(PROJECT_ROOT / "artifacts" / "attack_label_mapping.json")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Generate SHAP explanations for Random Forest baseline.")
    parser.add_argument("--model-path", type=Path, default=RF_MODEL_DIR / "random_forest_model.joblib")
    parser.add_argument("--input-path", type=Path, default=PROCESSED_DIR / "cleaned_cicids.parquet")
    parser.add_argument("--output-dir", type=Path, default=SHAP_DIR)
    parser.add_argument("--global-sample-size", type=int, default=2000)
    parser.add_argument("--local-candidate-size", type=int, default=50000)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    generate_shap(
        model_path=args.model_path,
        input_path=args.input_path,
        output_dir=args.output_dir,
        global_sample_size=args.global_sample_size,
        local_candidate_size=args.local_candidate_size,
        random_state=args.random_state,
    )


if __name__ == "__main__":
    main()
