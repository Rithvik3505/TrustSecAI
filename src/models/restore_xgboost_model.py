"""Restore a persisted XGBoost IDS model artifact from Week 1 configuration.

The original Week 1 XGBoost script evaluated the model but did not save it.
This script reconstructs the same random-split baseline from the cleaned
CICIDS2017 parquet and persists the model, feature order, and metadata for
downstream evidence expansion.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import date
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from xgboost import XGBClassifier

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.models.train_random_forest import EXCLUDED_COLUMNS, class_distribution
from src.models.train_xgboost import SplitConfig, evaluate_classifier, make_xgboost_hyperparameters, split_dataset
from src.utils.paths import METRICS_DIR, MODELS_DIR, PROCESSED_DIR, PROJECT_ROOT, REPORTS_DIR


XGB_MODEL_DIR = MODELS_DIR / "xgboost"
DEFAULT_MODEL_PATH = XGB_MODEL_DIR / "xgboost_model.joblib"
FEATURE_ORDER_PATH = XGB_MODEL_DIR / "feature_order.json"
MODEL_METADATA_PATH = XGB_MODEL_DIR / "model_metadata.json"


def rel(path: Path) -> str:
    """Return project-relative path when possible."""

    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def restore_xgboost_model(
    input_path: Path = PROCESSED_DIR / "cleaned_cicids.parquet",
    model_path: Path = DEFAULT_MODEL_PATH,
    random_state: int = 42,
) -> dict[str, Any]:
    """Retrain and persist the Week 1 random-split XGBoost model."""

    XGB_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    dataframe = pd.read_parquet(input_path)
    required = {"label", "binary_label", "source_file"}
    missing = required - set(dataframe.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    feature_columns = [column for column in dataframe.columns if column not in EXCLUDED_COLUMNS]
    x = dataframe[feature_columns]
    y = dataframe["binary_label"].astype(int)
    split_config = SplitConfig(random_state=random_state)
    x_train, x_validation, x_test, y_train, y_validation, y_test = split_dataset(x, y, split_config)
    hyperparameters = make_xgboost_hyperparameters(y_train, random_state)
    model = XGBClassifier(**hyperparameters)

    start = time.perf_counter()
    model.fit(x_train, y_train)
    training_time_seconds = time.perf_counter() - start

    validation_metrics = evaluate_classifier(model, x_validation, y_validation)
    test_metrics = evaluate_classifier(model, x_test, y_test)
    metrics_summary = {
        "validation": validation_metrics,
        "test": test_metrics,
    }

    metadata: dict[str, Any] = {
        "model_type": "XGBClassifier",
        "binary_or_multiclass": "binary",
        "feature_count": len(feature_columns),
        "feature_columns": feature_columns,
        "label_column": "binary_label",
        "class_mapping": {"0": "BENIGN", "1": "ATTACK"},
        "training_rows": int(len(y_train)),
        "validation_rows": int(len(y_validation)),
        "test_rows": int(len(y_test)),
        "hyperparameters": hyperparameters,
        "random_seed": random_state,
        "source_dataset": rel(input_path),
        "created_at": date.today().isoformat(),
        "metrics_summary": metrics_summary,
        "training_time_seconds": float(training_time_seconds),
        "notes": [
            "Reconstructed from src/models/train_xgboost.py because no saved XGBoost model artifact was present.",
            "Uses the Week 1 random stratified 70/15/15 split.",
            "Excludes label, binary_label, and source_file from model features.",
            "Binary IDS only: BENIGN -> 0, ATTACK -> 1.",
        ],
    }

    artifact = {
        "model": model,
        "feature_columns": feature_columns,
        "excluded_columns": sorted(EXCLUDED_COLUMNS),
        "hyperparameters": hyperparameters,
        "split_config": split_config.__dict__,
        "metadata": metadata,
    }
    joblib.dump(artifact, model_path)
    FEATURE_ORDER_PATH.write_text(json.dumps(feature_columns, indent=2), encoding="utf-8")
    MODEL_METADATA_PATH.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")
    return metadata


def write_reports(search_report: str, reconstruction: dict[str, Any], restore_metadata: dict[str, Any] | None = None) -> None:
    """Write model search, reconstruction, and restore reports."""

    (REPORTS_DIR / "xgboost_model_artifact_search.md").write_text(search_report, encoding="utf-8")

    recon_lines = [
        "# XGBoost Training Reconstruction",
        "",
        "## Reconstructed Configuration",
        "",
        "- Model task: binary IDS classification",
        "- Label column: `binary_label`",
        "- Class mapping: `0 = BENIGN`, `1 = ATTACK`",
        "- Excluded columns: `label`, `binary_label`, `source_file`",
        f"- Feature count: {reconstruction['feature_count']}",
        "- Split logic: stratified random 70/15/15 using random seed 42",
        "- Save path: `models/xgboost/xgboost_model.joblib`",
        "",
        "## Hyperparameters",
        "",
        "```json",
        json.dumps(reconstruction["hyperparameters"], indent=2, sort_keys=True),
        "```",
    ]
    (REPORTS_DIR / "xgboost_training_reconstruction.md").write_text("\n".join(recon_lines) + "\n", encoding="utf-8")

    if restore_metadata:
        restore_lines = [
            "# XGBoost Model Restore Report",
            "",
            "- Restore action: retrained and persisted Week 1 random-split XGBoost model",
            f"- Model path: `{rel(DEFAULT_MODEL_PATH)}`",
            f"- Feature order: `{rel(FEATURE_ORDER_PATH)}`",
            f"- Metadata: `{rel(MODEL_METADATA_PATH)}`",
            f"- Feature count: {restore_metadata['feature_count']}",
            f"- Training rows: {restore_metadata['training_rows']}",
            f"- Validation rows: {restore_metadata['validation_rows']}",
            f"- Test rows: {restore_metadata['test_rows']}",
            f"- Training time seconds: {restore_metadata['training_time_seconds']:.3f}",
            "",
            "## Test Metrics",
            "",
            "```json",
            json.dumps(restore_metadata["metrics_summary"]["test"], indent=2, sort_keys=True),
            "```",
        ]
        (REPORTS_DIR / "xgboost_model_restore_report.md").write_text("\n".join(restore_lines) + "\n", encoding="utf-8")


def build_search_report(model_like_files: list[Path], valid_model: Path | None) -> str:
    """Render the model artifact search report."""

    lines = [
        "# XGBoost Model Artifact Search",
        "",
        f"Created: {date.today().isoformat()}",
        "",
        "## Model-like Files Found",
        "",
    ]
    if model_like_files:
        lines.extend(f"- `{rel(path)}` ({path.stat().st_size:,} bytes)" for path in model_like_files)
    else:
        lines.append("- None")
    lines.extend(
        [
            "",
            "## Search Result",
            "",
            f"- Valid saved XGBoost model artifact: `{rel(valid_model)}`" if valid_model else "- No valid saved XGBoost model artifact was found.",
            "- Action: retrain from existing Week 1 code and cleaned dataset." if not valid_model else "- Action: use existing artifact.",
        ]
    )
    return "\n".join(lines) + "\n"


def find_model_like_files() -> list[Path]:
    """Search known project locations for model-like artifacts."""

    roots = [MODELS_DIR, PROJECT_ROOT / "artifacts" / "models", METRICS_DIR, REPORTS_DIR]
    suffixes = {".joblib", ".pkl", ".pickle", ".json", ".ubj", ".model"}
    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and (path.suffix.lower() in suffixes or "model" in path.name.lower() or "xgb" in path.name.lower()):
                files.append(path)
    return sorted(set(files))


def valid_existing_xgboost_artifact(files: list[Path]) -> Path | None:
    """Return the first loadable XGBoost joblib artifact, if present."""

    for path in files:
        if path.suffix.lower() != ".joblib" or "xgboost" not in str(path).lower():
            continue
        try:
            artifact = joblib.load(path)
        except Exception:
            continue
        if isinstance(artifact, dict) and artifact.get("model") is not None and artifact.get("feature_columns"):
            return path
    return None


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Restore persisted XGBoost IDS model artifact.")
    parser.add_argument("--input-path", type=Path, default=PROCESSED_DIR / "cleaned_cicids.parquet")
    parser.add_argument("--model-path", type=Path, default=DEFAULT_MODEL_PATH)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    files = find_model_like_files()
    valid = valid_existing_xgboost_artifact(files)
    metrics = json.loads((METRICS_DIR / "xgboost_metrics.json").read_text(encoding="utf-8"))
    reconstruction = {
        "feature_count": metrics["feature_count"],
        "hyperparameters": metrics["hyperparameters"],
    }
    if valid:
        search_report = build_search_report(files, valid)
        write_reports(search_report, reconstruction, None)
        return
    search_report = build_search_report(files, None)
    metadata = restore_xgboost_model(args.input_path, args.model_path, args.random_state)
    write_reports(search_report, reconstruction, metadata)


if __name__ == "__main__":
    main()
