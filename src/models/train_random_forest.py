"""Train the Week 1 baseline Random Forest IDS classifier.

This script trains a binary classifier on the preprocessed CICIDS2017 parquet:

- BENIGN -> 0
- ATTACK -> 1

It intentionally does not run SHAP or any downstream TrustSecAI phases.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.utils.logging import get_logger
from src.utils.paths import METRICS_DIR, PROCESSED_DIR, REPORTS_DIR, RF_MODEL_DIR, ensure_project_dirs


LOGGER = get_logger(__name__)
EXCLUDED_COLUMNS = {"label", "binary_label", "source_file"}
DEFAULT_RANDOM_STATE = 42


@dataclass(frozen=True)
class SplitConfig:
    """Train/validation/test split configuration."""

    train_size: float = 0.70
    validation_size: float = 0.15
    test_size: float = 0.15
    random_state: int = DEFAULT_RANDOM_STATE


@dataclass(frozen=True)
class TrainingOutputs:
    """Paths produced by Random Forest training."""

    metrics_path: Path
    report_path: Path
    model_path: Path


def class_distribution(y: pd.Series) -> dict[str, dict[str, float | int]]:
    """Return class count and percentage distribution for binary labels."""

    counts = y.value_counts().sort_index()
    total = int(counts.sum())
    return {
        str(int(label)): {
            "count": int(count),
            "percentage": round(float(count / total * 100), 6),
        }
        for label, count in counts.items()
    }


def split_dataset(
    x: pd.DataFrame,
    y: pd.Series,
    config: SplitConfig,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series]:
    """Create stratified train, validation, and test splits."""

    if round(config.train_size + config.validation_size + config.test_size, 8) != 1.0:
        raise ValueError("Split sizes must sum to 1.0")

    x_train, x_temp, y_train, y_temp = train_test_split(
        x,
        y,
        train_size=config.train_size,
        stratify=y,
        random_state=config.random_state,
    )

    relative_validation_size = config.validation_size / (config.validation_size + config.test_size)
    x_validation, x_test, y_validation, y_test = train_test_split(
        x_temp,
        y_temp,
        train_size=relative_validation_size,
        stratify=y_temp,
        random_state=config.random_state,
    )

    return x_train, x_validation, x_test, y_train, y_validation, y_test


def evaluate_classifier(
    model: RandomForestClassifier,
    x: pd.DataFrame,
    y: pd.Series,
) -> dict[str, Any]:
    """Evaluate a binary classifier and return serializable metrics."""

    predictions = model.predict(x)
    probabilities = model.predict_proba(x)[:, 1]
    matrix = confusion_matrix(y, predictions, labels=[0, 1])

    return {
        "accuracy": float(accuracy_score(y, predictions)),
        "precision": float(precision_score(y, predictions, zero_division=0)),
        "recall": float(recall_score(y, predictions, zero_division=0)),
        "f1_score": float(f1_score(y, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, probabilities)),
        "confusion_matrix": {
            "labels": [0, 1],
            "matrix": matrix.astype(int).tolist(),
            "tn": int(matrix[0, 0]),
            "fp": int(matrix[0, 1]),
            "fn": int(matrix[1, 0]),
            "tp": int(matrix[1, 1]),
        },
    }


def dataframe_to_markdown(dataframe: pd.DataFrame) -> str:
    """Render a dataframe as a simple Markdown table without optional deps."""

    if dataframe.empty:
        return "_No rows._"

    headers = [str(column) for column in dataframe.columns]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]

    for _, row in dataframe.iterrows():
        values = [str(row[column]) for column in dataframe.columns]
        lines.append("| " + " | ".join(values) + " |")

    return "\n".join(lines)


def write_report(
    path: Path,
    metrics: dict[str, Any],
    hyperparameters: dict[str, Any],
    training_time_seconds: float,
    feature_count: int,
) -> None:
    """Write the Random Forest Markdown report."""

    test_metrics = metrics["test_metrics"]
    validation_metrics = metrics["validation_metrics"]
    test_cm = test_metrics["confusion_matrix"]
    validation_cm = validation_metrics["confusion_matrix"]

    metric_rows = pd.DataFrame(
        [
            {"split": "validation", **{k: validation_metrics[k] for k in ["accuracy", "precision", "recall", "f1_score", "roc_auc"]}},
            {"split": "test", **{k: test_metrics[k] for k in ["accuracy", "precision", "recall", "f1_score", "roc_auc"]}},
        ]
    )
    for column in ["accuracy", "precision", "recall", "f1_score", "roc_auc"]:
        metric_rows[column] = metric_rows[column].map(lambda value: f"{value:.6f}")

    class_rows: list[dict[str, Any]] = []
    for split_name, distribution in metrics["class_distribution"].items():
        for label, values in distribution.items():
            class_rows.append(
                {
                    "split": split_name,
                    "binary_label": label,
                    "meaning": "BENIGN" if label == "0" else "ATTACK",
                    "count": values["count"],
                    "percentage": values["percentage"],
                }
            )

    hyperparameter_text = json.dumps(hyperparameters, indent=2, sort_keys=True)

    report = f"""# Random Forest Baseline IDS Report

## Scope

This report covers the Week 1 binary IDS baseline only. It uses `artifacts/processed/cleaned_cicids.parquet` and excludes `label`, `binary_label`, and `source_file` from model features.

## Hyperparameters

```json
{hyperparameter_text}
```

## Training Summary

| Metric | Value |
|---|---:|
| Feature count | {feature_count:,} |
| Training rows | {metrics["split_sizes"]["train"]:,} |
| Validation rows | {metrics["split_sizes"]["validation"]:,} |
| Test rows | {metrics["split_sizes"]["test"]:,} |
| Training time seconds | {training_time_seconds:.3f} |

## Metrics

{dataframe_to_markdown(metric_rows)}

## Test Confusion Matrix

Labels are ordered `[0, 1]`, where `0=BENIGN` and `1=ATTACK`.

|  | Predicted 0 | Predicted 1 |
|---|---:|---:|
| Actual 0 | {test_cm["tn"]} | {test_cm["fp"]} |
| Actual 1 | {test_cm["fn"]} | {test_cm["tp"]} |

## Validation Confusion Matrix

|  | Predicted 0 | Predicted 1 |
|---|---:|---:|
| Actual 0 | {validation_cm["tn"]} | {validation_cm["fp"]} |
| Actual 1 | {validation_cm["fn"]} | {validation_cm["tp"]} |

## Class Distribution

{dataframe_to_markdown(pd.DataFrame(class_rows))}

## Observations

- The first baseline uses a stratified 70/15/15 train/validation/test split.
- Class labels are binary only: `BENIGN -> 0`, all attacks -> `1`.
- The model excludes `source_file`, preventing direct file/day leakage through that audit column.
- Accuracy should not be the only decision metric because the cleaned dataset remains imbalanced.
- SHAP and explainability were intentionally not run in this phase.
"""

    path.write_text(report, encoding="utf-8")
    LOGGER.info("Wrote Random Forest report: %s", path)


def train_random_forest(
    input_path: Path = PROCESSED_DIR / "cleaned_cicids.parquet",
    metrics_path: Path = METRICS_DIR / "random_forest_metrics.json",
    report_path: Path = REPORTS_DIR / "random_forest_report.md",
    model_path: Path = RF_MODEL_DIR / "random_forest_model.joblib",
    n_estimators: int = 100,
    max_depth: int | None = None,
    n_jobs: int = -1,
    random_state: int = DEFAULT_RANDOM_STATE,
) -> TrainingOutputs:
    """Train and evaluate the Random Forest baseline."""

    ensure_project_dirs()
    if not input_path.exists():
        raise FileNotFoundError(f"Cleaned dataset not found: {input_path}")

    LOGGER.info("Loading cleaned dataset: %s", input_path)
    dataframe = pd.read_parquet(input_path)

    missing_columns = EXCLUDED_COLUMNS.difference(dataframe.columns)
    if missing_columns:
        raise ValueError(f"Missing required columns: {sorted(missing_columns)}")

    feature_columns = [column for column in dataframe.columns if column not in EXCLUDED_COLUMNS]
    x = dataframe[feature_columns]
    y = dataframe["binary_label"].astype(int)
    LOGGER.info("Loaded dataset | rows=%s | features=%s", len(dataframe), len(feature_columns))

    split_config = SplitConfig(random_state=random_state)
    x_train, x_validation, x_test, y_train, y_validation, y_test = split_dataset(x, y, split_config)
    LOGGER.info(
        "Created splits | train=%s | validation=%s | test=%s",
        len(y_train),
        len(y_validation),
        len(y_test),
    )

    hyperparameters = {
        "n_estimators": n_estimators,
        "max_depth": max_depth,
        "class_weight": "balanced_subsample",
        "n_jobs": n_jobs,
        "random_state": random_state,
        "criterion": "gini",
    }
    model = RandomForestClassifier(**hyperparameters)

    start = time.perf_counter()
    LOGGER.info("Training Random Forest")
    model.fit(x_train, y_train)
    training_time_seconds = time.perf_counter() - start
    LOGGER.info("Training complete in %.3f seconds", training_time_seconds)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "feature_columns": feature_columns,
            "excluded_columns": sorted(EXCLUDED_COLUMNS),
            "hyperparameters": hyperparameters,
            "split_config": asdict(split_config),
        },
        model_path,
    )
    LOGGER.info("Wrote model artifact: %s", model_path)

    metrics = {
        "model": "RandomForestClassifier",
        "task": "binary_ids_classification",
        "positive_class": "ATTACK",
        "negative_class": "BENIGN",
        "input_path": str(input_path),
        "model_path": str(model_path),
        "excluded_columns": sorted(EXCLUDED_COLUMNS),
        "feature_count": len(feature_columns),
        "hyperparameters": hyperparameters,
        "split_config": asdict(split_config),
        "split_sizes": {
            "train": int(len(y_train)),
            "validation": int(len(y_validation)),
            "test": int(len(y_test)),
        },
        "class_distribution": {
            "full": class_distribution(y),
            "train": class_distribution(y_train),
            "validation": class_distribution(y_validation),
            "test": class_distribution(y_test),
        },
        "training_time_seconds": float(training_time_seconds),
        "validation_metrics": evaluate_classifier(model, x_validation, y_validation),
        "test_metrics": evaluate_classifier(model, x_test, y_test),
    }

    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    LOGGER.info("Wrote metrics: %s", metrics_path)

    report_path.parent.mkdir(parents=True, exist_ok=True)
    write_report(
        report_path,
        metrics,
        hyperparameters,
        training_time_seconds,
        len(feature_columns),
    )

    return TrainingOutputs(metrics_path=metrics_path, report_path=report_path, model_path=model_path)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(description="Train the Random Forest IDS baseline.")
    parser.add_argument("--input-path", type=Path, default=PROCESSED_DIR / "cleaned_cicids.parquet")
    parser.add_argument("--metrics-path", type=Path, default=METRICS_DIR / "random_forest_metrics.json")
    parser.add_argument("--report-path", type=Path, default=REPORTS_DIR / "random_forest_report.md")
    parser.add_argument("--model-path", type=Path, default=RF_MODEL_DIR / "random_forest_model.joblib")
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--max-depth", type=int, default=None)
    parser.add_argument("--n-jobs", type=int, default=-1)
    parser.add_argument("--random-state", type=int, default=DEFAULT_RANDOM_STATE)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    train_random_forest(
        input_path=args.input_path,
        metrics_path=args.metrics_path,
        report_path=args.report_path,
        model_path=args.model_path,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        n_jobs=args.n_jobs,
        random_state=args.random_state,
    )


if __name__ == "__main__":
    main()
