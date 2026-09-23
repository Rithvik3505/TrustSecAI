"""Train the Week 1 XGBoost binary IDS baseline."""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.models.train_random_forest import EXCLUDED_COLUMNS, class_distribution, dataframe_to_markdown
from src.utils.logging import get_logger
from src.utils.paths import METRICS_DIR, PROCESSED_DIR, REPORTS_DIR, ensure_project_dirs


LOGGER = get_logger(__name__)


@dataclass(frozen=True)
class SplitConfig:
    """Train/validation/test split configuration."""

    train_size: float = 0.70
    validation_size: float = 0.15
    test_size: float = 0.15
    random_state: int = 42


def split_dataset(
    x: pd.DataFrame,
    y: pd.Series,
    config: SplitConfig,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series]:
    """Create stratified train, validation, and test splits."""

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


def evaluate_classifier(model: XGBClassifier, x: pd.DataFrame, y: pd.Series) -> dict[str, Any]:
    """Evaluate a binary XGBoost classifier."""

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


def make_xgboost_hyperparameters(y_train: pd.Series, random_state: int) -> dict[str, Any]:
    """Create XGBoost hyperparameters with class weighting."""

    negative = int((y_train == 0).sum())
    positive = int((y_train == 1).sum())
    return {
        "n_estimators": 300,
        "max_depth": 8,
        "learning_rate": 0.1,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "objective": "binary:logistic",
        "eval_metric": "logloss",
        "tree_method": "hist",
        "n_jobs": -1,
        "random_state": random_state,
        "scale_pos_weight": negative / positive,
    }


def write_report(path: Path, metrics: dict[str, Any]) -> None:
    """Write XGBoost Markdown report."""

    validation = metrics["validation_metrics"]
    test = metrics["test_metrics"]
    cm = test["confusion_matrix"]
    metric_table = pd.DataFrame(
        [
            {"split": "validation", **{key: f"{validation[key]:.6f}" for key in ["accuracy", "precision", "recall", "f1_score", "roc_auc"]}},
            {"split": "test", **{key: f"{test[key]:.6f}" for key in ["accuracy", "precision", "recall", "f1_score", "roc_auc"]}},
        ]
    )

    report = f"""# XGBoost Baseline IDS Report

## Scope

Binary IDS baseline using `artifacts/processed/cleaned_cicids.parquet`. Excluded columns: `label`, `binary_label`, `source_file`.

## Hyperparameters

```json
{json.dumps(metrics['hyperparameters'], indent=2, sort_keys=True)}
```

## Training Summary

| Metric | Value |
|---|---:|
| Feature count | {metrics['feature_count']:,} |
| Training rows | {metrics['split_sizes']['train']:,} |
| Validation rows | {metrics['split_sizes']['validation']:,} |
| Test rows | {metrics['split_sizes']['test']:,} |
| Training time seconds | {metrics['training_time_seconds']:.3f} |

## Metrics

{dataframe_to_markdown(metric_table)}

## Test Confusion Matrix

|  | Predicted 0 | Predicted 1 |
|---|---:|---:|
| Actual 0 | {cm['tn']} | {cm['fp']} |
| Actual 1 | {cm['fn']} | {cm['tp']} |

## Observations

- Uses the same stratified 70/15/15 split as the Random Forest baseline.
- Uses `tree_method=\"hist\"` for memory-conscious training.
- Uses `scale_pos_weight` from the training split class ratio.
- This is binary classification only; no SHAP or Week 2 components are run here.
"""

    path.write_text(report, encoding="utf-8")
    LOGGER.info("Wrote XGBoost report: %s", path)


def train_xgboost(
    input_path: Path = PROCESSED_DIR / "cleaned_cicids.parquet",
    metrics_path: Path = METRICS_DIR / "xgboost_metrics.json",
    report_path: Path = REPORTS_DIR / "xgboost_report.md",
    random_state: int = 42,
) -> dict[str, Any]:
    """Train and evaluate XGBoost on a stratified random split."""

    ensure_project_dirs()
    dataframe = pd.read_parquet(input_path)
    feature_columns = [column for column in dataframe.columns if column not in EXCLUDED_COLUMNS]
    x = dataframe[feature_columns]
    y = dataframe["binary_label"].astype(int)

    split_config = SplitConfig(random_state=random_state)
    x_train, x_validation, x_test, y_train, y_validation, y_test = split_dataset(x, y, split_config)
    hyperparameters = make_xgboost_hyperparameters(y_train, random_state)
    model = XGBClassifier(**hyperparameters)

    start = time.perf_counter()
    LOGGER.info("Training XGBoost random-split baseline")
    model.fit(x_train, y_train)
    training_time_seconds = time.perf_counter() - start
    LOGGER.info("Training complete in %.3f seconds", training_time_seconds)

    metrics = {
        "model": "XGBClassifier",
        "task": "binary_ids_classification",
        "input_path": str(input_path),
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

    metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    LOGGER.info("Wrote XGBoost metrics: %s", metrics_path)
    write_report(report_path, metrics)
    return metrics


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Train XGBoost random-split baseline.")
    parser.add_argument("--input-path", type=Path, default=PROCESSED_DIR / "cleaned_cicids.parquet")
    parser.add_argument("--metrics-path", type=Path, default=METRICS_DIR / "xgboost_metrics.json")
    parser.add_argument("--report-path", type=Path, default=REPORTS_DIR / "xgboost_report.md")
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    train_xgboost(
        input_path=args.input_path,
        metrics_path=args.metrics_path,
        report_path=args.report_path,
        random_state=args.random_state,
    )


if __name__ == "__main__":
    main()

