"""Train XGBoost with the CICIDS day-aware split and write final Week 1 reports."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from xgboost import XGBClassifier

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.models.train_random_forest import EXCLUDED_COLUMNS, class_distribution, dataframe_to_markdown
from src.models.train_xgboost import make_xgboost_hyperparameters
from src.utils.logging import get_logger
from src.utils.paths import METRICS_DIR, PROCESSED_DIR, REPORTS_DIR, ensure_project_dirs


LOGGER = get_logger(__name__)


def evaluate_classifier(model: XGBClassifier, x: pd.DataFrame, y: pd.Series) -> dict[str, Any]:
    """Evaluate a binary classifier."""

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


def write_day_report(path: Path, metrics: dict[str, Any]) -> None:
    """Write XGBoost day-aware report."""

    test = metrics["test_metrics"]
    cm = test["confusion_matrix"]
    metric_table = pd.DataFrame(
        [
            {
                "accuracy": f"{test['accuracy']:.6f}",
                "precision": f"{test['precision']:.6f}",
                "recall": f"{test['recall']:.6f}",
                "f1_score": f"{test['f1_score']:.6f}",
                "roc_auc": f"{test['roc_auc']:.6f}",
            }
        ]
    )

    report = f"""# XGBoost Day-Aware Split Report

## Scope

Train on Monday, Tuesday, Wednesday, and Thursday. Test on Friday. Binary labels only.

## Hyperparameters

```json
{json.dumps(metrics['hyperparameters'], indent=2, sort_keys=True)}
```

## Training Summary

| Metric | Value |
|---|---:|
| Feature count | {metrics['feature_count']:,} |
| Training rows | {metrics['split_sizes']['train']:,} |
| Test rows | {metrics['split_sizes']['test']:,} |
| Training time seconds | {metrics['training_time_seconds']:.3f} |

## Metrics

{dataframe_to_markdown(metric_table)}

## Confusion Matrix

|  | Predicted 0 | Predicted 1 |
|---|---:|---:|
| Actual 0 | {cm['tn']} | {cm['fp']} |
| Actual 1 | {cm['fn']} | {cm['tp']} |

## Observations

- Uses the same day-aware methodology as the Random Forest validation study.
- Uses `tree_method=\"hist\"` for memory-conscious training.
- Uses training-split `scale_pos_weight`.
"""

    path.write_text(report, encoding="utf-8")
    LOGGER.info("Wrote XGBoost day-aware report: %s", path)


def load_metrics(path: Path, split_key: str) -> dict[str, float]:
    """Load selected metric values from a metrics JSON file."""

    data = json.loads(path.read_text(encoding="utf-8"))
    values = data[split_key]
    return {key: float(values[key]) for key in ["accuracy", "precision", "recall", "f1_score", "roc_auc"]}


def write_model_comparison(path: Path, metrics_paths: dict[str, tuple[Path, str]]) -> pd.DataFrame:
    """Write the four-way model comparison report and return the table."""

    rows = []
    for name, (metrics_path, split_key) in metrics_paths.items():
        values = load_metrics(metrics_path, split_key)
        rows.append(
            {
                "model": name,
                "accuracy": f"{values['accuracy']:.6f}",
                "precision": f"{values['precision']:.6f}",
                "recall": f"{values['recall']:.6f}",
                "f1_score": f"{values['f1_score']:.6f}",
                "roc_auc": f"{values['roc_auc']:.6f}",
            }
        )
    table = pd.DataFrame(rows)
    report = f"""# Model Comparison

## Metrics

{dataframe_to_markdown(table)}

## Notes

- Random split results measure row-level stratified test performance.
- Day-aware results test generalization to held-out Friday traffic.
- The day-aware split is the stronger research-integrity signal for deployment-like generalization.
"""
    path.write_text(report, encoding="utf-8")
    LOGGER.info("Wrote model comparison report: %s", path)
    return table


def write_generalization_analysis(
    path: Path,
    rf_day_path: Path,
    xgb_day_path: Path,
    comparison_table: pd.DataFrame,
) -> None:
    """Write final Week 1 generalization analysis."""

    rf_day = load_metrics(rf_day_path, "test_metrics")
    xgb_day = load_metrics(xgb_day_path, "test_metrics")
    deltas = {key: xgb_day[key] - rf_day[key] for key in rf_day}
    improved = {key: value for key, value in deltas.items() if value > 0}
    if xgb_day["f1_score"] > rf_day["f1_score"]:
        answer = "Yes, XGBoost improves day-aware F1 compared with Random Forest."
    else:
        answer = "No, XGBoost does not improve day-aware F1 compared with Random Forest."

    limitation = (
        "The primary limitation is dataset distribution shift and attack distribution mismatch, not simply Random Forest. "
        "Friday contains DDoS, PortScan, and Bot-heavy traffic, while the Monday-Thursday training set has a different "
        "attack mix. A stronger learner can help only if the training distribution contains transferable evidence for "
        "the held-out attack behavior."
    )

    impact_section = """## Impact of Evaluation Strategy on IDS Performance

The Week 1 experiments show that evaluation strategy has a decisive impact on reported IDS performance. Under a stratified random split, both tree-based models can see highly similar traffic patterns across training and test partitions. This produces very high scores and is useful as a pipeline sanity check, but it is not a sufficient estimate of real-world generalization.

The day-aware split is stricter because Friday traffic is held out entirely while the model trains on Monday through Thursday. This exposes a major generalization challenge: attack families and traffic patterns are not evenly distributed across capture days. A model can perform well on random rows yet fail to recall attacks from a held-out day if those attack behaviors were weakly represented or absent during training.

For TrustSecAI, this result is important rather than discouraging. The framework should not only detect attacks; it should communicate uncertainty and contextual limits. Week 2 should therefore carry forward the model that best balances random-split strength with day-aware recall, while reporting day-aware validation as the more honest security evaluation. Random split metrics can remain as a baseline, but final claims should emphasize generalization under distribution shift."""

    report = f"""# Generalization Analysis

## Does XGBoost Improve Day-Aware Performance?

{answer}

## Day-Aware Metric Deltas

Positive values mean XGBoost is higher than Random Forest.

| Metric | Delta |
|---|---:|
| Accuracy | {deltas['accuracy']:.6f} |
| Precision | {deltas['precision']:.6f} |
| Recall | {deltas['recall']:.6f} |
| F1 | {deltas['f1_score']:.6f} |
| ROC-AUC | {deltas['roc_auc']:.6f} |

Improved metrics: `{', '.join(improved.keys()) if improved else 'none'}`.

## Primary Limitation

{limitation}

## Recommendation for Week 2

Carry both Random Forest and XGBoost forward for a short final checkpoint, but use the better day-aware performer as the primary IDS candidate. The final report should present random-split results as a baseline and day-aware results as the core generalization finding.

## Comparison Table

{dataframe_to_markdown(comparison_table)}

{impact_section}
"""
    path.write_text(report, encoding="utf-8")
    LOGGER.info("Wrote generalization analysis: %s", path)


def train_xgboost_day_split(
    input_path: Path = PROCESSED_DIR / "cleaned_cicids.parquet",
    metrics_path: Path = METRICS_DIR / "xgboost_day_split_metrics.json",
    report_path: Path = REPORTS_DIR / "xgboost_day_split_report.md",
    random_state: int = 42,
) -> dict[str, Any]:
    """Train and evaluate XGBoost with the day-aware split."""

    ensure_project_dirs()
    dataframe = pd.read_parquet(input_path)
    train_mask = dataframe["source_file"].str.startswith(("Monday", "Tuesday", "Wednesday", "Thursday"))
    test_mask = dataframe["source_file"].str.startswith("Friday")
    train_df = dataframe.loc[train_mask].copy()
    test_df = dataframe.loc[test_mask].copy()

    feature_columns = [column for column in dataframe.columns if column not in EXCLUDED_COLUMNS]
    x_train = train_df[feature_columns]
    y_train = train_df["binary_label"].astype(int)
    x_test = test_df[feature_columns]
    y_test = test_df["binary_label"].astype(int)

    hyperparameters = make_xgboost_hyperparameters(y_train, random_state)
    model = XGBClassifier(**hyperparameters)
    start = time.perf_counter()
    LOGGER.info("Training XGBoost day-aware baseline")
    model.fit(x_train, y_train)
    training_time_seconds = time.perf_counter() - start
    LOGGER.info("Training complete in %.3f seconds", training_time_seconds)

    metrics = {
        "model": "XGBClassifier",
        "task": "binary_ids_day_aware_validation",
        "input_path": str(input_path),
        "feature_count": len(feature_columns),
        "excluded_columns": sorted(EXCLUDED_COLUMNS),
        "train_files": sorted(train_df["source_file"].unique().tolist()),
        "test_files": sorted(test_df["source_file"].unique().tolist()),
        "hyperparameters": hyperparameters,
        "split_sizes": {"train": int(len(y_train)), "test": int(len(y_test))},
        "class_distribution": {"train": class_distribution(y_train), "test": class_distribution(y_test)},
        "training_time_seconds": float(training_time_seconds),
        "test_metrics": evaluate_classifier(model, x_test, y_test),
    }
    metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    LOGGER.info("Wrote XGBoost day-aware metrics: %s", metrics_path)
    write_day_report(report_path, metrics)

    comparison_table = write_model_comparison(
        REPORTS_DIR / "model_comparison.md",
        {
            "Random Forest - Random Split": (METRICS_DIR / "random_forest_metrics.json", "test_metrics"),
            "Random Forest - Day-Aware Split": (METRICS_DIR / "random_forest_day_split_metrics.json", "test_metrics"),
            "XGBoost - Random Split": (METRICS_DIR / "xgboost_metrics.json", "test_metrics"),
            "XGBoost - Day-Aware Split": (metrics_path, "test_metrics"),
        },
    )
    write_generalization_analysis(
        REPORTS_DIR / "generalization_analysis.md",
        METRICS_DIR / "random_forest_day_split_metrics.json",
        metrics_path,
        comparison_table,
    )
    return metrics


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Train XGBoost day-aware baseline.")
    parser.add_argument("--input-path", type=Path, default=PROCESSED_DIR / "cleaned_cicids.parquet")
    parser.add_argument("--metrics-path", type=Path, default=METRICS_DIR / "xgboost_day_split_metrics.json")
    parser.add_argument("--report-path", type=Path, default=REPORTS_DIR / "xgboost_day_split_report.md")
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    train_xgboost_day_split(
        input_path=args.input_path,
        metrics_path=args.metrics_path,
        report_path=args.report_path,
        random_state=args.random_state,
    )


if __name__ == "__main__":
    main()

