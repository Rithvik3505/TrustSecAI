"""Train Random Forest with a stricter CICIDS day-aware split.

Train days:
- Monday
- Tuesday
- Wednesday
- Thursday

Test day:
- Friday

This experiment checks whether the stratified random split baseline is inflated
by row-level leakage or file/day-specific traffic patterns.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.models.train_random_forest import EXCLUDED_COLUMNS, class_distribution, dataframe_to_markdown
from src.utils.logging import get_logger
from src.utils.paths import METRICS_DIR, PROCESSED_DIR, REPORTS_DIR, ensure_project_dirs


LOGGER = get_logger(__name__)


def evaluate_classifier(model: RandomForestClassifier, x: pd.DataFrame, y: pd.Series) -> dict[str, Any]:
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


def write_day_split_report(path: Path, metrics: dict[str, Any]) -> None:
    """Write the day-aware split report."""

    test_metrics = metrics["test_metrics"]
    cm = test_metrics["confusion_matrix"]
    metric_table = pd.DataFrame(
        [
            {
                "accuracy": f"{test_metrics['accuracy']:.6f}",
                "precision": f"{test_metrics['precision']:.6f}",
                "recall": f"{test_metrics['recall']:.6f}",
                "f1_score": f"{test_metrics['f1_score']:.6f}",
                "roc_auc": f"{test_metrics['roc_auc']:.6f}",
            }
        ]
    )

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

    report = f"""# Random Forest Day-Aware Split Report

## Scope

This experiment trains on Monday, Tuesday, Wednesday, and Thursday CICIDS2017 records and tests only on Friday records. It uses the same Random Forest hyperparameters as the stratified baseline.

## Split

- Train files: `{', '.join(metrics['train_files'])}`
- Test files: `{', '.join(metrics['test_files'])}`

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

Labels are ordered `[0, 1]`, where `0=BENIGN` and `1=ATTACK`.

|  | Predicted 0 | Predicted 1 |
|---|---:|---:|
| Actual 0 | {cm['tn']} | {cm['fp']} |
| Actual 1 | {cm['fn']} | {cm['tp']} |

## Class Distribution

{dataframe_to_markdown(pd.DataFrame(class_rows))}

## Observations

- This split is stricter than random row splitting because Friday attack scenarios are held out entirely from training.
- A performance drop relative to the random split is expected if row-level random splitting was benefiting from file/day-specific traffic similarity.
- This result is a better research-integrity check for generalization than the random split alone.
"""

    path.write_text(report, encoding="utf-8")
    LOGGER.info("Wrote day-aware report: %s", path)


def write_comparison_report(
    path: Path,
    random_metrics_path: Path,
    day_metrics: dict[str, Any],
) -> None:
    """Compare random stratified split and day-aware split results."""

    random_metrics = json.loads(random_metrics_path.read_text(encoding="utf-8"))
    random_test = random_metrics["test_metrics"]
    day_test = day_metrics["test_metrics"]
    rows = []
    for name, values in [
        ("Random Stratified Split", random_test),
        ("Day-Aware Split", day_test),
    ]:
        rows.append(
            {
                "evaluation": name,
                "accuracy": f"{values['accuracy']:.6f}",
                "precision": f"{values['precision']:.6f}",
                "recall": f"{values['recall']:.6f}",
                "f1_score": f"{values['f1_score']:.6f}",
                "roc_auc": f"{values['roc_auc']:.6f}",
            }
        )

    f1_delta = day_test["f1_score"] - random_test["f1_score"]
    recall_delta = day_test["recall"] - random_test["recall"]
    if f1_delta < -0.05:
        interpretation = (
            "The day-aware split shows a substantial performance drop. This suggests the random split likely "
            "overestimated generalization because records from the same capture days and attack scenarios were "
            "distributed across train and test."
        )
    elif f1_delta < -0.01:
        interpretation = (
            "The day-aware split shows a moderate performance drop. The model still transfers some behavior, but "
            "random split metrics are probably optimistic."
        )
    else:
        interpretation = (
            "The day-aware split remains close to the random split. This suggests the binary traffic patterns learned "
            "by the model generalize reasonably well across the held-out Friday files."
        )

    report = f"""# Validation Comparison

## Metrics

{dataframe_to_markdown(pd.DataFrame(rows))}

## Performance Difference

- F1 delta, day-aware minus random: `{f1_delta:.6f}`
- Recall delta, day-aware minus random: `{recall_delta:.6f}`

## Interpretation

{interpretation}

## Potential Leakage Discussion

The random stratified split is useful for a first sanity-check baseline, but it can place near-duplicate or same-capture traffic patterns into both training and test data. Because CICIDS2017 is organized by day and attack scenario, this can inflate reported performance.

The day-aware split is stricter because all Friday records are held out for testing. It better reflects the question: can the IDS trained on earlier days generalize to a later capture day with different attack mixes?

## Recommendation

For the final project, report both metrics:

- Use the random stratified split as the baseline comparability result.
- Use the day-aware split as the primary research-integrity generalization result.

If only one headline metric is allowed, prefer the day-aware split because it is less likely to benefit from row-level leakage.
"""

    path.write_text(report, encoding="utf-8")
    LOGGER.info("Wrote validation comparison: %s", path)


def train_day_split(
    input_path: Path = PROCESSED_DIR / "cleaned_cicids.parquet",
    metrics_path: Path = METRICS_DIR / "random_forest_day_split_metrics.json",
    report_path: Path = REPORTS_DIR / "random_forest_day_split_report.md",
    comparison_path: Path = REPORTS_DIR / "validation_comparison.md",
    random_metrics_path: Path = METRICS_DIR / "random_forest_metrics.json",
    random_state: int = 42,
) -> dict[str, Any]:
    """Run the day-aware Random Forest experiment."""

    ensure_project_dirs()
    dataframe = pd.read_parquet(input_path)
    train_mask = dataframe["source_file"].str.startswith(("Monday", "Tuesday", "Wednesday", "Thursday"))
    test_mask = dataframe["source_file"].str.startswith("Friday")

    train_df = dataframe.loc[train_mask].copy()
    test_df = dataframe.loc[test_mask].copy()
    if train_df.empty or test_df.empty:
        raise ValueError("Day-aware split produced an empty train or test set.")

    feature_columns = [column for column in dataframe.columns if column not in EXCLUDED_COLUMNS]
    x_train = train_df[feature_columns]
    y_train = train_df["binary_label"].astype(int)
    x_test = test_df[feature_columns]
    y_test = test_df["binary_label"].astype(int)

    hyperparameters = {
        "n_estimators": 100,
        "max_depth": None,
        "class_weight": "balanced_subsample",
        "n_jobs": -1,
        "random_state": random_state,
        "criterion": "gini",
    }
    model = RandomForestClassifier(**hyperparameters)
    start = time.perf_counter()
    LOGGER.info("Training day-aware Random Forest")
    model.fit(x_train, y_train)
    training_time_seconds = time.perf_counter() - start
    LOGGER.info("Training complete in %.3f seconds", training_time_seconds)

    metrics = {
        "model": "RandomForestClassifier",
        "task": "binary_ids_day_aware_validation",
        "input_path": str(input_path),
        "feature_count": len(feature_columns),
        "excluded_columns": sorted(EXCLUDED_COLUMNS),
        "train_files": sorted(train_df["source_file"].unique().tolist()),
        "test_files": sorted(test_df["source_file"].unique().tolist()),
        "hyperparameters": hyperparameters,
        "split_sizes": {"train": int(len(y_train)), "test": int(len(y_test))},
        "class_distribution": {
            "train": class_distribution(y_train),
            "test": class_distribution(y_test),
        },
        "training_time_seconds": float(training_time_seconds),
        "test_metrics": evaluate_classifier(model, x_test, y_test),
    }

    metrics_path.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
    LOGGER.info("Wrote day-aware metrics: %s", metrics_path)
    write_day_split_report(report_path, metrics)
    if random_metrics_path.exists():
        write_comparison_report(comparison_path, random_metrics_path, metrics)
    else:
        LOGGER.warning("Random split metrics not found; skipped comparison report: %s", random_metrics_path)
    return metrics


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Train Random Forest with CICIDS day-aware split.")
    parser.add_argument("--input-path", type=Path, default=PROCESSED_DIR / "cleaned_cicids.parquet")
    parser.add_argument("--metrics-path", type=Path, default=METRICS_DIR / "random_forest_day_split_metrics.json")
    parser.add_argument("--report-path", type=Path, default=REPORTS_DIR / "random_forest_day_split_report.md")
    parser.add_argument("--comparison-path", type=Path, default=REPORTS_DIR / "validation_comparison.md")
    parser.add_argument("--random-metrics-path", type=Path, default=METRICS_DIR / "random_forest_metrics.json")
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    train_day_split(
        input_path=args.input_path,
        metrics_path=args.metrics_path,
        report_path=args.report_path,
        comparison_path=args.comparison_path,
        random_metrics_path=args.random_metrics_path,
        random_state=args.random_state,
    )


if __name__ == "__main__":
    main()

