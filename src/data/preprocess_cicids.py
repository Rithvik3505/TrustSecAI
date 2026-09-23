"""Preprocess CICIDS2017 for the TrustSecAI Week 1 IDS pipeline.

The script cleans CICIDS2017 flow CSVs, writes audit outputs, and saves a cleaned
dataset plus an inspection sample. It intentionally stops at dataset preparation;
no model training is performed here.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any

import numpy as np
import pandas as pd

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.data.load_cicids import discover_cicids_files, inspect_cicids_files
from src.utils.logging import get_logger
from src.utils.paths import CICIDS_DIR, PROCESSED_DIR, REPORTS_DIR, ensure_project_dirs


LOGGER = get_logger(__name__)
RAW_LABEL_COLUMN = "Label"
MULTICLASS_LABEL_COLUMN = "label"
BINARY_LABEL_COLUMN = "binary_label"
SOURCE_FILE_COLUMN = "source_file"

EXPECTED_LABELS = {
    "BENIGN",
    "DDoS",
    "PortScan",
    "Bot",
    "Infiltration",
    "FTP-Patator",
    "SSH-Patator",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slowhttptest",
    "DoS slowloris",
    "Heartbleed",
    "Web Attack - Brute Force",
    "Web Attack - XSS",
    "Web Attack - Sql Injection",
}

LABEL_NORMALIZATION = {
    "BENIGN": "BENIGN",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "Bot": "Bot",
    "Infiltration": "Infiltration",
    "FTP-Patator": "FTP-Patator",
    "SSH-Patator": "SSH-Patator",
    "DoS GoldenEye": "DoS GoldenEye",
    "DoS Hulk": "DoS Hulk",
    "DoS Slowhttptest": "DoS Slowhttptest",
    "DoS slowloris": "DoS slowloris",
    "Heartbleed": "Heartbleed",
    "Web Attack Brute Force": "Web Attack - Brute Force",
    "Web Attack - Brute Force": "Web Attack - Brute Force",
    "Web Attack \ufffd Brute Force": "Web Attack - Brute Force",
    "Web Attack � Brute Force": "Web Attack - Brute Force",
    "Web Attack XSS": "Web Attack - XSS",
    "Web Attack - XSS": "Web Attack - XSS",
    "Web Attack \ufffd XSS": "Web Attack - XSS",
    "Web Attack � XSS": "Web Attack - XSS",
    "Web Attack Sql Injection": "Web Attack - Sql Injection",
    "Web Attack - Sql Injection": "Web Attack - Sql Injection",
    "Web Attack \ufffd Sql Injection": "Web Attack - Sql Injection",
    "Web Attack � Sql Injection": "Web Attack - Sql Injection",
}

NONFINITE_TOKENS = {"Infinity", "Inf", "-Infinity", "-Inf"}


@dataclass(frozen=True)
class PreprocessingStats:
    """Summary statistics for preprocessing."""

    rows_before: int
    rows_after: int
    rows_removed_invalid: int
    duplicate_rows_before: int
    duplicate_rows_removed: int
    columns_before: int
    columns_after: int
    invalid_rows_by_reason: dict[str, int]
    unknown_labels: dict[str, int]


def normalize_column_names(columns: list[str]) -> list[str]:
    """Strip whitespace and make duplicate columns unique."""

    counts: Counter[str] = Counter()
    normalized: list[str] = []

    for raw_column in columns:
        column = str(raw_column).strip()
        counts[column] += 1
        if counts[column] == 1:
            normalized.append(column)
        else:
            normalized.append(f"{column}.{counts[column] - 1}")

    return normalized


def normalize_label(value: Any) -> str:
    """Normalize raw CICIDS label values to the approved label vocabulary."""

    label = str(value).strip()
    label = " ".join(label.split())
    label = LABEL_NORMALIZATION.get(label, label)
    return label


def load_raw_cicids(data_dir: Path) -> pd.DataFrame:
    """Load all raw CICIDS files and attach the source file name."""

    inspect_cicids_files(data_dir)
    frames: list[pd.DataFrame] = []

    for path in discover_cicids_files(data_dir):
        LOGGER.info("Reading %s", path.name)
        frame = pd.read_csv(
            path,
            encoding="utf-8",
            encoding_errors="replace",
            na_values=["", "NaN", "nan", "null", "NULL"],
            keep_default_na=True,
            low_memory=False,
        )
        frame[SOURCE_FILE_COLUMN] = path.name
        LOGGER.info("Loaded %s | rows=%s | columns=%s", path.name, len(frame), len(frame.columns))
        frames.append(frame)

    return pd.concat(frames, ignore_index=True)


def build_feature_profile(
    raw_features: pd.DataFrame,
    numeric_features: pd.DataFrame,
) -> pd.DataFrame:
    """Create feature-level profile with dtype, missing, and non-finite counts."""

    profile_rows: list[dict[str, Any]] = []

    for column in raw_features.columns:
        raw_series = raw_features[column]
        numeric_series = numeric_features[column]
        profile_rows.append(
            {
                "feature": column,
                "dtype": str(numeric_series.dtype),
                "missing_count": int(numeric_series.isna().sum()),
                "non_finite_count": int(np.isinf(numeric_series.to_numpy(dtype=float)).sum()),
                "source_dtype": str(raw_series.dtype),
            }
        )

    return pd.DataFrame(profile_rows)


def write_label_distribution(labels: pd.Series, output_path: Path) -> pd.DataFrame:
    """Write label distribution CSV and return the dataframe."""

    counts = labels.value_counts(dropna=False).rename_axis("label").reset_index(name="count")
    counts["percentage"] = (counts["count"] / len(labels) * 100).round(6)
    counts.to_csv(output_path, index=False)
    return counts


def dataframe_to_markdown(dataframe: pd.DataFrame) -> str:
    """Render a small dataframe as a GitHub-flavored Markdown table."""

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


def save_cleaned_dataset(cleaned: pd.DataFrame, output_dir: Path, sample_size: int) -> tuple[Path | None, Path]:
    """Save cleaned data as parquet when supported and always save a sample CSV."""

    output_dir.mkdir(parents=True, exist_ok=True)
    parquet_path = output_dir / "cleaned_cicids.parquet"
    sample_path = output_dir / "cleaned_cicids_sample.csv"

    parquet_written: Path | None = None
    try:
        cleaned.to_parquet(parquet_path, index=False)
        parquet_written = parquet_path
        LOGGER.info("Wrote parquet dataset: %s", parquet_path)
    except Exception as exc:  # pragma: no cover - depends on optional engines.
        LOGGER.warning("Could not write parquet dataset: %s", exc)
        fallback_path = output_dir / "cleaned_cicids.csv"
        cleaned.to_csv(fallback_path, index=False)
        LOGGER.info("Wrote CSV fallback dataset: %s", fallback_path)

    cleaned.sample(n=min(sample_size, len(cleaned)), random_state=42).to_csv(sample_path, index=False)
    LOGGER.info("Wrote inspection sample: %s", sample_path)
    return parquet_written, sample_path


def write_preprocessing_report(
    path: Path,
    stats: PreprocessingStats,
    label_distribution: pd.DataFrame,
    profile: pd.DataFrame,
    parquet_path: Path | None,
    sample_path: Path,
) -> None:
    """Write a Markdown report summarizing preprocessing results."""

    total_missing = int(profile["missing_count"].sum())
    total_non_finite = int(profile["non_finite_count"].sum())
    top_missing = profile.sort_values("missing_count", ascending=False).head(10)
    labels_md = dataframe_to_markdown(label_distribution)
    missing_md = dataframe_to_markdown(top_missing)

    parquet_line = str(parquet_path) if parquet_path else "Not written; CSV fallback was created."

    report = f"""# CICIDS2017 Preprocessing Report

## Summary

| Metric | Value |
|---|---:|
| Rows before cleaning | {stats.rows_before:,} |
| Rows after cleaning | {stats.rows_after:,} |
| Rows removed | {stats.rows_before - stats.rows_after:,} |
| Rows removed for invalid/missing/non-finite values | {stats.rows_removed_invalid:,} |
| Duplicate rows before cleaning | {stats.duplicate_rows_before:,} |
| Duplicate rows removed | {stats.duplicate_rows_removed:,} |
| Columns before cleaning | {stats.columns_before:,} |
| Columns after cleaning | {stats.columns_after:,} |
| Total missing feature values before invalid-row removal | {total_missing:,} |
| Total non-finite feature values before replacement | {total_non_finite:,} |

## Invalid Row Reasons

| Reason | Rows |
|---|---:|
| Missing feature value | {stats.invalid_rows_by_reason.get("missing_feature", 0):,} |
| Non-finite feature value | {stats.invalid_rows_by_reason.get("non_finite_feature", 0):,} |
| Unknown label | {stats.invalid_rows_by_reason.get("unknown_label", 0):,} |

## Label Distribution After Cleaning

{labels_md}

## Top Missing-Value Features Before Cleaning

{missing_md}

## Unknown Labels

```json
{json.dumps(stats.unknown_labels, indent=2, sort_keys=True)}
```

## Output Files

- Cleaned parquet: `{parquet_line}`
- Cleaned sample CSV: `{sample_path}`
- Feature profile CSV: `reports/cicids_profile.csv`
- Label distribution CSV: `reports/cicids_label_distribution.csv`

## Assumptions

- CICIDS2017 is the only dataset used for Week 1 preprocessing.
- Label values are normalized to the approved vocabulary from the Week 1 plan.
- `BENIGN` maps to `binary_label=0`; every approved attack label maps to `binary_label=1`.
- Non-finite values are treated as invalid and removed for the first baseline dataset.
- Rows with missing feature values are removed for the first baseline dataset.
- Duplicate rows are removed after invalid rows are removed.
- The original multiclass label is preserved in the `label` column.
- A `source_file` column is retained for auditability but should not be used as a model feature.
"""

    path.write_text(report, encoding="utf-8")
    LOGGER.info("Wrote preprocessing report: %s", path)


def preprocess_cicids(
    data_dir: Path = CICIDS_DIR,
    reports_dir: Path = REPORTS_DIR,
    processed_dir: Path = PROCESSED_DIR,
    sample_size: int = 10000,
) -> PreprocessingStats:
    """Run the full CICIDS preprocessing workflow."""

    ensure_project_dirs()
    reports_dir.mkdir(parents=True, exist_ok=True)
    processed_dir.mkdir(parents=True, exist_ok=True)

    raw = load_raw_cicids(data_dir)
    rows_before = len(raw)
    columns_before = len(raw.columns)

    raw.columns = normalize_column_names(list(raw.columns))
    if RAW_LABEL_COLUMN not in raw.columns:
        raise ValueError(f"Expected label column not found: {RAW_LABEL_COLUMN}")

    raw[MULTICLASS_LABEL_COLUMN] = raw[RAW_LABEL_COLUMN].map(normalize_label)
    unknown_label_counts = (
        raw.loc[~raw[MULTICLASS_LABEL_COLUMN].isin(EXPECTED_LABELS), MULTICLASS_LABEL_COLUMN]
        .value_counts(dropna=False)
        .to_dict()
    )
    unknown_label_mask = ~raw[MULTICLASS_LABEL_COLUMN].isin(EXPECTED_LABELS)

    feature_columns = [
        column
        for column in raw.columns
        if column not in {RAW_LABEL_COLUMN, MULTICLASS_LABEL_COLUMN, SOURCE_FILE_COLUMN}
    ]
    raw_features = raw[feature_columns].replace(list(NONFINITE_TOKENS), np.nan)
    numeric_features = raw_features.apply(pd.to_numeric, errors="coerce")

    non_finite_mask = np.isinf(numeric_features.to_numpy(dtype=float))
    non_finite_by_column = pd.Series(non_finite_mask.sum(axis=0), index=feature_columns)
    numeric_features = numeric_features.replace([np.inf, -np.inf], np.nan)

    profile = build_feature_profile(raw_features, numeric_features)
    profile["non_finite_count"] = profile["feature"].map(non_finite_by_column.to_dict()).fillna(0).astype(int)
    profile.to_csv(reports_dir / "cicids_profile.csv", index=False)
    LOGGER.info("Wrote feature profile: %s", reports_dir / "cicids_profile.csv")

    missing_feature_mask = numeric_features.isna().any(axis=1)
    invalid_mask = missing_feature_mask | unknown_label_mask

    cleaned = numeric_features.loc[~invalid_mask].copy()
    cleaned[MULTICLASS_LABEL_COLUMN] = raw.loc[~invalid_mask, MULTICLASS_LABEL_COLUMN].to_numpy()
    cleaned[BINARY_LABEL_COLUMN] = (cleaned[MULTICLASS_LABEL_COLUMN] != "BENIGN").astype(int)
    cleaned[SOURCE_FILE_COLUMN] = raw.loc[~invalid_mask, SOURCE_FILE_COLUMN].to_numpy()

    duplicate_subset = [column for column in cleaned.columns if column != SOURCE_FILE_COLUMN]
    duplicate_rows_before = int(cleaned.duplicated(subset=duplicate_subset).sum())
    cleaned = cleaned.drop_duplicates(subset=duplicate_subset, ignore_index=True)
    duplicate_rows_removed = duplicate_rows_before

    label_distribution = write_label_distribution(
        cleaned[MULTICLASS_LABEL_COLUMN],
        reports_dir / "cicids_label_distribution.csv",
    )
    LOGGER.info("Wrote label distribution: %s", reports_dir / "cicids_label_distribution.csv")

    parquet_path, sample_path = save_cleaned_dataset(cleaned, processed_dir, sample_size)

    stats = PreprocessingStats(
        rows_before=rows_before,
        rows_after=len(cleaned),
        rows_removed_invalid=int(invalid_mask.sum()),
        duplicate_rows_before=duplicate_rows_before,
        duplicate_rows_removed=duplicate_rows_removed,
        columns_before=columns_before,
        columns_after=len(cleaned.columns),
        invalid_rows_by_reason={
            "missing_feature": int(missing_feature_mask.sum()),
            "non_finite_feature": int(non_finite_mask.any(axis=1).sum()),
            "unknown_label": int(unknown_label_mask.sum()),
        },
        unknown_labels={str(key): int(value) for key, value in unknown_label_counts.items()},
    )

    write_preprocessing_report(
        reports_dir / "preprocessing_report.md",
        stats,
        label_distribution,
        profile,
        parquet_path,
        sample_path,
    )

    LOGGER.info(
        "Preprocessing complete | rows_before=%s | rows_after=%s | removed=%s",
        stats.rows_before,
        stats.rows_after,
        stats.rows_before - stats.rows_after,
    )
    return stats


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(description="Preprocess CICIDS2017 for TrustSecAI.")
    parser.add_argument("--data-dir", type=Path, default=CICIDS_DIR)
    parser.add_argument("--reports-dir", type=Path, default=REPORTS_DIR)
    parser.add_argument("--processed-dir", type=Path, default=PROCESSED_DIR)
    parser.add_argument("--sample-size", type=int, default=10000)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    preprocess_cicids(
        data_dir=args.data_dir,
        reports_dir=args.reports_dir,
        processed_dir=args.processed_dir,
        sample_size=args.sample_size,
    )


if __name__ == "__main__":
    main()
