"""Load CICIDS2017 CSV files for the TrustSecAI IDS pipeline.

This module discovers all CICIDS2017 CSV files, verifies the basic schema, logs
per-file dimensions, and can concatenate the files into a single dataframe.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Iterable

import pandas as pd

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.utils.logging import get_logger
from src.utils.paths import CICIDS_DIR


LOGGER = get_logger(__name__)
LABEL_COLUMN = "Label"


@dataclass(frozen=True)
class CicidsFileInfo:
    """Metadata for one CICIDS CSV file."""

    path: Path
    row_count: int
    column_count: int
    columns: tuple[str, ...]
    duplicate_columns: tuple[str, ...]


def discover_cicids_files(data_dir: Path = CICIDS_DIR) -> list[Path]:
    """Return sorted CICIDS CSV files from ``data_dir``."""

    if not data_dir.exists():
        raise FileNotFoundError(f"CICIDS directory not found: {data_dir}")

    files = sorted(data_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CICIDS CSV files found in: {data_dir}")

    return files


def _find_duplicate_columns(columns: Iterable[str]) -> tuple[str, ...]:
    """Return duplicate column names while preserving first duplicate order."""

    seen: set[str] = set()
    duplicates: list[str] = []

    for column in columns:
        if column in seen and column not in duplicates:
            duplicates.append(column)
        seen.add(column)

    return tuple(duplicates)


def inspect_cicids_file(path: Path) -> CicidsFileInfo:
    """Inspect one CICIDS CSV file and return row/column/schema metadata."""

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        first_line = handle.readline().rstrip("\r\n")

    columns = tuple(column for column in first_line.split(","))
    stripped_columns = tuple(column.strip() for column in columns)
    duplicate_columns = _find_duplicate_columns(stripped_columns)

    if LABEL_COLUMN not in stripped_columns:
        raise ValueError(f"Missing label column in {path.name}")

    row_count = sum(1 for _ in path.open("r", encoding="utf-8", errors="replace")) - 1
    column_count = len(columns)

    LOGGER.info(
        "Discovered %s | rows=%s | columns=%s",
        path.name,
        row_count,
        column_count,
    )
    if duplicate_columns:
        LOGGER.warning("Duplicate columns in %s: %s", path.name, duplicate_columns)

    return CicidsFileInfo(
        path=path,
        row_count=row_count,
        column_count=column_count,
        columns=columns,
        duplicate_columns=duplicate_columns,
    )


def inspect_cicids_files(data_dir: Path = CICIDS_DIR) -> list[CicidsFileInfo]:
    """Inspect all CICIDS CSV files and validate schema consistency."""

    infos = [inspect_cicids_file(path) for path in discover_cicids_files(data_dir)]
    reference = infos[0].columns

    for info in infos[1:]:
        if len(info.columns) != len(reference):
            raise ValueError(
                f"Column count mismatch for {info.path.name}: "
                f"{len(info.columns)} != {len(reference)}"
            )
        if tuple(column.strip() for column in info.columns) != tuple(
            column.strip() for column in reference
        ):
            raise ValueError(f"Schema mismatch for {info.path.name}")

    LOGGER.info("Schema consistency check passed for %s files", len(infos))
    return infos


def load_cicids_dataframe(data_dir: Path = CICIDS_DIR) -> pd.DataFrame:
    """Load and concatenate all CICIDS CSV files into one dataframe."""

    infos = inspect_cicids_files(data_dir)
    frames: list[pd.DataFrame] = []

    for info in infos:
        LOGGER.info("Loading %s", info.path.name)
        frame = pd.read_csv(info.path, encoding="utf-8", encoding_errors="replace")
        frame["source_file"] = info.path.name
        frames.append(frame)

    combined = pd.concat(frames, ignore_index=True)
    LOGGER.info(
        "Combined CICIDS dataframe created | rows=%s | columns=%s",
        len(combined),
        len(combined.columns),
    )
    return combined


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(description="Inspect or load CICIDS2017 files.")
    parser.add_argument("--data-dir", type=Path, default=CICIDS_DIR)
    parser.add_argument(
        "--load",
        action="store_true",
        help="Load and concatenate all files after inspection.",
    )
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    if args.load:
        load_cicids_dataframe(args.data_dir)
    else:
        inspect_cicids_files(args.data_dir)


if __name__ == "__main__":
    main()
