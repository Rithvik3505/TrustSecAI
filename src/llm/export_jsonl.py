"""Export helpers for TrustSecAI corpus examples."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Mapping


def write_jsonl(records: Iterable[Mapping[str, object]], path: Path) -> None:
    """Write records as UTF-8 JSONL."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def write_pretty_json(records: Iterable[Mapping[str, object]], path: Path) -> None:
    """Write records as pretty JSON for manual review."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(list(records), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

