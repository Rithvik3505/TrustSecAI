"""Build minimal CWE bridge nodes from referenced CWE IDs."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable


def normalize_cwe_id(raw_id: str) -> str:
    """Normalize a CWE ID."""

    cleaned = str(raw_id).strip()
    if not cleaned:
        return ""
    if cleaned.upper().startswith("CWE-") or cleaned.startswith("NVD-CWE-"):
        return cleaned.upper() if cleaned.upper().startswith("CWE-") else cleaned
    if cleaned.isdigit():
        return f"CWE-{cleaned}"
    return cleaned


def build_cwe_nodes(cwe_ids: Iterable[str], source: str, source_file: str) -> list[dict[str, str]]:
    """Create minimal CWE node dictionaries without inventing metadata."""

    ingested_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    nodes = []
    for cwe_id in sorted({normalize_cwe_id(value) for value in cwe_ids if normalize_cwe_id(value)}):
        nodes.append(
            {
                "cwe_id": cwe_id,
                "source": source,
                "source_file": source_file,
                "raw_id": cwe_id,
                "ingested_at": ingested_at,
            }
        )
    return nodes

