"""Parse CAPEC CSV data for TrustSecAI graph ingestion."""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.utils.paths import DATASETS_DIR


CAPEC_PRIMARY_PATH = DATASETS_DIR / "CAPEC" / "Comprehensive Dictionary" / "2000.csv"

RELATIONSHIP_MAP = {
    "ChildOf": "CHILD_OF",
    "CanPrecede": "CAN_PRECEDE",
    "CanFollow": "CAN_FOLLOW",
    "PeerOf": "PEER_OF",
    "CanAlsoBe": "CAN_ALSO_BE",
}


@dataclass
class CapecParseResult:
    """Parsed CAPEC graph payload."""

    source_file: str
    ingested_at: str
    patterns: list[dict[str, Any]] = field(default_factory=list)
    relationships: dict[str, list[dict[str, Any]]] = field(default_factory=lambda: {value: [] for value in RELATIONSHIP_MAP.values()})
    related_weakness: list[dict[str, Any]] = field(default_factory=list)
    attack_mappings: list[dict[str, Any]] = field(default_factory=list)
    cwe_ids: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)


def _clean_header(header: str) -> str:
    return header.strip().strip("'").strip('"')


def _value(row: dict[str, str], key: str) -> str:
    return (row.get(key) or "").strip()


def normalize_attack_id(raw_id: str) -> str:
    """Normalize CAPEC ATT&CK taxonomy IDs."""

    cleaned = raw_id.strip()
    if cleaned and cleaned[0].isdigit():
        return f"T{cleaned}"
    return cleaned


def normalize_cwe_id(raw_id: str) -> str:
    """Normalize a CWE numeric ID."""

    cleaned = raw_id.strip()
    if not cleaned:
        return ""
    if cleaned.upper().startswith("CWE-"):
        return cleaned.upper()
    if cleaned.isdigit():
        return f"CWE-{cleaned}"
    return cleaned


def read_capec_rows(path: Path) -> list[dict[str, str]]:
    """Read CAPEC CSV with normalized headers."""

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return []
        fieldnames = [_clean_header(name) for name in reader.fieldnames]
        rows = []
        for raw in reader:
            rows.append({_clean_header(key): value for key, value in raw.items() if key is not None})
        # If csv kept the original quoted header literally, normalize through field order.
        normalized_rows = []
        for row in rows:
            normalized = {}
            for original, clean in zip(row.keys(), fieldnames):
                normalized[clean] = row.get(original, "")
            normalized_rows.append(normalized)
        return normalized_rows


def parse_related_patterns(text: str) -> list[tuple[str, str]]:
    """Extract CAPEC related pattern pairs as (nature, target_capec_id)."""

    matches = re.findall(r"NATURE:([^:]+):CAPEC ID:([^:]+):", text or "")
    return [(nature.strip(), target.strip()) for nature, target in matches]


def parse_related_weaknesses(text: str) -> list[str]:
    """Extract CWE IDs from CAPEC Related Weaknesses."""

    return [normalize_cwe_id(match) for match in re.findall(r"::([^:]+)::", text or "") if normalize_cwe_id(match)]


def parse_attack_mappings(text: str) -> list[str]:
    """Extract ATT&CK IDs from CAPEC taxonomy mappings."""

    ids = re.findall(r"TAXONOMY NAME:ATTACK:ENTRY ID:([^:]+):", text or "")
    return [normalize_attack_id(value) for value in ids]


def parse_capec(path: Path = CAPEC_PRIMARY_PATH) -> CapecParseResult:
    """Parse the CAPEC comprehensive dictionary."""

    ingested_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    result = CapecParseResult(source_file=str(path), ingested_at=ingested_at)
    rows = read_capec_rows(path)

    for row in rows:
        capec_id = _value(row, "ID")
        if not capec_id:
            result.warnings.append("Skipped CAPEC row with missing ID")
            continue
        node = {
            "capec_id": f"CAPEC-{capec_id}" if not capec_id.startswith("CAPEC-") else capec_id,
            "name": _value(row, "Name"),
            "description": _value(row, "Description"),
            "abstraction": _value(row, "Abstraction"),
            "status": _value(row, "Status"),
            "likelihood": _value(row, "Likelihood Of Attack"),
            "severity": _value(row, "Typical Severity"),
            "execution_flow": _value(row, "Execution Flow"),
            "prerequisites": _value(row, "Prerequisites"),
            "skills_required": _value(row, "Skills Required"),
            "resources_required": _value(row, "Resources Required"),
            "indicators": _value(row, "Indicators"),
            "consequences": _value(row, "Consequences"),
            "mitigations": _value(row, "Mitigations"),
            "example_instances": _value(row, "Example Instances"),
            "notes": _value(row, "Notes"),
            "source": "CAPEC",
            "source_file": str(path),
            "raw_id": capec_id,
            "ingested_at": ingested_at,
        }
        result.patterns.append(node)

        for nature, target in parse_related_patterns(_value(row, "Related Attack Patterns")):
            rel_type = RELATIONSHIP_MAP.get(nature)
            if not rel_type:
                result.warnings.append(f"Unsupported CAPEC relationship nature {nature} for {capec_id}")
                continue
            result.relationships[rel_type].append(
                {
                    "source_id": node["capec_id"],
                    "target_id": f"CAPEC-{target}" if not target.startswith("CAPEC-") else target,
                    "raw_relationship_id": f"{node['capec_id']}:{nature}:{target}",
                    "raw_nature": nature,
                    "source": "CAPEC",
                    "source_file": str(path),
                    "confidence": "source",
                    "inferred": False,
                    "ingested_at": ingested_at,
                }
            )

        for cwe_id in parse_related_weaknesses(_value(row, "Related Weaknesses")):
            result.cwe_ids.add(cwe_id)
            result.related_weakness.append(
                {
                    "source_id": node["capec_id"],
                    "target_id": cwe_id,
                    "raw_relationship_id": f"{node['capec_id']}:RELATED_WEAKNESS:{cwe_id}",
                    "source": "CAPEC",
                    "source_file": str(path),
                    "confidence": "source",
                    "inferred": False,
                    "ingested_at": ingested_at,
                }
            )

        for attack_id in parse_attack_mappings(_value(row, "Taxonomy Mappings")):
            result.attack_mappings.append(
                {
                    "source_id": node["capec_id"],
                    "target_attack_id": attack_id,
                    "raw_relationship_id": f"{node['capec_id']}:MAPS_TO_ATTACK:{attack_id}",
                    "source": "CAPEC",
                    "source_file": str(path),
                    "taxonomy_name": "ATTACK",
                    "confidence": "source",
                    "inferred": False,
                    "ingested_at": ingested_at,
                }
            )

    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parse CAPEC comprehensive dictionary.")
    parser.add_argument("--input", type=Path, default=CAPEC_PRIMARY_PATH)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    parsed = parse_capec(args.input)
    print(json.dumps({
        "patterns": len(parsed.patterns),
        "relationships": {key: len(value) for key, value in parsed.relationships.items()},
        "related_weakness": len(parsed.related_weakness),
        "attack_mappings": len(parsed.attack_mappings),
        "cwe_ids": len(parsed.cwe_ids),
        "warnings": len(parsed.warnings),
    }, indent=2))


if __name__ == "__main__":
    main()

