"""Automatic quality checks for TrustSecAI corpus examples."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Set


ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
TACTIC_RE = re.compile(r"\bTA\d{4}\b")
MITIGATION_RE = re.compile(r"\bM\d{4}\b")
CAPEC_RE = re.compile(r"\bCAPEC-\d+\b")
CWE_RE = re.compile(r"\bCWE-\d+\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
INTERNAL_OUTPUT_PATTERNS = (
    "this example prepares future agreement analysis",
    "no agreement module is executed",
    "this is a training example",
    "difficulty level",
    "generation pipeline",
    "corpus generator",
    "dataset generator",
    "future module",
)
PERSONA_LABEL_PATTERNS = (
    "tier-1 soc analyst",
    "tier-2 soc analyst",
    "tier-3 soc analyst",
    "threat hunter",
    "incident responder",
    "blue team engineer",
    "executive briefing analyst",
    "security assurance analyst",
)


@dataclass
class QualityResult:
    """Validation result for one record."""

    valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def stable_hash(record: Mapping[str, Any]) -> str:
    """Return a deterministic hash for duplicate detection."""

    payload = json.dumps(record, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def flatten_text(value: Any) -> str:
    """Flatten nested JSON-like data into text for identifier checks."""

    if isinstance(value, dict):
        return " ".join(flatten_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(flatten_text(v) for v in value)
    return str(value)


def collect_allowed_ids(graph_context: Mapping[str, Any]) -> Set[str]:
    """Collect all entity IDs allowed by the supplied graph context."""

    allowed: Set[str] = set()

    def add_entity(entity: Any) -> None:
        if isinstance(entity, dict):
            for key in ("id", "attack_id", "cve_id", "cwe_id"):
                value = entity.get(key) or entity.get("properties", {}).get(key)
                if value:
                    allowed.add(str(value))
            for child in entity.values():
                add_entity(child)
        elif isinstance(entity, list):
            for item in entity:
                add_entity(item)

    add_entity(graph_context)
    for provenance in graph_context.get("provenance", []):
        if isinstance(provenance, dict):
            for key in ("origin_node", "target_node"):
                if provenance.get(key):
                    allowed.add(str(provenance[key]))
    return allowed


def collect_output_ids(output: Mapping[str, Any]) -> Set[str]:
    """Collect security IDs mentioned in output."""

    text = flatten_text(output)
    ids: Set[str] = set()
    for regex in (ATTACK_RE, TACTIC_RE, MITIGATION_RE, CAPEC_RE, CWE_RE, CVE_RE):
        ids.update(regex.findall(text))
    return ids


def validate_record(record: Mapping[str, Any], seen_hashes: Set[str]) -> QualityResult:
    """Validate one corpus record."""

    errors: List[str] = []
    warnings: List[str] = []
    required = ("instruction", "input", "output", "metadata")
    for key in required:
        if key not in record:
            errors.append(f"missing top-level field: {key}")
    if errors:
        return QualityResult(False, errors, warnings)

    try:
        json.dumps(record, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        errors.append(f"malformed json: {exc}")

    digest = stable_hash(record)
    if digest in seen_hashes:
        errors.append("duplicate example")
    seen_hashes.add(digest)

    input_data = record.get("input", {})
    graph_context = input_data.get("graph_context", {}) if isinstance(input_data, dict) else {}
    output = record.get("output", {})
    metadata = record.get("metadata", {})
    provenance = graph_context.get("provenance", []) if isinstance(graph_context, dict) else []
    if metadata.get("provenance_required", True) and not provenance:
        errors.append("missing provenance")

    allowed_ids = collect_allowed_ids(graph_context)
    output_ids = collect_output_ids(output if isinstance(output, dict) else {"output": output})
    invented = sorted(output_ids - allowed_ids)
    if invented:
        errors.append(f"invented security identifiers: {', '.join(invented[:10])}")

    output_text = flatten_text(output).lower()
    if "attributed to" in output_text or "responsible for this incident" in output_text:
        errors.append("unsupported attribution phrasing")
    if "confirmed exposure" in output_text and "asset evidence" not in output_text:
        errors.append("unsupported asset exposure claim")

    if metadata.get("variant") == "negative" and "unsupported" not in output_text:
        warnings.append("negative example does not explicitly mention unsupported conclusions")
    for pattern in INTERNAL_OUTPUT_PATTERNS:
        if pattern in output_text:
            errors.append(f"training/internal output phrase: {pattern}")
    for pattern in PERSONA_LABEL_PATTERNS:
        if pattern in output_text:
            errors.append(f"visible persona label in output: {pattern}")

    return QualityResult(not errors, errors, warnings)


def persona_bucket(example_id: str) -> str:
    """Derive deterministic persona bucket from example ID without schema changes."""

    try:
        sequence = int(str(example_id).rsplit("-", 1)[-1])
    except (TypeError, ValueError):
        sequence = 0
    return str(sequence % 8)


def validate_records(records: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    """Validate all records and return a report."""

    seen: Set[str] = set()
    accepted = 0
    rejected = 0
    warnings: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    for index, record in enumerate(records):
        result = validate_record(record, seen)
        if result.valid:
            accepted += 1
        else:
            rejected += 1
            errors.append(
                {
                    "index": index,
                    "example_id": record.get("metadata", {}).get("example_id"),
                    "errors": result.errors,
                }
            )
        if result.warnings:
            warnings.append(
                {
                    "index": index,
                    "example_id": record.get("metadata", {}).get("example_id"),
                    "warnings": result.warnings,
                }
            )
    return {
        "accepted": accepted,
        "rejected": rejected,
        "errors": errors,
        "warnings": warnings,
    }
