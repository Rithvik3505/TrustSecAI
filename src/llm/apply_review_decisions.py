"""Apply TrustSecAI gold-candidate v1 review decisions.

This script does not regenerate examples. It applies decisions from the
assistant-reviewed workbook CSV to the existing gold-candidate v1 JSONL and
exports a strict reviewed corpus plus a candidate-plus-reviewed corpus.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
V1_DIR = ROOT / "artifacts" / "gold_candidates" / "v1"
REVIEWED_DIR = V1_DIR / "reviewed"
REPORTS = ROOT / "reports"

ORIGINAL_JSONL = V1_DIR / "trustsecai_gold_candidate_v1.jsonl"
REVIEWED_CSV = V1_DIR / "review_workbook_assistant_reviewed.csv"
SPLIT_FILES = {
    "train": V1_DIR / "train.jsonl",
    "validation": V1_DIR / "validation.jsonl",
    "test": V1_DIR / "test.jsonl",
}

CHECK_COLUMNS = [
    "grounding_check",
    "uncertainty_check",
    "attribution_check",
    "graph_not_proof_check",
    "shap_check",
    "tone_check",
]


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load JSONL records."""

    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    """Write JSONL records."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_json(path: Path, value: Any) -> None:
    """Write pretty JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def load_review_decisions(path: Path) -> dict[str, dict[str, str]]:
    """Load review workbook CSV decisions keyed by example_id."""

    decisions: dict[str, dict[str, str]] = {}
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            example_id = row.get("example_id", "").strip()
            if not example_id:
                continue
            decisions[example_id] = {key: (value or "").strip() for key, value in row.items()}
    return decisions


def parse_revised_output(text: str) -> Any:
    """Validate and parse revised output JSON."""

    if not text or not text.strip():
        raise ValueError("revised_output is empty")
    return json.loads(text)


def allowed_security_ids(record: dict[str, Any]) -> dict[str, set[str]]:
    """Collect security IDs allowed by the supplied input context."""

    graph = record.get("input", {}).get("graph_context", {})
    return {
        "attack": {str(graph.get("attack_technique_id"))} if graph.get("attack_technique_id") else set(),
        "capec": {str(item) for item in graph.get("capec_ids", []) if item},
        "cwe": {str(item) for item in graph.get("cwe_ids", []) if item},
        "cve": {str(item) for item in graph.get("cve_ids", []) if item},
    }


def validate_revised_output(record: dict[str, Any], revised_output: Any) -> list[str]:
    """Lightweight validation that revised output does not introduce unsupported IDs/claims."""

    text = json.dumps(revised_output, ensure_ascii=False)
    allowed = allowed_security_ids(record)
    patterns = {
        "attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
        "capec": re.compile(r"\bCAPEC-\d+\b"),
        "cwe": re.compile(r"\bCWE-\d+\b"),
        "cve": re.compile(r"\bCVE-\d{4}-\d+\b"),
    }
    issues = []
    for kind, pattern in patterns.items():
        for found in pattern.findall(text):
            if found not in allowed[kind]:
                issues.append(f"unsupported {kind} id in revised_output: {found}")
    lower = text.lower()
    if "asset exposure is confirmed" in lower or "product is exposed" in lower:
        issues.append("revised_output appears to introduce asset exposure")
    if "attributed to" in lower:
        issues.append("revised_output appears to introduce attribution")
    if "multiclass probability" in lower and "not" not in lower and "do not" not in lower:
        issues.append("revised_output appears to introduce multiclass probability")
    return issues


def add_review_metadata(record: dict[str, Any], decision_row: dict[str, str] | None, include_unreviewed: bool) -> dict[str, Any] | None:
    """Apply one review decision to a record."""

    updated = deepcopy(record)
    metadata = updated.setdefault("metadata", {})
    if decision_row is None:
        if not include_unreviewed:
            return None
        metadata.update(
            {
                "review_status": "candidate_unreviewed",
                "review_source": "none",
                "review_decision": "unreviewed",
                "reviewer_notes": "",
                "review_checks": {column: "pending" for column in CHECK_COLUMNS},
            }
        )
        return updated

    decision = decision_row.get("reviewer_decision", "").strip().lower()
    if decision not in {"approve", "revise", "reject"}:
        raise ValueError(f"Unsupported review decision for {metadata.get('example_id')}: {decision}")
    metadata["review_source"] = "assistant_review_workbook"
    metadata["review_decision"] = decision
    metadata["reviewer_notes"] = decision_row.get("reviewer_notes", "")
    metadata["review_checks"] = {column: decision_row.get(column, "") for column in CHECK_COLUMNS}

    if decision == "reject":
        metadata["review_status"] = "rejected"
        return None
    if decision == "approve":
        metadata["review_status"] = "approved"
        return updated

    revised = parse_revised_output(decision_row.get("revised_output", ""))
    issues = validate_revised_output(updated, revised)
    if issues:
        raise ValueError(f"Invalid revised_output for {metadata.get('example_id')}: {issues}")
    updated["output"] = revised
    metadata["review_status"] = "revised"
    return updated


def build_corpora(records: list[dict[str, Any]], decisions: dict[str, dict[str, str]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Build strict reviewed and candidate-plus-reviewed corpora."""

    strict: list[dict[str, Any]] = []
    candidate_plus: list[dict[str, Any]] = []
    decision_counts: Counter[str] = Counter()
    unmatched_decisions = sorted(set(decisions) - {r["metadata"]["example_id"] for r in records})

    for record in records:
        example_id = record["metadata"]["example_id"]
        decision_row = decisions.get(example_id)
        if decision_row:
            decision_counts[decision_row.get("reviewer_decision", "").strip().lower()] += 1
        else:
            decision_counts["unreviewed"] += 1
        strict_record = add_review_metadata(record, decision_row, include_unreviewed=False)
        if strict_record is not None:
            strict.append(strict_record)
        plus_record = add_review_metadata(record, decision_row, include_unreviewed=True)
        if plus_record is not None:
            candidate_plus.append(plus_record)

    return strict, candidate_plus, {"decision_counts": dict(decision_counts), "unmatched_decisions": unmatched_decisions}


def output_text(record: dict[str, Any]) -> str:
    """Serialize target output for duplicate checks."""

    return json.dumps(record.get("output", {}), sort_keys=True, ensure_ascii=False)


def split_leakage(splits: dict[str, list[dict[str, Any]]]) -> dict[str, list[str]]:
    """Check base_context_id leakage across splits."""

    base_sets = {name: {r["metadata"].get("base_context_id") for r in rows} for name, rows in splits.items()}
    return {
        "train_validation": sorted(base_sets.get("train", set()) & base_sets.get("validation", set())),
        "train_test": sorted(base_sets.get("train", set()) & base_sets.get("test", set())),
        "validation_test": sorted(base_sets.get("validation", set()) & base_sets.get("test", set())),
    }


def validate_corpus(records: list[dict[str, Any]], splits: dict[str, list[dict[str, Any]]] | None, name: str) -> dict[str, Any]:
    """Validate an exported reviewed corpus."""

    ids = [r["metadata"].get("example_id") for r in records]
    duplicate_ids = [item for item, count in Counter(ids).items() if count > 1]
    duplicate_outputs = sum(count - 1 for count in Counter(output_text(r) for r in records).values() if count > 1)
    flagged = []
    for record in records:
        meta = record.get("metadata", {})
        if not meta.get("base_context_id"):
            flagged.append({"example_id": meta.get("example_id"), "issue": "missing base_context_id"})
        if meta.get("sample_id") is None:
            flagged.append({"example_id": meta.get("example_id"), "issue": "missing sample_id"})
        if not record.get("output", {}).get("provenance"):
            flagged.append({"example_id": meta.get("example_id"), "issue": "missing provenance in output"})
        if meta.get("review_decision") not in {"approve", "revise", "reject", "unreviewed"}:
            flagged.append({"example_id": meta.get("example_id"), "issue": "unsupported review decision"})
        if meta.get("review_status") == "rejected":
            flagged.append({"example_id": meta.get("example_id"), "issue": "rejected example included"})
    leakage = split_leakage(splits) if splits else {"train_validation": [], "train_test": [], "validation_test": []}
    split_counts = {split: len(rows) for split, rows in (splits or {}).items()}
    return {
        "corpus": name,
        "total_examples": len(records),
        "approved_count": sum(1 for r in records if r["metadata"].get("review_status") == "approved"),
        "revised_count": sum(1 for r in records if r["metadata"].get("review_status") == "revised"),
        "rejected_count": sum(1 for r in records if r["metadata"].get("review_status") == "rejected"),
        "unreviewed_count": sum(1 for r in records if r["metadata"].get("review_status") == "candidate_unreviewed"),
        "duplicate_example_ids": duplicate_ids,
        "duplicate_target_outputs": duplicate_outputs,
        "flagged": flagged,
        "split_leakage": leakage,
        "split_counts": split_counts,
        "ids_label_distribution": dict(Counter(r["metadata"].get("ids_label") for r in records)),
        "task_distribution": dict(Counter(r["metadata"].get("task_type") for r in records)),
        "confidence_band_distribution": dict(Counter(r["metadata"].get("confidence_band") for r in records)),
        "cve_distribution": dict(Counter("cve_present" if r["metadata"].get("has_cve") else "cve_absent" for r in records)),
        "shap_coverage": dict(Counter(str(r["metadata"].get("has_real_shap")) for r in records)),
        "provenance_type_distribution": dict(Counter(r["metadata"].get("provenance_type") for r in records)),
        "passed": not duplicate_ids and not flagged and not any(leakage.values()),
    }


def filter_splits(approved_ids: set[str], records_by_id: dict[str, dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Filter original split files to reviewed approved/revised examples."""

    splits: dict[str, list[dict[str, Any]]] = {}
    for split, path in SPLIT_FILES.items():
        rows = []
        for original in load_jsonl(path):
            example_id = original["metadata"]["example_id"]
            if example_id in approved_ids:
                rows.append(records_by_id[example_id])
        splits[split] = rows
    return splits


def write_reports(strict_quality: dict[str, Any], plus_quality: dict[str, Any], application: dict[str, Any]) -> None:
    """Write review application and readiness reports."""

    REPORTS.mkdir(parents=True, exist_ok=True)
    application_lines = [
        "# TrustSecAI Gold v1 Review Application Report",
        "",
        f"Created: {date.today().isoformat()}",
        "",
        f"- Review CSV: `{REVIEWED_CSV.as_posix()}`",
        f"- Original candidate dataset: `{ORIGINAL_JSONL.as_posix()}`",
        f"- Decisions loaded: {sum(application['decision_counts'].values()) - application['decision_counts'].get('unreviewed', 0)}",
        f"- Decision counts: {application['decision_counts']}",
        f"- Unmatched decision rows: {len(application['unmatched_decisions'])}",
        "",
        "Strict reviewed corpus includes only approved/revised reviewed rows. Candidate-plus-approved includes reviewed rows plus unreviewed candidates with explicit unreviewed metadata.",
    ]
    (REPORTS / "trustsecai_gold_v1_review_application_report.md").write_text("\n".join(application_lines) + "\n", encoding="utf-8")

    quality_lines = [
        "# TrustSecAI Gold v1 Reviewed Quality Report",
        "",
        "## Strict Reviewed Corpus",
        "",
        "```json",
        json.dumps(strict_quality, indent=2),
        "```",
        "",
        "## Candidate-Plus-Approved Corpus",
        "",
        "```json",
        json.dumps(plus_quality, indent=2),
        "```",
    ]
    (REPORTS / "trustsecai_gold_v1_reviewed_quality_report.md").write_text("\n".join(quality_lines) + "\n", encoding="utf-8")

    split_lines = [
        "# TrustSecAI Gold v1 Reviewed Split Report",
        "",
        f"- Strict reviewed split counts: {strict_quality['split_counts']}",
        f"- Strict reviewed split leakage: {strict_quality['split_leakage']}",
        "",
        "Splits were filtered from the original v1 split files; no reshuffling was performed.",
    ]
    (REPORTS / "trustsecai_gold_v1_reviewed_split_report.md").write_text("\n".join(split_lines) + "\n", encoding="utf-8")

    readiness = [
        "# TrustSecAI Gold v1 Training Corpus Readiness",
        "",
        "## Recommendation",
        "",
        "Use the strict reviewed corpus for the first clean LoRA experiment. It is smaller, but every included example has an explicit approve/revise review decision.",
        "",
        "Keep the candidate-plus-approved corpus for later ablation experiments because it contains unreviewed candidate examples clearly labeled as `candidate_unreviewed`.",
        "",
        "## Corpora",
        "",
        f"- Strict reviewed examples: {strict_quality['total_examples']}",
        f"- Candidate-plus-approved examples: {plus_quality['total_examples']}",
        f"- Strict reviewed quality passed: {strict_quality['passed']}",
        f"- Candidate-plus-approved quality passed: {plus_quality['passed']}",
        "",
        "No LoRA training or inference was performed.",
    ]
    (REPORTS / "trustsecai_gold_v1_training_corpus_readiness.md").write_text("\n".join(readiness) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Apply TrustSecAI v1 review decisions.")
    parser.add_argument("--original-jsonl", type=Path, default=ORIGINAL_JSONL)
    parser.add_argument("--reviewed-csv", type=Path, default=REVIEWED_CSV)
    return parser.parse_args()


def main() -> None:
    """Apply review decisions and export corpora."""

    args = parse_args()
    global ORIGINAL_JSONL, REVIEWED_CSV
    ORIGINAL_JSONL = args.original_jsonl
    REVIEWED_CSV = args.reviewed_csv

    REVIEWED_DIR.mkdir(parents=True, exist_ok=True)
    original_records = load_jsonl(ORIGINAL_JSONL)
    decisions = load_review_decisions(REVIEWED_CSV)
    strict, candidate_plus, application = build_corpora(original_records, decisions)

    strict_by_id = {r["metadata"]["example_id"]: r for r in strict}
    strict_splits = filter_splits(set(strict_by_id), strict_by_id)

    write_jsonl(REVIEWED_DIR / "trustsecai_gold_v1_reviewed.jsonl", strict)
    write_json(REVIEWED_DIR / "trustsecai_gold_v1_reviewed_pretty.json", strict)
    write_jsonl(REVIEWED_DIR / "trustsecai_gold_v1_candidate_plus_reviewed.jsonl", candidate_plus)
    write_json(REVIEWED_DIR / "trustsecai_gold_v1_candidate_plus_reviewed_pretty.json", candidate_plus)
    for split, rows in strict_splits.items():
        write_jsonl(REVIEWED_DIR / f"{split}_reviewed.jsonl", rows)

    strict_quality = validate_corpus(strict, strict_splits, "strict_reviewed")
    plus_quality = validate_corpus(candidate_plus, None, "candidate_plus_reviewed")
    write_json(REVIEWED_DIR / "trustsecai_gold_v1_reviewed_quality_report.json", strict_quality)
    write_json(REVIEWED_DIR / "trustsecai_gold_v1_candidate_plus_reviewed_quality_report.json", plus_quality)
    write_reports(strict_quality, plus_quality, application)


if __name__ == "__main__":
    main()
