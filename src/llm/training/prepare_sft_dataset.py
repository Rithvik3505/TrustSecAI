"""Prepare reviewed TrustSecAI examples for Llama-style SFT."""

from __future__ import annotations

import argparse
import json
import random
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
REVIEWED_DIR = ROOT / "artifacts" / "gold_candidates" / "v1" / "reviewed"
OUT_DIR = ROOT / "artifacts" / "training" / "datasets"
REPORT_PATH = ROOT / "reports" / "training" / "sft_dataset_preparation_report.md"
SYSTEM_MESSAGE = (
    "You are TrustSecAI, a security incident analysis assistant. Use only the supplied classifier, SHAP, "
    "and graph context. Do not invent asset exposure, attribution, or vulnerability confirmation."
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load JSONL."""

    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    """Write JSONL."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def clean_metadata(metadata: dict[str, Any], split: str) -> dict[str, Any]:
    """Keep provenance metadata and remove review-only text from training rows."""

    allowed = [
        "example_id",
        "base_context_id",
        "sample_id",
        "ids_label",
        "model_prediction",
        "model_confidence",
        "confidence_band",
        "task_type",
        "task_variant",
        "difficulty",
        "provenance_type",
        "has_real_shap",
        "has_cve",
        "source_file",
        "source_artifact_refs",
        "review_status",
        "review_source",
        "review_decision",
    ]
    cleaned = {key: metadata.get(key) for key in allowed if key in metadata}
    cleaned["split"] = split
    return cleaned


def user_payload(record: dict[str, Any]) -> str:
    """Build user message from instruction and structured input."""

    return (
        f"Instruction:\n{record['instruction']}\n\n"
        "Supplied TrustSecAI context:\n"
        f"{json.dumps(record['input'], indent=2, ensure_ascii=False)}"
    )


def compact_input(record: dict[str, Any]) -> dict[str, Any]:
    """Build a compact context that preserves critical grounding fields."""

    source_input = record["input"]
    classifier = source_input.get("classifier", {})
    sample = source_input.get("sample", {})
    graph = source_input.get("graph_context", {})
    output = record.get("output", {})
    limitations = output.get("limitations", []) if isinstance(output, dict) else []
    return {
        "classifier": {
            "model_type": classifier.get("model_type"),
            "model_prediction": classifier.get("model_prediction"),
            "model_confidence": classifier.get("model_confidence"),
            "confidence_band": classifier.get("confidence_band"),
            "ids_subtype_basis": classifier.get("ids_subtype_basis"),
            "ids_label_ground_truth": classifier.get("ids_label_ground_truth"),
        },
        "sample": {
            "sample_id": sample.get("sample_id"),
            "source_file": sample.get("source_file"),
        },
        "shap": {
            "has_real_shap": source_input.get("shap", {}).get("has_real_shap"),
            "top_features": source_input.get("shap", {}).get("top_features", [])[:4],
        },
        "graph_context": {
            "retrieval_context_path": graph.get("retrieval_context_path"),
            "attack_technique_id": graph.get("attack_technique_id"),
            "tactic_ids": graph.get("tactic_ids", []),
            "mitigation_ids": graph.get("mitigation_ids", []),
            "capec_ids": graph.get("capec_ids", []),
            "cwe_ids": graph.get("cwe_ids", []),
            "cve_ids": graph.get("cve_ids", []),
            "product_id_count": len(graph.get("product_ids", [])),
            "provenance_type": graph.get("provenance_type"),
            "evidence_completeness": graph.get("evidence_completeness", {}),
            "summary": {
                "technique": graph.get("summary", {}).get("technique"),
                "tactics": graph.get("summary", {}).get("tactics", []),
                "mitigations": graph.get("summary", {}).get("mitigations", []),
                "capec": graph.get("summary", {}).get("capec", []),
                "cwes": graph.get("summary", {}).get("cwes", []),
                "cves": graph.get("summary", {}).get("cves", []),
                "provenance_summary": {
                    "type": graph.get("provenance_type"),
                    "source_artifacts": record.get("metadata", {}).get("source_artifact_refs", []),
                    "provenance_ids_preserved": True,
                },
            },
        },
        "evidence_gaps": limitations,
        "analyst_constraints": source_input.get("analyst_constraints", {}),
        "base_context_id": source_input.get("base_context_id"),
    }


def user_payload_compact(record: dict[str, Any]) -> str:
    """Build compact user message."""

    return (
        f"Instruction:\n{record['instruction']}\n\n"
        "Compact supplied TrustSecAI context:\n"
        f"{json.dumps(compact_input(record), indent=2, ensure_ascii=False)}"
    )


def chat_text(system: str, user: str, assistant: Any) -> str:
    """Render a simple Llama-compatible chat-style text."""

    assistant_text = json.dumps(assistant, indent=2, ensure_ascii=False)
    return (
        "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
        f"{system}<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n"
        f"{user}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
        f"{assistant_text}<|eot_id|>"
    )


def convert_record(record: dict[str, Any], split: str, compact_context: bool = False) -> dict[str, Any]:
    """Convert one reviewed example to SFT row."""

    if not record.get("instruction") or not record.get("input") or not record.get("output"):
        raise ValueError(f"Missing instruction/input/output for {record.get('metadata', {}).get('example_id')}")
    metadata = record.get("metadata", {})
    required = ["example_id", "base_context_id", "sample_id", "task_type", "ids_label"]
    missing = [key for key in required if metadata.get(key) in {None, ""}]
    if missing:
        raise ValueError(f"Missing metadata {missing} for {metadata.get('example_id')}")
    user = user_payload_compact(record) if compact_context else user_payload(record)
    return {
        "text": chat_text(SYSTEM_MESSAGE, user, record["output"]),
        "messages": [
            {"role": "system", "content": SYSTEM_MESSAGE},
            {"role": "user", "content": user},
            {"role": "assistant", "content": json.dumps(record["output"], indent=2, ensure_ascii=False)},
        ],
        "metadata": clean_metadata(metadata, split),
    }


def stratified_tiny(rows: list[dict[str, Any]], size: int, seed: int = 42) -> list[dict[str, Any]]:
    """Create a small deterministic stratified sample by IDS label/task."""

    rng = random.Random(seed)
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        meta = row["metadata"]
        buckets[(meta.get("ids_label", ""), meta.get("task_type", ""))].append(row)
    selected: dict[str, dict[str, Any]] = {}
    for bucket_rows in buckets.values():
        rng.shuffle(bucket_rows)
        if bucket_rows and len(selected) < size:
            selected[bucket_rows[0]["metadata"]["example_id"]] = bucket_rows[0]
    remaining = [row for row in rows if row["metadata"]["example_id"] not in selected]
    rng.shuffle(remaining)
    for row in remaining:
        if len(selected) >= size:
            break
        selected[row["metadata"]["example_id"]] = row
    return list(selected.values())


def prepare(compact_context: bool = False) -> dict[str, Any]:
    """Prepare all SFT split files."""

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    splits = {
        "train": REVIEWED_DIR / "train_reviewed.jsonl",
        "validation": REVIEWED_DIR / "validation_reviewed.jsonl",
        "test": REVIEWED_DIR / "test_reviewed.jsonl",
    }
    converted: dict[str, list[dict[str, Any]]] = {}
    stats: dict[str, Any] = {"created_at": date.today().isoformat(), "splits": {}}
    for split, path in splits.items():
        records = load_jsonl(path)
        rows = [convert_record(record, split, compact_context=compact_context) for record in records]
        converted[split] = rows
        suffix = "_sft_compact.jsonl" if compact_context else "_sft.jsonl"
        write_jsonl(OUT_DIR / f"{split}{suffix}", rows)
        stats["splits"][split] = {
            "rows": len(rows),
            "ids_labels": dict(Counter(row["metadata"]["ids_label"] for row in rows)),
            "tasks": dict(Counter(row["metadata"]["task_type"] for row in rows)),
            "confidence_bands": dict(Counter(row["metadata"]["confidence_band"] for row in rows)),
            "avg_text_chars": round(sum(len(row["text"]) for row in rows) / max(1, len(rows)), 2),
        }
    if compact_context:
        stats_path = OUT_DIR / "dataset_stats_compact.json"
    else:
        tiny_train = stratified_tiny(converted["train"], 16)
        tiny_val = stratified_tiny(converted["validation"], 8)
        write_jsonl(OUT_DIR / "train_sft_tiny.jsonl", tiny_train)
        write_jsonl(OUT_DIR / "validation_sft_tiny.jsonl", tiny_val)
        stats["tiny"] = {"train_rows": len(tiny_train), "validation_rows": len(tiny_val)}
        stats_path = OUT_DIR / "dataset_stats.json"
    stats["compact_context"] = compact_context
    stats_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    write_report(stats)
    return stats


def write_report(stats: dict[str, Any]) -> None:
    """Write preparation Markdown report."""

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# TrustSecAI SFT Dataset Preparation Report",
        "",
        "Prepared from strict reviewed gold v1 split files only.",
        "",
    ]
    for split, values in stats["splits"].items():
        lines.extend(
            [
                f"## {split}",
                "",
                f"- Rows: {values['rows']}",
                f"- IDS labels: {values['ids_labels']}",
                f"- Tasks: {values['tasks']}",
                f"- Confidence bands: {values['confidence_bands']}",
                f"- Average text chars: {values['avg_text_chars']}",
                "",
            ]
        )
    lines.extend(
        ["", f"Compact context mode: {stats.get('compact_context', False)}"]
    )
    if "tiny" in stats:
        lines.extend(
            [
                "",
                "## Tiny Dry-Run Files",
                "",
                f"- Train tiny rows: {stats['tiny']['train_rows']}",
                f"- Validation tiny rows: {stats['tiny']['validation_rows']}",
            ]
        )
    else:
        lines.extend(["", "Compact mode writes compact train/validation/test files only; existing tiny files are unchanged."])
    lines.append("")
    lines.append("Reviewer notes and checklist fields are not included in training text.")
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    """CLI entrypoint."""

    parser = argparse.ArgumentParser(description="Prepare TrustSecAI reviewed SFT datasets.")
    parser.add_argument("--compact-context", action="store_true", help="Write compact SFT files without verbose graph payloads.")
    args = parser.parse_args()
    stats = prepare(compact_context=args.compact_context)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
