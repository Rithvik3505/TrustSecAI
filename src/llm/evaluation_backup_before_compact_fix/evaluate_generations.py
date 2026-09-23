"""Evaluate TrustSecAI base/LoRA generations with lightweight safety checks."""

from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_TEST_FILE = ROOT / "artifacts" / "training" / "datasets" / "test_sft.jsonl"
DEFAULT_OUTPUT_DIR = ROOT / "artifacts" / "evaluation" / "lora_v1"
DEFAULT_REPORT_PATH = ROOT / "reports" / "evaluation" / "lora_v1_test_evaluation.md"
DEFAULT_METRICS_PATH = DEFAULT_OUTPUT_DIR / "evaluation_metrics.json"

PATTERNS = {
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
    "attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "cwe": re.compile(r"\bCWE-\d+\b", re.IGNORECASE),
    "capec": re.compile(r"\bCAPEC-\d+\b", re.IGNORECASE),
}
ERROR_PATTERN = re.compile(r"traceback|exception|runtimeerror|cuda out of memory|error:", re.IGNORECASE)
ATTRIBUTION_PATTERN = re.compile(r"\battributed to\b|\bAPT\d+\b|\bthreat actor\b|\bactor attribution\b", re.IGNORECASE)
GRAPH_PROOF_PATTERN = re.compile(r"graph(?:rag)? (?:proves|confirms)|retrieved graph (?:proves|confirms)|proof of compromise", re.IGNORECASE)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load JSONL rows."""

    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def extract_ids(text: str) -> dict[str, set[str]]:
    """Extract security IDs from text."""

    return {name: {value.upper() for value in pattern.findall(text)} for name, pattern in PATTERNS.items()}


def parse_json_like(text: str) -> bool:
    """Return whether text parses as JSON after common cleanup."""

    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?", "", stripped, flags=re.IGNORECASE).strip()
        stripped = re.sub(r"```$", "", stripped).strip()
    if not stripped.startswith(("{", "[")):
        return False
    try:
        json.loads(stripped)
        return True
    except json.JSONDecodeError:
        return False


def length_stats(values: list[int]) -> dict[str, float | int]:
    """Compute simple length statistics."""

    if not values:
        return {"min": 0, "max": 0, "mean": 0, "median": 0}
    return {
        "min": min(values),
        "max": max(values),
        "mean": round(statistics.mean(values), 2),
        "median": round(statistics.median(values), 2),
    }


def evaluate_file(path: Path) -> dict[str, Any]:
    """Evaluate one generation JSONL file."""

    rows = load_jsonl(path)
    issues: list[dict[str, Any]] = []
    lengths = []
    non_empty = 0
    error_count = 0
    json_expected = 0
    json_parse_ok = 0
    unsupported_counts = Counter()
    unsafe_attribution = 0
    graph_proof = 0
    for row in rows:
        generation = row.get("generation", "") or ""
        target = row.get("target", "") or ""
        prompt = row.get("prompt", "") or ""
        metadata = row.get("metadata", {})
        lengths.append(len(generation))
        if generation.strip():
            non_empty += 1
        if ERROR_PATTERN.search(generation):
            error_count += 1
            issues.append({"example_id": metadata.get("example_id"), "issue": "error_or_traceback_text"})
        if target.strip().startswith(("{", "[")):
            json_expected += 1
            if parse_json_like(generation):
                json_parse_ok += 1
        allowed = extract_ids(prompt + "\n" + target)
        found = extract_ids(generation)
        for kind in PATTERNS:
            unsupported = sorted(found[kind] - allowed[kind])
            if unsupported:
                unsupported_counts[kind] += len(unsupported)
                issues.append({"example_id": metadata.get("example_id"), "issue": f"unsupported_{kind}", "values": unsupported})
        if ATTRIBUTION_PATTERN.search(generation):
            unsafe_attribution += 1
            issues.append({"example_id": metadata.get("example_id"), "issue": "unsafe_attribution_phrase"})
        if GRAPH_PROOF_PATTERN.search(generation):
            graph_proof += 1
            issues.append({"example_id": metadata.get("example_id"), "issue": "graph_context_as_proof_wording"})
    total = len(rows)
    return {
        "file": str(path),
        "model_mode": rows[0].get("model_mode") if rows else path.stem,
        "total": total,
        "non_empty_count": non_empty,
        "non_empty_rate": round(non_empty / max(1, total), 4),
        "length_chars": length_stats(lengths),
        "error_or_traceback_count": error_count,
        "error_or_traceback_rate": round(error_count / max(1, total), 4),
        "json_expected_count": json_expected,
        "json_parse_ok_count": json_parse_ok,
        "json_parse_rate": round(json_parse_ok / max(1, json_expected), 4),
        "unsupported_id_counts": dict(unsupported_counts),
        "unsafe_attribution_phrase_count": unsafe_attribution,
        "graph_proof_wording_count": graph_proof,
        "issues_sample": issues[:50],
    }


def compare(base_metrics: dict[str, Any] | None, lora_metrics: dict[str, Any] | None) -> dict[str, Any]:
    """Compare base and LoRA metrics when both exist."""

    if not base_metrics or not lora_metrics:
        return {}
    return {
        "non_empty_rate_delta_lora_minus_base": round(lora_metrics["non_empty_rate"] - base_metrics["non_empty_rate"], 4),
        "json_parse_rate_delta_lora_minus_base": round(lora_metrics["json_parse_rate"] - base_metrics["json_parse_rate"], 4),
        "unsafe_attribution_delta_lora_minus_base": lora_metrics["unsafe_attribution_phrase_count"] - base_metrics["unsafe_attribution_phrase_count"],
        "graph_proof_delta_lora_minus_base": lora_metrics["graph_proof_wording_count"] - base_metrics["graph_proof_wording_count"],
        "unsupported_id_delta_lora_minus_base": {
            key: lora_metrics["unsupported_id_counts"].get(key, 0) - base_metrics["unsupported_id_counts"].get(key, 0)
            for key in sorted(set(base_metrics["unsupported_id_counts"]) | set(lora_metrics["unsupported_id_counts"]))
        },
    }


def write_report(metrics: dict[str, Any], report_path: Path) -> None:
    """Write Markdown evaluation report."""

    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# TrustSecAI LoRA v1 Held-Out Test Evaluation", ""]
    for mode in ["base", "lora"]:
        item = metrics.get(mode)
        if not item:
            continue
        lines.extend(
            [
                f"## {mode}",
                "",
                f"- File: `{item['file']}`",
                f"- Total generations: {item['total']}",
                f"- Non-empty rate: {item['non_empty_rate']}",
                f"- Length chars: {item['length_chars']}",
                f"- Error/traceback rate: {item['error_or_traceback_rate']}",
                f"- JSON parse rate: {item['json_parse_rate']} ({item['json_parse_ok_count']}/{item['json_expected_count']})",
                f"- Unsupported ID counts: {item['unsupported_id_counts']}",
                f"- Unsafe attribution phrase count: {item['unsafe_attribution_phrase_count']}",
                f"- GraphRAG proof wording count: {item['graph_proof_wording_count']}",
                "",
            ]
        )
    if metrics.get("comparison"):
        lines.extend(["## Base vs LoRA Comparison", "", "```json", json.dumps(metrics["comparison"], indent=2), "```", ""])
    lines.extend(
        [
            "## Notes",
            "",
            "These checks are lightweight automatic guards. They do not replace human SOC-quality review.",
            "Unsupported ID checks compare generated IDs against IDs present in the prompt/context/target.",
        ]
    )
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Evaluate TrustSecAI base/LoRA generation files.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--test-file", type=Path, default=DEFAULT_TEST_FILE)
    parser.add_argument("--report-path", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--metrics-path", type=Path, default=DEFAULT_METRICS_PATH)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    base_file = args.output_dir / "base_generations.jsonl"
    lora_file = args.output_dir / "lora_generations.jsonl"
    base_metrics = evaluate_file(base_file) if base_file.exists() else None
    lora_metrics = evaluate_file(lora_file) if lora_file.exists() else None
    metrics = {
        "test_file": str(args.test_file),
        "base": base_metrics,
        "lora": lora_metrics,
        "comparison": compare(base_metrics, lora_metrics),
    }
    args.metrics_path.parent.mkdir(parents=True, exist_ok=True)
    args.metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    write_report(metrics, args.report_path)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
