"""Audit tokenizer lengths for TrustSecAI SFT datasets."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - local fallback handles training_config.yaml
    yaml = None


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG = ROOT / "src" / "llm" / "training" / "training_config.yaml"
REPORT_PATH = ROOT / "reports" / "training" / "token_length_audit_report.md"
JSON_PATH = ROOT / "artifacts" / "training" / "logs" / "token_length_audit.json"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load JSONL rows."""

    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def percentile(values: list[int], pct: float) -> int:
    """Return nearest-rank percentile."""

    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((pct / 100) * (len(ordered) - 1))))
    return int(ordered[index])


def stats(lengths: list[int], max_seq_length: int) -> dict[str, Any]:
    """Compute length stats."""

    above = [value for value in lengths if value > max_seq_length]
    return {
        "count": len(lengths),
        "min_tokens": min(lengths) if lengths else 0,
        "max_tokens": max(lengths) if lengths else 0,
        "mean_tokens": round(statistics.mean(lengths), 2) if lengths else 0,
        "median_tokens": int(statistics.median(lengths)) if lengths else 0,
        "p90": percentile(lengths, 90),
        "p95": percentile(lengths, 95),
        "p99": percentile(lengths, 99),
        "above_max_seq_length": len(above),
        "above_max_seq_length_pct": round(len(above) / max(1, len(lengths)) * 100, 3),
    }


def load_tokenizer(model_name: str, trust_remote_code: bool):
    """Load tokenizer only, failing clearly on missing deps/auth."""

    try:
        from transformers import AutoTokenizer
    except ImportError as exc:
        raise RuntimeError("transformers is not installed. Install the training dependencies before running token audit.") from exc
    try:
        return AutoTokenizer.from_pretrained(model_name, trust_remote_code=trust_remote_code)
    except Exception as exc:
        raise RuntimeError(
            "Tokenizer loading failed. If this is a gated Hugging Face model, run `huggingface-cli login` "
            "or set a secure HF token on the HPC. No audit was completed."
        ) from exc


def parse_scalar(value: str) -> Any:
    """Parse a small YAML scalar subset."""

    value = value.strip()
    if value in {"true", "false"}:
        return value == "true"
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def load_config(path: Path) -> dict[str, Any]:
    """Load YAML config, with a tiny fallback parser if PyYAML is absent."""

    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        return yaml.safe_load(text)
    config: dict[str, Any] = {}
    current_section: str | None = None
    current_list_key: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        if not raw.startswith(" ") and raw.endswith(":"):
            current_section = raw[:-1].strip()
            config[current_section] = {}
            current_list_key = None
            continue
        if current_section is None:
            continue
        stripped = raw.strip()
        if stripped.startswith("- ") and current_list_key:
            config[current_section][current_list_key].append(parse_scalar(stripped[2:]))
            continue
        if ":" in stripped:
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip()
            if value == "":
                config[current_section][key] = []
                current_list_key = key
            else:
                config[current_section][key] = parse_scalar(value)
                current_list_key = None
    return config


def audit(config_path: Path) -> dict[str, Any]:
    """Run tokenizer length audit."""

    config = load_config(config_path)
    model_name = config["model"]["base_model_name"]
    tokenizer = load_tokenizer(model_name, bool(config["model"].get("trust_remote_code", False)))
    text_field = config["data"]["text_field"]
    max_seq_length = int(config["data"]["max_seq_length"])
    split_files = {
        "train": ROOT / config["data"]["train_file"],
        "validation": ROOT / config["data"]["validation_file"],
        "test": ROOT / config["data"]["test_file"],
    }
    result: dict[str, Any] = {
        "model_name": model_name,
        "max_seq_length": max_seq_length,
        "splits": {},
    }
    all_long_rows: list[dict[str, Any]] = []
    for split, path in split_files.items():
        rows = load_jsonl(path)
        audited = []
        for row in rows:
            token_count = len(tokenizer(row[text_field], add_special_tokens=False)["input_ids"])
            metadata = row.get("metadata", {})
            item = {
                "split": split,
                "example_id": metadata.get("example_id"),
                "base_context_id": metadata.get("base_context_id"),
                "sample_id": metadata.get("sample_id"),
                "task_type": metadata.get("task_type"),
                "ids_label": metadata.get("ids_label"),
                "token_count": token_count,
            }
            audited.append(item)
            if token_count > max_seq_length:
                all_long_rows.append(item)
        lengths = [item["token_count"] for item in audited]
        longest = sorted(audited, key=lambda item: item["token_count"], reverse=True)[:20]
        long_rows = [item for item in audited if item["token_count"] > max_seq_length]
        result["splits"][split] = {
            **stats(lengths, max_seq_length),
            "longest_20": longest,
            "long_task_distribution": dict(Counter(item["task_type"] for item in long_rows)),
            "long_label_distribution": dict(Counter(item["ids_label"] for item in long_rows)),
        }
    result["overall_long_task_distribution"] = dict(Counter(item["task_type"] for item in all_long_rows))
    result["overall_long_label_distribution"] = dict(Counter(item["ids_label"] for item in all_long_rows))
    return result


def write_reports(result: dict[str, Any]) -> None:
    """Write JSON and Markdown audit reports."""

    JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    JSON_PATH.write_text(json.dumps(result, indent=2), encoding="utf-8")
    lines = [
        "# TrustSecAI Token Length Audit",
        "",
        f"- Tokenizer/model: `{result['model_name']}`",
        f"- Configured max_seq_length: `{result['max_seq_length']}`",
        "",
    ]
    for split, values in result["splits"].items():
        lines.extend(
            [
                f"## {split}",
                "",
                f"- Count: {values['count']}",
                f"- Min tokens: {values['min_tokens']}",
                f"- Max tokens: {values['max_tokens']}",
                f"- Mean tokens: {values['mean_tokens']}",
                f"- Median tokens: {values['median_tokens']}",
                f"- p90: {values['p90']}",
                f"- p95: {values['p95']}",
                f"- p99: {values['p99']}",
                f"- Above max_seq_length: {values['above_max_seq_length']} ({values['above_max_seq_length_pct']}%)",
                f"- Long task distribution: {values['long_task_distribution']}",
                f"- Long label distribution: {values['long_label_distribution']}",
                "",
                "### Longest 20",
                "",
            ]
        )
        for item in values["longest_20"]:
            lines.append(
                f"- {item['example_id']} | {item['token_count']} tokens | "
                f"{item['task_type']} | {item['ids_label']} | {item['split']}"
            )
        lines.append("")
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    """Parse CLI args."""

    parser = argparse.ArgumentParser(description="Audit token lengths for TrustSecAI SFT data.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    try:
        result = audit(args.config)
    except RuntimeError as exc:
        print(str(exc))
        return
    write_reports(result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
