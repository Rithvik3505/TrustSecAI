"""Create deterministic manual-review samples from the TrustSecAI pilot corpus."""

from __future__ import annotations

import json
import random
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence, Set


SEED = 42
INPUT_PATH = Path("artifacts/corpus/pilot_dataset_pretty.json")
OUTPUT_DIR = Path("artifacts/review_samples")
REPORT_PATH = Path("reports/review_summary.md")


def load_corpus(path: Path = INPUT_PATH) -> List[Dict[str, Any]]:
    """Load the pretty pilot corpus without modifying it."""

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Pilot corpus must be a JSON list.")
    return data


def example_id(record: Mapping[str, Any]) -> str:
    """Return a stable example ID."""

    return str(record.get("metadata", {}).get("example_id", ""))


def graph_context(record: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return graph context from a corpus record."""

    return record.get("input", {}).get("graph_context", {})


def graph_entity_counts(record: Mapping[str, Any]) -> Dict[str, int]:
    """Count available graph entity groups for a compact review header."""

    context = graph_context(record)
    attack = context.get("attack", {}) if isinstance(context, dict) else {}
    return {
        "technique": 1 if attack.get("technique") else 0,
        "tactics": len(attack.get("tactics", []) or []),
        "mitigations": len(attack.get("mitigations", []) or []),
        "capec": len(context.get("capec", []) or []),
        "cwes": len(context.get("cwes", []) or []),
        "cves": len(context.get("cves", []) or []),
        "products": len(context.get("products", []) or []),
        "references": len(context.get("references", []) or []),
        "groups": len(context.get("groups", []) or []),
        "tools": len(context.get("tools", []) or []),
        "malware": len(context.get("malware", []) or []),
        "detection_guidance": len(context.get("detection_guidance", []) or []),
    }


def has_shap(record: Mapping[str, Any]) -> bool:
    """Return whether SHAP top features are present."""

    return bool(record.get("input", {}).get("shap", {}).get("top_features"))


def review_header(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Build a compact human-review header for one example."""

    metadata = record.get("metadata", {})
    ids = record.get("input", {}).get("ids", {})
    counts = graph_entity_counts(record)
    variant = metadata.get("variant")
    return {
        "example_id": metadata.get("example_id"),
        "ids_label": ids.get("prediction"),
        "difficulty": metadata.get("difficulty"),
        "variant": variant,
        "task": metadata.get("task_type"),
        "prediction": ids.get("prediction"),
        "confidence": ids.get("confidence"),
        "graph_entities_available": counts,
        "has_shap": has_shap(record),
        "has_cves": counts["cves"] > 0,
        "has_capec": counts["capec"] > 0,
        "has_mitigations": counts["mitigations"] > 0,
        "multi_turn": variant == "multi_turn",
        "negative_example": variant == "negative",
        "agreement_example": variant == "agreement",
    }


def wrap_for_review(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Attach a compact review header while preserving the original example."""

    return {
        "review_header": review_header(record),
        "example": record,
    }


def deterministic_sample(
    records: Sequence[Dict[str, Any]],
    count: int,
    rng: random.Random,
    used_ids: Set[str],
    avoid_duplicates: bool = True,
) -> List[Dict[str, Any]]:
    """Sample records deterministically, avoiding previously used IDs when possible."""

    shuffled = list(records)
    rng.shuffle(shuffled)
    selected: List[Dict[str, Any]] = []
    if avoid_duplicates:
        for record in shuffled:
            if example_id(record) in used_ids:
                continue
            selected.append(record)
            used_ids.add(example_id(record))
            if len(selected) == count:
                return selected
    for record in shuffled:
        if record in selected:
            continue
        selected.append(record)
        used_ids.add(example_id(record))
        if len(selected) == count:
            break
    return selected


def filter_records(
    records: Iterable[Dict[str, Any]], predicate: Callable[[Dict[str, Any]], bool]
) -> List[Dict[str, Any]]:
    """Return records matching a predicate."""

    return [record for record in records if predicate(record)]


def write_sample(name: str, records: Sequence[Dict[str, Any]]) -> None:
    """Write one review sample file."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / f"{name}.json"
    payload = [wrap_for_review(record) for record in records]
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def malformed_indexes(records: Sequence[Mapping[str, Any]]) -> List[int]:
    """Detect malformed corpus records for review reporting."""

    malformed: List[int] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            malformed.append(index)
            continue
        if not all(key in record for key in ("instruction", "input", "output", "metadata")):
            malformed.append(index)
            continue
        if not record.get("metadata", {}).get("example_id"):
            malformed.append(index)
    return malformed


def distribution(records: Sequence[Mapping[str, Any]], key: str) -> Dict[str, int]:
    """Compute metadata distribution for a field."""

    return dict(sorted(Counter(str(record.get("metadata", {}).get(key)) for record in records).items()))


def duplicate_ids(records: Sequence[Mapping[str, Any]]) -> List[str]:
    """Return duplicate example IDs in the full corpus."""

    counts = Counter(example_id(record) for record in records)
    return sorted(example_id for example_id, count in counts.items() if count > 1)


def write_summary(
    corpus: Sequence[Dict[str, Any]], sample_sets: Mapping[str, Sequence[Dict[str, Any]]]
) -> None:
    """Write the review summary report."""

    sampled_ids = [example_id(record) for records in sample_sets.values() for record in records]
    duplicate_sampled = sorted(
        example_id for example_id, count in Counter(sampled_ids).items() if count > 1
    )
    malformed = malformed_indexes(corpus)
    unique_sampled = len(set(sampled_ids))
    total_sampled = len(sampled_ids)

    lines = [
        "# TrustSecAI Corpus Review Summary",
        "",
        "## Summary",
        "",
        f"- Input corpus: `{INPUT_PATH.as_posix()}`",
        f"- Total corpus size: {len(corpus)}",
        f"- Sample files generated: {len(sample_sets)}",
        f"- Sampled examples across files: {total_sampled}",
        f"- Unique sampled example IDs: {unique_sampled}",
        f"- Duplicate IDs in full corpus: {len(duplicate_ids(corpus))}",
        f"- Duplicate IDs across review files: {len(duplicate_sampled)}",
        f"- Malformed examples detected: {len(malformed)}",
        f"- Random seed: {SEED}",
        "",
        "## Difficulty Distribution",
        "",
        "| Difficulty | Count |",
        "|---|---:|",
    ]
    lines.extend(f"| {key} | {value} |" for key, value in distribution(corpus, "difficulty").items())
    lines.extend(["", "## Variant Distribution", "", "| Variant | Count |", "|---|---:|"])
    lines.extend(f"| {key} | {value} |" for key, value in distribution(corpus, "variant").items())
    lines.extend(["", "## Task Distribution", "", "| Task | Count |", "|---|---:|"])
    lines.extend(f"| {key} | {value} |" for key, value in distribution(corpus, "task_type").items())
    lines.extend(["", "## Review Files", "", "| File | Examples |", "|---|---:|"])
    lines.extend(f"| `{name}.json` | {len(records)} |" for name, records in sample_sets.items())
    lines.extend(["", "## Duplicate IDs Detected", ""])
    if duplicate_ids(corpus):
        lines.extend(f"- `{item}`" for item in duplicate_ids(corpus))
    else:
        lines.append("- None in full corpus.")
    if duplicate_sampled:
        lines.append("")
        lines.append("Duplicate IDs across review files were unavoidable for these categories:")
        lines.extend(f"- `{item}`" for item in duplicate_sampled)
    lines.extend(["", "## Malformed Examples", ""])
    if malformed:
        lines.extend(f"- index `{index}`" for index in malformed)
    else:
        lines.append("- None detected.")

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_samples(corpus: Sequence[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Build all deterministic review sample sets."""

    rng = random.Random(SEED)
    used_ids: Set[str] = set()
    sample_sets: Dict[str, List[Dict[str, Any]]] = {}

    sample_sets["overall_random"] = deterministic_sample(corpus, 20, rng, used_ids)

    difficulty_specs = {
        "easy": "easy",
        "medium": "medium",
        "hard": "hard",
        "expert": "expert",
    }
    for file_name, difficulty in difficulty_specs.items():
        candidates = filter_records(
            corpus, lambda record, value=difficulty: record.get("metadata", {}).get("difficulty") == value
        )
        sample_sets[file_name] = deterministic_sample(candidates, 5, rng, used_ids)

    variant_specs = {
        "negative": "negative",
        "agreement": "agreement",
        "multi_turn": "multi_turn",
    }
    for file_name, variant in variant_specs.items():
        candidates = filter_records(
            corpus, lambda record, value=variant: record.get("metadata", {}).get("variant") == value
        )
        sample_sets[file_name] = deterministic_sample(candidates, 5, rng, used_ids)

    task_specs = {
        "executive_summary": "executive_summary",
        "incident_report": "incident_report_generation",
    }
    for file_name, task in task_specs.items():
        candidates = filter_records(
            corpus, lambda record, value=task: record.get("metadata", {}).get("task_type") == value
        )
        sample_sets[file_name] = deterministic_sample(candidates, 5, rng, used_ids)

    return sample_sets


def run() -> Dict[str, Any]:
    """Create review samples and summary report."""

    corpus = load_corpus()
    sample_sets = build_samples(corpus)
    for name, records in sample_sets.items():
        write_sample(name, records)
    write_summary(corpus, sample_sets)
    return {
        "corpus_size": len(corpus),
        "sample_files": len(sample_sets),
        "sampled_examples": sum(len(records) for records in sample_sets.values()),
        "output_dir": OUTPUT_DIR.as_posix(),
        "report": REPORT_PATH.as_posix(),
    }


def main() -> None:
    """CLI entry point."""

    print(json.dumps(run(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

