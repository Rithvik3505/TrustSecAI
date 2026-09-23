"""Dataset diversity analysis for TrustSecAI SFT corpora."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List, Mapping

from .quality_checks import flatten_text


WORD_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9_-]*\b")
SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")


def words(text: str) -> List[str]:
    """Tokenize text for rough diversity metrics."""

    return [token.lower() for token in WORD_RE.findall(text)]


def sentences(text: str) -> List[str]:
    """Split text into approximate sentences."""

    parts = []
    for raw in SENTENCE_RE.split(text.replace("\n", " ")):
        item = " ".join(raw.split())
        if item:
            parts.append(item)
    return parts


def ngrams(tokens: List[str], n: int) -> Iterable[str]:
    """Yield n-grams."""

    for index in range(0, max(0, len(tokens) - n + 1)):
        yield " ".join(tokens[index : index + n])


def output_text(record: Mapping[str, Any]) -> str:
    """Flatten output text."""

    return flatten_text(record.get("output", {}))


SKIP_NATURAL_KEYS = {
    "id",
    "cve_id",
    "attack_id",
    "technique_id",
    "technique_name",
    "relationship_type",
    "source",
    "target_node",
    "origin_node",
    "provenance",
    "attack_mapping",
    "mapped_technique",
    "mapped_mitigations",
    "references",
}


def natural_text(value: Any, parent_key: str = "") -> str:
    """Flatten generated analyst language while skipping structured IDs/provenance."""

    if parent_key in SKIP_NATURAL_KEYS:
        return ""
    if isinstance(value, dict):
        return " ".join(natural_text(v, str(k)) for k, v in value.items())
    if isinstance(value, list):
        return " ".join(natural_text(item, parent_key) for item in value)
    if isinstance(value, str):
        return value
    return ""


def source_ids(record: Mapping[str, Any], key: str) -> List[str]:
    """Return source IDs from metadata."""

    value = record.get("metadata", {}).get("source_ids", {}).get(key, [])
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if value:
        return [str(value)]
    return []


def count_reasoning_depth(record: Mapping[str, Any]) -> int:
    """Estimate reasoning depth from structured output."""

    output = record.get("output", {})
    if isinstance(output, dict):
        if isinstance(output.get("analyst_reasoning_flow"), list):
            return len(output["analyst_reasoning_flow"])
        if isinstance(output.get("reasoning"), list):
            return len(output["reasoning"])
        if isinstance(output.get("messages"), list):
            return len(output["messages"])
    text = output_text(record).lower()
    return sum(1 for marker in ("observation", "evidence", "reasoning", "conclusion", "limitation") if marker in text)


def mitigation_mentions(record: Mapping[str, Any]) -> List[str]:
    """Collect mitigation IDs mentioned in metadata and output."""

    ids = source_ids(record, "mitigations")
    text = output_text(record)
    ids.extend(re.findall(r"\bM\d{4}\b", text))
    return sorted(set(ids))


def text_diversity_metrics(texts: List[str]) -> Dict[str, Any]:
    """Compute reusable diversity metrics for a list of text blobs."""

    token_rows = [words(text) for text in texts]
    all_tokens = [token for row in token_rows for token in row]
    sentence_rows = [sentence for text in texts for sentence in sentences(text)]
    paragraph_rows = [" ".join(text.split()) for text in texts if text.strip()]
    sentence_counts = Counter(sentence_rows)
    paragraph_counts = Counter(paragraph_rows)
    openings = Counter()
    closings = Counter()
    for text in texts:
        sents = sentences(text)
        if sents:
            openings[sents[0][:140]] += 1
            closings[sents[-1][:140]] += 1
    per_record_ttr = [
        len(set(row)) / max(1, len(row)) for row in token_rows if row
    ]
    repeated_sentence_types = sum(1 for count in sentence_counts.values() if count > 1)
    repeated_paragraph_types = sum(1 for count in paragraph_counts.values() if count > 1)
    return {
        "vocabulary_diversity": round(mean(per_record_ttr), 4) if per_record_ttr else 0,
        "unique_word_count": len(set(all_tokens)),
        "total_word_count": len(all_tokens),
        "average_length_words": round(mean([len(row) for row in token_rows]), 2)
        if token_rows
        else 0,
        "unique_sentence_ratio": round(len(sentence_counts) / max(1, len(sentence_rows)), 4),
        "repeated_exact_sentence_percent": round(
            (repeated_sentence_types / max(1, len(sentence_counts))) * 100, 2
        ),
        "repeated_paragraph_percent": round(
            (repeated_paragraph_types / max(1, len(paragraph_counts))) * 100, 2
        ),
        "repeated_opening_percent": round(
            (sum(1 for count in openings.values() if count > 1) / max(1, len(openings))) * 100,
            2,
        ),
        "repeated_closing_percent": round(
            (sum(1 for count in closings.values() if count > 1) / max(1, len(closings))) * 100,
            2,
        ),
        "top_repeated_phrases": dict(Counter(ngrams(all_tokens, 4)).most_common(20)),
        "most_common_openings": dict(openings.most_common(15)),
        "most_common_closings": dict(closings.most_common(15)),
    }


def analyze_diversity(records: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    """Compute diversity and coverage metrics."""

    rows = list(records)
    outputs = [natural_text(record.get("output", {})) for record in rows]
    full_record_texts = [flatten_text(record) for record in rows]
    target_metrics = text_diversity_metrics(outputs)
    full_record_metrics = text_diversity_metrics(full_record_texts)
    all_words = [token for text in outputs for token in words(text)]
    sentence_rows = [sentence for text in outputs for sentence in sentences(text)]
    paragraph_rows = [" ".join(text.split()) for text in outputs if text.strip()]
    sentence_counts = Counter(sentence_rows)
    paragraph_counts = Counter(paragraph_rows)
    task_distribution = Counter(str(r.get("metadata", {}).get("task_type")) for r in rows)
    technique_distribution = Counter(
        item for record in rows for item in source_ids(record, "technique")
    )
    capec_coverage = Counter(item for record in rows for item in source_ids(record, "capec"))
    cwe_coverage = Counter(item for record in rows for item in source_ids(record, "cwes"))
    cve_coverage = Counter(item for record in rows for item in source_ids(record, "cves"))
    mitigation_distribution = Counter(item for record in rows for item in mitigation_mentions(record))
    attack_ids = Counter()
    for record in rows:
        for key in ("technique", "tactics"):
            attack_ids.update(source_ids(record, key))

    provenance_counts = [
        len(record.get("input", {}).get("graph_context", {}).get("provenance", []) or [])
        for record in rows
    ]
    shap_counts = [
        len(record.get("input", {}).get("shap", {}).get("top_features", []) or [])
        for record in rows
    ]
    reasoning_depths = [count_reasoning_depth(record) for record in rows]
    response_lengths = [len(words(text)) for text in outputs]
    openings = Counter()
    closings = Counter()
    for text in outputs:
        sents = sentences(text)
        if sents:
            openings[sents[0][:140]] += 1
            closings[sents[-1][:140]] += 1
    repeated_sentence_types = sum(1 for count in sentence_counts.values() if count > 1)
    repeated_paragraph_types = sum(1 for count in paragraph_counts.values() if count > 1)
    repeated_mitigations = sum(count for count in mitigation_distribution.values() if count > 1)
    reasoning_phrases = Counter()
    for text in outputs:
        lowered = text.lower()
        for marker in (
            "graphrag context supports",
            "not proof of compromise",
            "candidate context",
            "analyst review",
            "corroborating telemetry",
            "asset exposure",
            "graph retrieval links",
        ):
            if marker in lowered:
                reasoning_phrases[marker] += 1
    repeated_reasoning_dominance = (
        max(reasoning_phrases.values()) / max(1, sum(reasoning_phrases.values()))
        if reasoning_phrases
        else 0
    )
    phrase_counts = Counter(ngrams(all_words, 4))

    vocabulary_diversity = target_metrics["vocabulary_diversity"]
    repeated_sentence_pct = round(
        (repeated_sentence_types / max(1, len(sentence_counts))) * 100, 2
    )
    repeated_paragraph_pct = round(
        (repeated_paragraph_types / max(1, len(paragraph_counts))) * 100, 2
    )
    repeated_mitigation_pct = round(
        (repeated_mitigations / max(1, sum(mitigation_distribution.values()))) * 100, 2
    )
    repeated_reasoning_pct = round(repeated_reasoning_dominance * 100, 2)
    flags = []
    if repeated_sentence_pct > 99.5:
        flags.append("Repeated sentence percentage is high.")
    if repeated_paragraph_pct > 15:
        flags.append("Repeated paragraph percentage is high.")
    if repeated_reasoning_pct > 45:
        flags.append("Repeated reasoning phrase percentage is high.")
    if vocabulary_diversity < 0.25:
        flags.append("Vocabulary diversity is low for this corpus size.")

    return {
        "example_count": len(rows),
        "vocabulary_diversity": vocabulary_diversity,
        "full_record_diversity": full_record_metrics,
        "target_output_diversity": target_metrics,
        "unique_word_count": len(set(all_words)),
        "total_word_count": len(all_words),
        "average_response_length": round(mean(response_lengths), 2) if response_lengths else 0,
        "repeated_sentence_percent": repeated_sentence_pct,
        "repeated_paragraph_percent": repeated_paragraph_pct,
        "repeated_mitigation_percent": repeated_mitigation_pct,
        "repeated_reasoning_percent": repeated_reasoning_pct,
        "task_distribution": dict(sorted(task_distribution.items())),
        "technique_distribution": dict(sorted(technique_distribution.items())),
        "mitigation_distribution": dict(mitigation_distribution.most_common(20)),
        "attack_coverage": dict(sorted(attack_ids.items())),
        "capec_coverage": dict(sorted(capec_coverage.items())),
        "cwe_coverage": dict(sorted(cwe_coverage.items())),
        "cve_coverage": dict(sorted(cve_coverage.items())),
        "average_provenance_references": round(mean(provenance_counts), 2) if provenance_counts else 0,
        "average_reasoning_depth": round(mean(reasoning_depths), 2) if reasoning_depths else 0,
        "average_shap_features_referenced": round(mean(shap_counts), 2) if shap_counts else 0,
        "top_repeated_phrases": dict(phrase_counts.most_common(20)),
        "most_common_openings": dict(openings.most_common(15)),
        "most_common_closings": dict(closings.most_common(15)),
        "task_wise_diversity": {
            task: text_diversity_metrics(
                [outputs[index] for index, record in enumerate(rows) if str(record.get("metadata", {}).get("task_type")) == task]
            )
            for task in sorted(task_distribution)
        },
        "persona_wise_diversity": {
            str(bucket): text_diversity_metrics(
                [
                    outputs[index]
                    for index, record in enumerate(rows)
                    if str((int(str(record.get("metadata", {}).get("example_id", "0")).rsplit("-", 1)[-1]) % 8)) == str(bucket)
                ]
            )
            for bucket in range(8)
        },
        "ids_label_wise_diversity": {
            label: text_diversity_metrics(
                [outputs[index] for index, record in enumerate(rows) if str(record.get("input", {}).get("ids", {}).get("prediction")) == label]
            )
            for label in sorted(set(str(record.get("input", {}).get("ids", {}).get("prediction")) for record in rows))
        },
        "agreement_output_diversity": text_diversity_metrics(
            [outputs[index] for index, record in enumerate(rows) if record.get("metadata", {}).get("variant") == "agreement"]
        ),
        "negative_example_diversity": text_diversity_metrics(
            [outputs[index] for index, record in enumerate(rows) if record.get("metadata", {}).get("variant") == "negative"]
        ),
        "multi_turn_response_diversity": text_diversity_metrics(
            [outputs[index] for index, record in enumerate(rows) if record.get("metadata", {}).get("variant") == "multi_turn"]
        ),
        "flags": flags,
    }


def write_diversity_report(metrics: Mapping[str, Any], path: Path) -> None:
    """Write a human-readable diversity report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# TrustSecAI Dataset Diversity Report",
        "",
        "## Summary",
        "",
        f"- Examples: {metrics['example_count']}",
        f"- Primary metric scope: target output text only",
        f"- Target-output vocabulary diversity: {metrics['target_output_diversity']['vocabulary_diversity']}",
        f"- Target-output unique sentence ratio: {metrics['target_output_diversity']['unique_sentence_ratio']}",
        f"- Target-output repeated exact sentence %: {metrics['target_output_diversity']['repeated_exact_sentence_percent']}",
        f"- Target-output repeated paragraph %: {metrics['target_output_diversity']['repeated_paragraph_percent']}",
        f"- Target-output repeated opening %: {metrics['target_output_diversity']['repeated_opening_percent']}",
        f"- Target-output repeated closing %: {metrics['target_output_diversity']['repeated_closing_percent']}",
        f"- Full-record vocabulary diversity: {metrics['full_record_diversity']['vocabulary_diversity']}",
        f"- Full-record repeated exact sentence %: {metrics['full_record_diversity']['repeated_exact_sentence_percent']}",
        f"- Repeated mitigation %: {metrics['repeated_mitigation_percent']}",
        f"- Repeated reasoning %: {metrics['repeated_reasoning_percent']}",
        f"- Average provenance references: {metrics['average_provenance_references']}",
        f"- Average reasoning depth: {metrics['average_reasoning_depth']}",
        f"- Average SHAP features referenced: {metrics['average_shap_features_referenced']}",
        "",
        "## Flags",
        "",
    ]
    lines.extend(f"- {flag}" for flag in metrics["flags"]) if metrics["flags"] else lines.append("- None.")
    for title, key in (
        ("Task Distribution", "task_distribution"),
        ("Technique Distribution", "technique_distribution"),
        ("Mitigation Distribution", "mitigation_distribution"),
        ("ATT&CK Coverage", "attack_coverage"),
        ("CAPEC Coverage", "capec_coverage"),
        ("CWE Coverage", "cwe_coverage"),
        ("CVE Coverage", "cve_coverage"),
        ("Top Repeated Phrases", "top_repeated_phrases"),
        ("Most Common Openings", "most_common_openings"),
        ("Most Common Closings", "most_common_closings"),
    ):
        lines.extend(["", f"## {title}", "", "| Item | Count |", "|---|---:|"])
        values = metrics[key]
        if values:
            lines.extend(f"| `{item}` | {count} |" for item, count in values.items())
        else:
            lines.append("| None | 0 |")
    lines.extend(["", "## Target-Output Diversity By Variant", ""])
    for title, key in (
        ("Agreement Output Diversity", "agreement_output_diversity"),
        ("Negative Example Diversity", "negative_example_diversity"),
        ("Multi-Turn Response Diversity", "multi_turn_response_diversity"),
    ):
        value = metrics[key]
        lines.extend(
            [
                f"### {title}",
                "",
                f"- Vocabulary diversity: {value['vocabulary_diversity']}",
                f"- Unique sentence ratio: {value['unique_sentence_ratio']}",
                f"- Repeated exact sentence %: {value['repeated_exact_sentence_percent']}",
                "",
            ]
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_diversity_json(metrics: Mapping[str, Any], path: Path) -> None:
    """Write diversity metrics as JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metrics, indent=2, sort_keys=True), encoding="utf-8")
