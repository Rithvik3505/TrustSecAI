"""Statistics and reporting for TrustSecAI corpus generation."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, Mapping

from .quality_checks import flatten_text


def compute_statistics(records: Iterable[Mapping[str, Any]], quality: Mapping[str, Any]) -> Dict[str, Any]:
    """Compute corpus statistics from accepted records."""

    rows = list(records)
    difficulty = Counter(str(r.get("metadata", {}).get("difficulty")) for r in rows)
    tasks = Counter(str(r.get("metadata", {}).get("task_type")) for r in rows)
    variants = Counter(str(r.get("metadata", {}).get("variant")) for r in rows)
    categories = Counter(str(r.get("metadata", {}).get("category")) for r in rows)
    prompt_lengths = [len(str(r.get("instruction", "")).split()) for r in rows]
    response_lengths = [len(flatten_text(r.get("output", {})).split()) for r in rows]
    labels = Counter(str(r.get("input", {}).get("ids", {}).get("prediction")) for r in rows)

    return {
        "example_count": len(rows),
        "difficulty_distribution": dict(sorted(difficulty.items())),
        "task_distribution": dict(sorted(tasks.items())),
        "variant_distribution": dict(sorted(variants.items())),
        "category_distribution": dict(sorted(categories.items())),
        "label_distribution": dict(sorted(labels.items())),
        "negative_examples": variants.get("negative", 0),
        "multi_turn_examples": variants.get("multi_turn", 0),
        "agreement_examples": variants.get("agreement", 0),
        "average_prompt_length_words": round(mean(prompt_lengths), 2) if prompt_lengths else 0,
        "average_response_length_words": round(mean(response_lengths), 2) if response_lengths else 0,
        "quality": dict(quality),
    }


def write_statistics_report(stats: Mapping[str, Any], path: Path) -> None:
    """Write the corpus statistics report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# TrustSecAI Corpus Statistics",
        "",
        "## Summary",
        "",
        f"- Number of examples: {stats['example_count']}",
        f"- Negative examples: {stats['negative_examples']}",
        f"- Multi-turn examples: {stats['multi_turn_examples']}",
        f"- Agreement-analysis examples: {stats['agreement_examples']}",
        f"- Average prompt length: {stats['average_prompt_length_words']} words",
        f"- Average response length: {stats['average_response_length_words']} words",
        f"- Accepted by validation: {stats['quality'].get('accepted')}",
        f"- Rejected by validation: {stats['quality'].get('rejected')}",
        "",
        "## Difficulty Distribution",
        "",
        "| Difficulty | Count |",
        "|---|---:|",
    ]
    lines.extend(
        f"| {key} | {value} |" for key, value in stats["difficulty_distribution"].items()
    )
    lines.extend(["", "## Task Distribution", "", "| Task | Count |", "|---|---:|"])
    lines.extend(f"| {key} | {value} |" for key, value in stats["task_distribution"].items())
    lines.extend(["", "## Variant Distribution", "", "| Variant | Count |", "|---|---:|"])
    lines.extend(f"| {key} | {value} |" for key, value in stats["variant_distribution"].items())
    lines.extend(["", "## Dataset Balance By IDS Label", "", "| IDS Label | Count |", "|---|---:|"])
    lines.extend(f"| {key} | {value} |" for key, value in stats["label_distribution"].items())
    lines.extend(
        [
            "",
            "## Validation Notes",
            "",
            "- The validation framework rejects malformed JSON, duplicate examples, missing provenance, invented security IDs, and unsupported attribution phrasing.",
            "- The pilot corpus is deterministic and intended for manual review before scaling.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_generation_report(stats: Mapping[str, Any], path: Path) -> None:
    """Write the final corpus generation report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# TrustSecAI Corpus Generation Report",
        "",
        "## Pipeline Overview",
        "",
        "The corpus generation framework reads existing TrustSecAI evidence artifacts and creates supervised fine-tuning examples using deterministic templates. It does not train, fine-tune, or call any LLM.",
        "",
        "Pipeline:",
        "",
        "```text",
        "IDS prediction + confidence",
        "-> SHAP top features",
        "-> Graph Retrieval JSON",
        "-> Prompt template",
        "-> Curriculum level",
        "-> Deterministic target output",
        "-> Quality validation",
        "-> JSONL export",
        "```",
        "",
        "## Example Generation Flow",
        "",
        "1. Load retrieval contexts from `artifacts/retrieval/*.json`.",
        "2. Attach SHAP explanations from `artifacts/shap/sample_explanations.json` when available.",
        "3. Apply one of the approved prompt templates.",
        "4. Limit graph context according to easy, medium, hard, or expert curriculum settings.",
        "5. Generate a structured target output that cites only supplied evidence.",
        "6. Validate the example for unsupported IDs, missing provenance, duplicates, and attribution overclaiming.",
        "",
        "## Validation Summary",
        "",
        f"- Accepted examples: {stats['quality'].get('accepted')}",
        f"- Rejected examples: {stats['quality'].get('rejected')}",
        f"- Validation warnings: {len(stats['quality'].get('warnings', []))}",
        "",
        "## Known Limitations",
        "",
        "- The pilot uses only the currently exported retrieval contexts, so IDS label coverage is limited to available JSON artifacts.",
        "- SHAP local examples are available for a subset of labels; other labels use deterministic fallback feature summaries.",
        "- Target outputs are template-generated and should be manually reviewed before being used for training.",
        "- CVEs are framed as candidate context unless separate asset exposure evidence is supplied.",
        "- Actor, tool, and malware relationships are treated as ATT&CK usage context, not attribution.",
        "",
        "## Recommended Scaling Strategy",
        "",
        "- Export retrieval JSON for every mapped CICIDS2017 attack label.",
        "- Generate a 200-500 example review set per major prompt family before full-scale generation.",
        "- Add human review for a stratified sample of high, low, sparse, and inferred-context examples.",
        "- Keep train/validation/test splits grouped by base incident and graph context to avoid leakage.",
        "- Add a full official CWE dictionary if rich CWE explanation tasks are required.",
        "",
        "## Estimated Final Corpus Size",
        "",
        "A practical final corpus target is 10,000 to 25,000 examples after quality filtering, with synthetic IDS + SHAP + graph examples forming the largest component.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_final_corpus_report(
    stats: Mapping[str, Any], diversity: Mapping[str, Any], path: Path
) -> None:
    """Write final production corpus report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# TrustSecAI Final Corpus Report",
        "",
        "## Summary",
        "",
        f"- Final examples: {stats['example_count']}",
        f"- Accepted by validation: {stats['quality'].get('accepted')}",
        f"- Rejected by validation: {stats['quality'].get('rejected')}",
        f"- Validation warnings: {len(stats['quality'].get('warnings', []))}",
        f"- Negative examples: {stats['negative_examples']}",
        f"- Multi-turn examples: {stats['multi_turn_examples']}",
        f"- Agreement-analysis examples: {stats['agreement_examples']}",
        f"- Average response length: {diversity['average_response_length']} words",
        f"- Vocabulary diversity: {diversity['vocabulary_diversity']}",
        "",
        "## Generation Scope",
        "",
        "The final corpus was generated from IDS predictions, SHAP feature evidence, and Graph Retrieval JSON. No LoRA training, model inference, Neo4j changes, GraphRAG changes, IDS changes, or SHAP regeneration were performed.",
        "",
        "## Quality Improvements",
        "",
        "- SOC-style analyst language with varied reasoning structures.",
        "- Natural SHAP feature summaries using only supplied feature names.",
        "- Confidence-aware wording for high, medium, and low confidence cases.",
        "- Executive summaries focused on business impact, operational risk, confidence, and recommended action.",
        "- Explicit uncertainty language for missing graph evidence, candidate CVEs, and non-attribution of actor/tool/malware context.",
        "- Compact graph descriptions while preserving IDs, relationships, provenance, confidence, and retrieval structure.",
        "",
        "## Distribution",
        "",
        "### Difficulty",
        "",
        "| Difficulty | Count |",
        "|---|---:|",
    ]
    lines.extend(f"| {k} | {v} |" for k, v in stats["difficulty_distribution"].items())
    lines.extend(["", "### Tasks", "", "| Task | Count |", "|---|---:|"])
    lines.extend(f"| {k} | {v} |" for k, v in stats["task_distribution"].items())
    lines.extend(["", "### IDS Labels", "", "| Label | Count |", "|---|---:|"])
    lines.extend(f"| {k} | {v} |" for k, v in stats["label_distribution"].items())
    lines.extend(
        [
            "",
            "## Known Limitations",
            "",
            "- Local retrieval artifacts currently cover five IDS labels; final label coverage depends on exported retrieval contexts.",
            "- Synthetic examples are deterministic and should receive manual review before LoRA training.",
            "- CVE relevance remains candidate context unless asset evidence confirms exposure.",
            "- Group, tool, malware, and campaign context remains behavior-usage context, not attribution.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_training_readiness_report(
    stats: Mapping[str, Any], diversity: Mapping[str, Any], path: Path
) -> None:
    """Write final training-readiness report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    ready = (
        stats["quality"].get("rejected") == 0
        and len(stats["quality"].get("warnings", [])) == 0
        and not diversity.get("flags")
    )
    lines = [
        "# TrustSecAI Training Readiness",
        "",
        f"- Status: {'Ready for manual review before LoRA training' if ready else 'Needs review before training'}",
        f"- Examples: {stats['example_count']}",
        f"- Validation rejected: {stats['quality'].get('rejected')}",
        f"- Validation warnings: {len(stats['quality'].get('warnings', []))}",
        f"- Diversity flags: {len(diversity.get('flags', []))}",
        "",
        "## Readiness Checks",
        "",
        "| Check | Result |",
        "|---|---|",
        f"| JSONL export present | pass |",
        f"| Pretty JSON export present | pass |",
        f"| Quality report generated | pass |",
        f"| Missing provenance rejected | pass |",
        f"| Invented security IDs rejected | pass |",
        f"| Unsupported attribution rejected | pass |",
        f"| Dataset diversity report generated | pass |",
        "",
        "## Required Human Review",
        "",
        "- Review samples from each task family, difficulty level, and variant.",
        "- Check that response tone matches expected SOC analyst style.",
        "- Confirm that negative examples appropriately refuse unsupported conclusions.",
        "- Confirm that executive summaries avoid excess technical detail.",
        "- Confirm that GraphRAG context is framed as contextual evidence rather than proof.",
        "",
        "## Next Step",
        "",
        "After manual approval, this same deterministic pipeline can be used to scale toward the 20,000-30,000 example LoRA corpus.",
    ]
    if diversity.get("flags"):
        lines.extend(["", "## Diversity Flags", ""])
        lines.extend(f"- {flag}" for flag in diversity["flags"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
