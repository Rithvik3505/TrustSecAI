"""Classifier-vs-LLM agreement analysis."""

from __future__ import annotations

import re
from typing import Any


UNCERTAIN_TERMS = ("uncertain", "insufficient", "evidence gap", "missing evidence", "cannot determine")
BENIGN_PATTERNS = (
    re.compile(r"\bfalse positive\b"),
    re.compile(r"\bnot an? attack\b"),
    re.compile(r"\bno attack\b"),
    re.compile(r"\bclassified as benign\b"),
    re.compile(r"\bassess(?:ed)? as benign\b"),
    re.compile(r"\blikely benign\b"),
)
ATTACK_RELEVANT_TERMS = ("attack", "exploit", "technique", "compromise", "mitigation", "detection", "malicious")


def _text_from_output(parsed_llm_output: dict[str, Any]) -> str:
    parts = []
    for value in parsed_llm_output.values():
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(str(item) for item in value)
        elif isinstance(value, dict):
            parts.append(str(value))
    return " ".join(parts).lower()


def analyze_agreement(
    classifier_prediction: str,
    classifier_confidence: float | None,
    ids_label: str | None,
    parsed_llm_output: dict[str, Any],
    evidence_flags: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Classify agreement between classifier output and secondary LLM assessment."""

    evidence_flags = evidence_flags or {}
    confidence = classifier_confidence if classifier_confidence is not None else 0.0
    classifier_attack = str(classifier_prediction).upper() == "ATTACK"
    text = _text_from_output(parsed_llm_output)
    uncertain = any(term in text for term in UNCERTAIN_TERMS)
    benign = any(pattern.search(text) for pattern in BENIGN_PATTERNS)
    attack_relevant = any(term in text for term in ATTACK_RELEVANT_TERMS)
    sparse_evidence = not evidence_flags.get("has_real_shap", True) or (
        not evidence_flags.get("has_cve", False) and evidence_flags.get("requires_vulnerability_context", False)
    )

    if sparse_evidence:
        category = "evidence_gap"
        rationale = "The assessment depends on missing or sparse evidence, so analyst review is required."
    elif classifier_attack and benign:
        category = "classifier_attack_llm_benign_or_uncertain"
        rationale = "The classifier predicts attack, but the LLM output appears benign-leaning or false-positive oriented."
    elif classifier_attack and confidence >= 0.9 and attack_relevant and not uncertain:
        category = "agree_attack_high_confidence"
        rationale = f"Classifier and LLM both support an attack-oriented assessment for {ids_label} with high classifier confidence."
    elif classifier_attack and uncertain:
        category = "llm_uncertain_classifier_attack"
        rationale = "The classifier predicts attack, while the LLM emphasizes uncertainty or missing corroboration."
    elif classifier_attack and confidence >= 0.9:
        category = "agree_attack_high_confidence"
        rationale = f"Classifier and LLM both support an attack-oriented assessment for {ids_label} with high classifier confidence."
    elif classifier_attack:
        category = "agree_attack_low_confidence"
        rationale = f"Classifier and LLM both support attack-oriented review for {ids_label}, but classifier confidence is not high."
    else:
        category = "evidence_gap"
        rationale = "The classifier does not provide an attack-positive signal; treat the LLM output as contextual review only."

    return {
        "category": category,
        "classifier_prediction": classifier_prediction,
        "classifier_confidence": classifier_confidence,
        "ids_label": ids_label,
        "rationale": rationale,
    }
