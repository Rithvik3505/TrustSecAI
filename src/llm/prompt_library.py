"""Reusable prompt templates for TrustSecAI supervised fine-tuning data."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable


@dataclass(frozen=True)
class PromptTemplate:
    """A reusable instruction template and expected output contract."""

    template_id: str
    task_type: str
    name: str
    instruction: str
    expected_output: Dict[str, object]


PROMPT_TEMPLATES: Dict[str, PromptTemplate] = {
    "incident_report": PromptTemplate(
        template_id="incident_report",
        task_type="incident_report_generation",
        name="Incident Report",
        instruction=(
            "Generate a SOC analyst incident assessment from the provided TrustSecAI "
            "context. Use only the supplied evidence. Include classifier result, key "
            "SHAP evidence, ATT&CK mapping, relevant attack patterns, candidate "
            "vulnerabilities, mitigations, recommended actions, and uncertainties."
        ),
        expected_output={
            "title": "Security Incident Assessment",
            "primary_assessment": "...",
            "classifier_evidence": [],
            "attack_mapping": [],
            "threat_context": [],
            "candidate_vulnerabilities": [],
            "recommended_actions": [],
            "uncertainties": [],
            "severity": "low|medium|high|critical",
            "confidence": "low|medium|high",
        },
    ),
    "threat_assessment": PromptTemplate(
        template_id="threat_assessment",
        task_type="threat_assessment",
        name="Threat Assessment",
        instruction=(
            "Assess the likely threat represented by the IDS prediction and graph "
            "context. Explain the likely attacker objective, mapped ATT&CK "
            "tactic/technique, relevant CAPEC behavior, and operational risk. Do not "
            "claim facts that are not present in the context."
        ),
        expected_output={
            "threat_summary": "...",
            "likely_objective": "...",
            "mapped_technique": {"attack_id": "...", "name": "..."},
            "tactics": [],
            "risk_drivers": [],
            "evidence": [],
            "uncertainties": [],
        },
    ),
    "mitigation_recommendation": PromptTemplate(
        template_id="mitigation_recommendation",
        task_type="mitigation_recommendation",
        name="Mitigation Recommendation",
        instruction=(
            "Recommend prioritized mitigations for the supplied incident context. "
            "Prefer mitigations from ATT&CK and CAPEC. Include detection or validation "
            "steps when available. Separate immediate containment from longer-term "
            "hardening."
        ),
        expected_output={
            "immediate_actions": [],
            "hardening_actions": [],
            "detection_and_validation": [],
            "mapped_mitigations": [],
            "rationale": [],
            "limitations": [],
        },
    ),
    "executive_summary": PromptTemplate(
        template_id="executive_summary",
        task_type="executive_summary",
        name="Executive Summary",
        instruction=(
            "Write a concise executive summary of the incident for a non-technical "
            "stakeholder. Keep the language clear and avoid unnecessary technical "
            "detail. Preserve severity, business impact, confidence, and recommended "
            "next steps."
        ),
        expected_output={
            "summary": "...",
            "severity": "...",
            "business_impact": "...",
            "confidence": "...",
            "next_steps": [],
        },
    ),
    "attack_mapping": PromptTemplate(
        template_id="attack_mapping",
        task_type="attack_mapping",
        name="ATT&CK Mapping",
        instruction=(
            "Map the IDS prediction to ATT&CK context using the supplied graph data. "
            "Return the technique, tactic, related mitigations, detection guidance, "
            "and supporting provenance. If the mapping is broad or uncertain, say so "
            "explicitly."
        ),
        expected_output={
            "ids_prediction": "...",
            "attack_mapping": {
                "technique_id": "...",
                "technique_name": "...",
                "tactics": [],
            },
            "mitigations": [],
            "detection_guidance": [],
            "provenance": [],
            "mapping_confidence": "low|medium|high",
            "caveats": [],
        },
    ),
    "security_analyst_reasoning": PromptTemplate(
        template_id="security_analyst_reasoning",
        task_type="security_analyst_reasoning",
        name="Security Analyst Reasoning",
        instruction=(
            "Explain how the classifier evidence and graph context support or limit "
            "the incident assessment. Discuss top SHAP features, mapped technique "
            "behavior, and any retrieved vulnerability context. Use cautious language "
            "for inferred relationships."
        ),
        expected_output={
            "reasoning": [{"step": 1, "claim": "...", "evidence": []}],
            "classifier_interpretation": [],
            "graph_interpretation": [],
            "inferred_context": [],
            "uncertainties": [],
        },
    ),
    "vulnerability_summary": PromptTemplate(
        template_id="vulnerability_summary",
        task_type="vulnerability_summary",
        name="Vulnerability Summary",
        instruction=(
            "Summarize candidate vulnerability context for the incident. Use "
            "CVE/CWE/product context only when present in the supplied graph. Mark "
            "CVEs as candidate context unless the input contains asset evidence "
            "proving exposure."
        ),
        expected_output={
            "weaknesses": [],
            "candidate_cves": [],
            "affected_products": [],
            "cvss_summary": "...",
            "asset_exposure_note": "...",
            "references": [],
        },
    ),
    "evidence_review": PromptTemplate(
        template_id="evidence_review",
        task_type="uncertainty_analysis",
        name="Evidence Review",
        instruction=(
            "Review the supplied TrustSecAI context for evidence strength and "
            "uncertainty. Identify which conclusions are directly supported, which "
            "are inferred, and what additional evidence a SOC analyst should collect."
        ),
        expected_output={
            "directly_supported": [],
            "inferred": [],
            "unsupported_or_missing": [],
            "recommended_evidence_to_collect": [],
            "overall_confidence": "low|medium|high",
        },
    ),
}


def get_template(template_id: str) -> PromptTemplate:
    """Return a prompt template by ID."""

    return PROMPT_TEMPLATES[template_id]


def iter_templates() -> Iterable[PromptTemplate]:
    """Iterate over templates in deterministic order."""

    for template_id in sorted(PROMPT_TEMPLATES):
        yield PROMPT_TEMPLATES[template_id]

