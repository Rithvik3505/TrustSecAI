"""Build final TrustSecAI Markdown security assessment reports."""

from __future__ import annotations

import json
import re
from typing import Any


def _fmt_list(items: Any) -> str:
    if not items:
        return "- None supplied"
    if isinstance(items, str):
        return f"- {items}"
    if isinstance(items, dict):
        return "\n".join(f"- `{key}`: {value}" for key, value in items.items())
    lines = []
    for item in items:
        if isinstance(item, dict):
            label = item.get("id") or item.get("feature") or item.get("name") or "item"
            detail = item.get("name") or item.get("technique") or item.get("tactic") or item
            lines.append(f"- `{label}`: {detail}")
        else:
            lines.append(f"- {item}")
    return "\n".join(lines) if lines else "- None supplied"


def _fmt_shap_features(features: Any, limit: int = 5) -> str:
    """Format top SHAP features as concise analyst-readable bullets."""

    if not features:
        return "- None supplied"
    lines = []
    for item in list(features)[:limit]:
        if not isinstance(item, dict):
            lines.append(f"- {item}")
            continue
        feature = item.get("feature", "unknown feature")
        value = item.get("value", "unknown")
        shap_value = item.get("shap_value")
        direction = str(item.get("direction", "unknown")).replace("_", " ")
        if isinstance(shap_value, (int, float)):
            shap_text = f"{shap_value:+.4f}"
        else:
            shap_text = str(shap_value)
        lines.append(f"- {feature} = {value}, SHAP {shap_text}, {direction}")
    return "\n".join(lines)


def _fmt_attack_chain_steps(steps: Any) -> str:
    """Format bounded attack-chain steps without raw dictionaries."""

    if not steps:
        return "- None supplied"
    lines = []
    for item in steps:
        if not isinstance(item, dict):
            lines.append(f"- {item}")
            continue
        tactic = item.get("tactic", "Follow-up")
        technique = item.get("technique") or item.get("technique_name") or item.get("description") or "review related evidence"
        technique_id = item.get("id") or item.get("technique_id") or "candidate"
        if technique_id == "candidate":
            lines.append(f"- {tactic}: candidate {technique.lower()}")
        else:
            lines.append(f"- {tactic}: {technique_id} {technique}")
    return "\n".join(lines)


def _fmt_mitigations(items: Any) -> str:
    """Format mitigation strings or graph-backed mitigation dictionaries."""

    if not items:
        return "- None supplied"
    lines = []
    for item in items:
        if isinstance(item, dict):
            mid = item.get("id") or "mitigation"
            name = item.get("name") or ""
            lines.append(f"- {mid} {name}".strip())
        else:
            lines.append(f"- {item}")
    return "\n".join(lines)


def _fmt_vulnerability_context(context: dict[str, Any] | None) -> str:
    """Format CAPEC/CWE/CVE context from graph-backed attack-chain output."""

    if not context:
        return "- None supplied"
    lines = []
    for label, key in [("CAPEC", "capec"), ("CWE", "cwes"), ("CVE", "cves")]:
        items = context.get(key) or []
        if not items:
            lines.append(f"- {label}: none reached")
            continue
        values = []
        for item in items[:5]:
            if isinstance(item, dict):
                value = item.get("id") or item.get("name")
                name = item.get("name")
                values.append(f"{value} {name}".strip() if name and name != value else str(value))
            else:
                values.append(str(item))
        lines.append(f"- {label}: {', '.join(values)}")
    return "\n".join(lines)


def _has_candidate_vulnerability_context(graph_context_summary: dict[str, Any]) -> bool:
    """Return whether CAPEC/CWE/CVE candidate context is present."""

    return any(
        graph_context_summary.get(key)
        for key in ("capec_ids", "cwe_ids", "cve_ids")
    )


def _build_executive_summary(
    label: str,
    confidence_text: str,
    classifier_evidence: dict[str, Any],
    graph_context_summary: dict[str, Any],
    shap_evidence: dict[str, Any],
) -> str:
    """Create a concise, evidence-grounded executive summary."""

    technique = graph_context_summary.get("technique") or {}
    cve_ids = graph_context_summary.get("cve_ids") or []
    has_asset_exposure = graph_context_summary.get("has_asset_exposure_evidence", False)
    shap_features = shap_evidence.get("top_features") or shap_evidence.get("shap_evidence") or []
    shap_phrase = "SHAP evidence is available"
    if shap_features:
        top_names = [str(item.get("feature")) for item in shap_features[:2] if isinstance(item, dict) and item.get("feature")]
        if top_names:
            shap_phrase = f"SHAP evidence is led by {', '.join(top_names)}"
    graph_phrase = "No ATT&CK technique was supplied"
    if technique.get("id"):
        graph_phrase = f"graph context maps the behavior to {technique.get('id')} {technique.get('name', '')}".strip()
    if has_asset_exposure:
        evidence_gap = "Asset exposure evidence is present in the supplied context."
    elif _has_candidate_vulnerability_context(graph_context_summary):
        evidence_gap = "CVE/CWE candidate enrichment is present, but asset exposure is not established."
    elif not cve_ids:
        evidence_gap = "No CVE or asset exposure evidence is present, so this is a triage assessment rather than confirmed compromise."
    else:
        evidence_gap = "CVE candidate enrichment is present, but asset exposure is not established."
    return (
        f"The classifier identified {label} with {confidence_text} confidence and prediction "
        f"{classifier_evidence.get('model_prediction', 'unknown')}. {shap_phrase}, and {graph_phrase} "
        f"as contextual intelligence. {evidence_gap}"
    )


def _strip_code_fence(text: str) -> str:
    """Remove common Markdown code fences."""

    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?", "", stripped, flags=re.IGNORECASE).strip()
        stripped = re.sub(r"```$", "", stripped).strip()
    return stripped


def _load_jsonish(raw_output: str) -> dict[str, Any]:
    """Best-effort JSON repair for fallback-parsed LLM output."""

    stripped = _strip_code_fence(raw_output or "")
    candidates = [stripped]
    if "{" in stripped and "}" in stripped:
        candidates.append(stripped[stripped.find("{") : stripped.rfind("}") + 1])
    for candidate in candidates:
        try:
            loaded = json.loads(candidate)
            if isinstance(loaded, dict):
                return loaded
        except json.JSONDecodeError:
            continue
    return {}


def _extract_json_string(raw_output: str, key: str) -> str | None:
    """Extract a quoted JSON string value by key."""

    match = re.search(rf'"{re.escape(key)}"\s*:\s*"((?:\\.|[^"\\])*)"', raw_output or "", flags=re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(f'"{match.group(1)}"')
    except json.JSONDecodeError:
        return match.group(1)


def _extract_json_array(raw_output: str, key: str) -> list[Any] | None:
    """Extract a simple JSON array value by key."""

    marker = f'"{key}"'
    start = (raw_output or "").find(marker)
    if start < 0:
        return None
    bracket = raw_output.find("[", start)
    if bracket < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    for index, char in enumerate(raw_output[bracket:], start=bracket):
        if escape:
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                try:
                    loaded = json.loads(raw_output[bracket : index + 1])
                    return loaded if isinstance(loaded, list) else None
                except json.JSONDecodeError:
                    return None
    return None


def _recover_llm_display_fields(llm_secondary_assessment: dict[str, Any]) -> dict[str, Any]:
    """Recover display fields without dumping raw fallback output."""

    if llm_secondary_assessment.get("parse_ok"):
        return {
            "graph_interpretation": llm_secondary_assessment.get("graph_interpretation") or "Not available",
            "recommended_actions": llm_secondary_assessment.get("recommended_actions"),
            "limitations": llm_secondary_assessment.get("limitations"),
        }

    raw_output = llm_secondary_assessment.get("raw_output") or ""
    recovered = _load_jsonish(raw_output)
    graph_interpretation = recovered.get("graph_interpretation") or _extract_json_string(raw_output, "graph_interpretation")
    recommended_actions = recovered.get("recommended_actions") or _extract_json_array(raw_output, "recommended_actions")
    limitations = recovered.get("limitations") or _extract_json_array(raw_output, "limitations")

    if not graph_interpretation:
        current = llm_secondary_assessment.get("graph_interpretation")
        if isinstance(current, str) and not current.lstrip().startswith(("{", "[")) and len(current) < 500:
            graph_interpretation = current
    if not graph_interpretation:
        graph_interpretation = "Structured fields were not fully recoverable; raw output is available in the JSON artifact."
    return {
        "graph_interpretation": graph_interpretation,
        "recommended_actions": recommended_actions,
        "limitations": limitations,
    }


def build_security_report(
    classifier_evidence: dict[str, Any],
    shap_evidence: dict[str, Any],
    graph_context_summary: dict[str, Any],
    llm_secondary_assessment: dict[str, Any],
    agreement_result: dict[str, Any],
    attack_chain_prediction: dict[str, Any],
    limitations: list[str] | None = None,
) -> str:
    """Build a Markdown report from TrustSecAI evidence and analyses."""

    limitations = limitations or []
    label = classifier_evidence.get("ids_label") or classifier_evidence.get("ids_label_ground_truth") or "Unknown"
    confidence = classifier_evidence.get("model_confidence")
    confidence_text = f"{confidence:.2%}" if isinstance(confidence, (int, float)) else "unavailable"
    technique = graph_context_summary.get("technique") or {}
    tactics = graph_context_summary.get("tactics") or []
    tactic_text = ", ".join(f"{item.get('id')} {item.get('name', '')}" for item in tactics) if tactics else "None supplied"
    shap_features = shap_evidence.get("top_features") or shap_evidence.get("shap_evidence")
    parse_line = (
        "LLM output parsed successfully."
        if llm_secondary_assessment.get("parse_ok")
        else "LLM output required fallback parsing."
    )
    llm_display = _recover_llm_display_fields(llm_secondary_assessment)
    executive_summary = _build_executive_summary(
        label=label,
        confidence_text=confidence_text,
        classifier_evidence=classifier_evidence,
        graph_context_summary=graph_context_summary,
        shap_evidence=shap_evidence,
    )
    chain_mode = attack_chain_prediction.get("mode", "static_fallback")
    chain_mode_text = (
        "graph-backed Neo4j traversal" if chain_mode == "graph" else "static fallback"
    )

    lines = [
        "# TrustSecAI Security Assessment Report",
        "",
        "## Executive Summary",
        "",
        executive_summary,
        "",
        "## Incident Summary",
        "",
        f"- IDS label: `{label}`",
        f"- Binary classifier prediction: `{classifier_evidence.get('model_prediction', 'unknown')}`",
        f"- Classifier confidence: `{confidence_text}`",
        f"- Sample ID: `{classifier_evidence.get('sample_id', 'unknown')}`",
        "",
        "## Classifier And SHAP Evidence",
        "",
        _fmt_shap_features(shap_features),
        "",
        "## Graph Context",
        "",
        f"- Technique: `{technique.get('id', 'unknown')}` {technique.get('name', '')}",
        f"- Tactics: {tactic_text}",
        f"- Mitigations: {', '.join(graph_context_summary.get('mitigation_ids', []) or []) or 'None supplied'}",
        "",
        "Graph context is contextual intelligence and does not prove compromise or attribution.",
        "",
        "## LLM Secondary Assessment",
        "",
        f"- {parse_line}",
        f"- Graph interpretation: {llm_display.get('graph_interpretation')}",
        "",
        "### Recommended Actions",
        "",
        _fmt_list(llm_display.get("recommended_actions")),
        "",
        "### LLM Limitations",
        "",
        _fmt_list(llm_display.get("limitations")),
        "",
        "## Classifier vs LLM Agreement",
        "",
        f"- Category: `{agreement_result.get('category')}`",
        f"- Rationale: {agreement_result.get('rationale')}",
        "",
        "## Defensive Attack Chain Hypothesis",
        "",
        f"- Attack-chain mode: {chain_mode_text}",
        f"- Seed technique: `{(attack_chain_prediction.get('seed_technique') or {}).get('id', 'unknown')}` "
        f"{(attack_chain_prediction.get('seed_technique') or {}).get('name', '')}",
        f"- Confidence: `{attack_chain_prediction.get('confidence', 'unknown')}`",
        "",
        "### Likely Next Tactics/Techniques",
        "",
        _fmt_attack_chain_steps(attack_chain_prediction.get("likely_next_tactics_techniques")),
        "",
        "### Chain Mitigations",
        "",
        _fmt_mitigations(attack_chain_prediction.get("mitigations")),
        "",
        "### Vulnerability Context",
        "",
        _fmt_vulnerability_context(attack_chain_prediction.get("vulnerability_context")),
        "",
        "### Caveats",
        "",
        _fmt_list(attack_chain_prediction.get("caveats")),
        "",
        "## Overall Limitations",
        "",
        _fmt_list(limitations),
        "",
    ]
    return "\n".join(lines)
