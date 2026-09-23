"""Deterministic target-output generation for the TrustSecAI pilot corpus."""

from __future__ import annotations

from copy import deepcopy
import random
from typing import Any, Dict, List, Mapping


REASONING_STYLES = (
    {
        "name": "observation_evidence_assessment",
        "opening": "Initial observation",
        "evidence": "Supporting evidence",
        "assessment": "Assessment",
        "action": "Next step",
    },
    {
        "name": "evidence_risk_recommendation",
        "opening": "Evidence review",
        "evidence": "Risk signal",
        "assessment": "Analyst assessment",
        "action": "Recommended action",
    },
    {
        "name": "confidence_limitations_next_steps",
        "opening": "Confidence view",
        "evidence": "Limitation",
        "assessment": "Interpretation",
        "action": "Next steps",
    },
    {
        "name": "mapping_context_caveat",
        "opening": "Mapping",
        "evidence": "Context",
        "assessment": "Caveat",
        "action": "Follow-up",
    },
    {
        "name": "signal_context_response",
        "opening": "Signal",
        "evidence": "Context",
        "assessment": "Response priority",
        "action": "Action",
    },
    {
        "name": "triage_finding_impact",
        "opening": "Triage finding",
        "evidence": "Evidence basis",
        "assessment": "Potential impact",
        "action": "Containment focus",
    },
    {
        "name": "classifier_graph_uncertainty",
        "opening": "Classifier result",
        "evidence": "Graph context",
        "assessment": "Uncertainty",
        "action": "Review path",
    },
    {
        "name": "analyst_note_evidence_gap",
        "opening": "Analyst note",
        "evidence": "Known evidence",
        "assessment": "Evidence gap",
        "action": "Collection priority",
    },
    {
        "name": "operational_risk_controls",
        "opening": "Operational risk",
        "evidence": "Relevant controls",
        "assessment": "Security assessment",
        "action": "Control review",
    },
    {
        "name": "briefing_rationale_caution",
        "opening": "Briefing",
        "evidence": "Rationale",
        "assessment": "Caution",
        "action": "Decision support",
    },
)

OBSERVATION_PHRASES = (
    "The alert should be triaged as a security signal, not a standalone conclusion",
    "The classifier output gives the SOC team a starting point for investigation",
    "The event is notable because the model and graph context point to a recognizable behavior",
    "The available evidence supports a focused review of this alert",
    "The record is suitable for analyst triage because it contains classifier and graph evidence",
    "The incident context is sufficient for an initial assessment, with normal validation caveats",
    "The alert is actionable as an investigation lead",
    "The evidence package is strongest when the IDS result, SHAP features, and graph mapping are read together",
    "The current context supports an initial SOC assessment",
    "The alert should be reviewed in the context of surrounding network and host telemetry",
    "The classifier result is a useful detection signal",
    "The graph enrichment narrows the likely behavior to a known ATT&CK technique",
)

RISK_PHRASES = (
    "Operational risk depends on whether the behavior is repeated, targeted, or tied to exposed services",
    "Risk is higher if the affected service is internet-facing or business-critical",
    "The main risk is that the observed behavior may precede follow-on activity",
    "The business impact should be assessed against affected assets and service exposure",
    "The triage priority should increase if similar activity appears across multiple hosts",
    "Risk remains contextual until the SOC confirms scope, asset value, and exposure",
    "The alert is more concerning when paired with failed authentication, scanning bursts, or unusual destinations",
    "The operational concern is not attribution, but whether the behavior indicates an active intrusion path",
)

MITIGATION_VERBS = (
    "review",
    "prioritize",
    "evaluate",
    "consider",
    "validate",
    "apply where appropriate",
    "assess the fit of",
    "map existing controls to",
)

COLLECTION_ACTIONS = (
    "compare flow timing with firewall and proxy logs",
    "check whether the destination service is expected for the host role",
    "review endpoint telemetry for related process or authentication activity",
    "look for repeated attempts from the same source or subnet",
    "verify whether the asset is internet-facing or business-critical",
    "check recent vulnerability exposure for the affected product family",
    "confirm whether segmentation or access-control policy should have blocked the flow",
    "correlate the alert with authentication, DNS, and EDR events",
    "preserve packet or flow evidence before tuning the alert",
    "compare the event with known maintenance windows or scanning jobs",
)

CONCLUSION_PHRASES = (
    "Treat this as a credible lead until corroborating telemetry confirms or downgrades it",
    "The safest conclusion is to investigate the mapped behavior without assuming compromise",
    "The alert merits review, but the graph context should not be read as proof of attacker activity",
    "The response should stay evidence-led and avoid attribution claims",
    "The current evidence supports triage and containment planning, not final incident closure",
    "Analyst review should focus on confirming scope and exposure before escalation",
)

GRAPH_CONTEXT_PHRASES = (
    "GraphRAG adds context for triage, but it does not prove compromise on its own",
    "The graph evidence should be treated as enrichment rather than confirmation",
    "Retrieved ATT&CK context narrows the hypothesis; it does not establish attacker activity by itself",
    "Graph retrieval supports investigation planning, not final incident determination",
    "The graph context explains possible behavior but still needs local telemetry for confirmation",
    "Use the retrieved graph facts as analyst context, not as a substitute for direct evidence",
    "The graph relationship is useful for mapping and mitigation, not attribution",
    "GraphRAG provides supporting intelligence and should be weighed against environment evidence",
)

NO_CVE_PHRASES = (
    "No CVEs are present in the supplied graph context; avoid inferring vulnerabilities",
    "The retrieved context does not include CVEs, so vulnerability claims should be withheld",
    "No candidate CVE evidence is supplied for this alert",
    "The graph output has no CVE entries for this case",
    "Vulnerability discussion should remain general because no CVEs were retrieved",
)

NO_MITIGATION_PHRASES = (
    "No mitigation node is present in the supplied graph context",
    "The retrieved context does not include a mapped mitigation",
    "Mitigation guidance is absent from the graph output for this example",
    "No source mitigation was returned, so controls should be selected by analyst review",
)

LOW_CONFIDENCE_PHRASES = (
    "Classifier confidence is low; analyst review is recommended",
    "The classifier signal is weak, so a human analyst should verify the alert",
    "Low confidence makes this a review-first example",
    "The model score is not strong enough for an automated conclusion",
)

NO_ATTRIBUTION_PHRASES = (
    "Actor, tool, and malware context shows observed ATT&CK usage, not attribution",
    "Related groups, tools, or malware should not be treated as the identified operator",
    "Threat-actor context is behavioral background only",
    "Usage relationships provide context but do not identify the attacker",
    "Retrieved actor or software links are not attribution evidence",
)

INFERRED_CONTEXT_PHRASES = (
    "Some graph context is inferred and should be described as candidate evidence",
    "Inferred graph edges require cautious wording",
    "Treat inferred relationships as leads rather than confirmed facts",
    "Candidate graph links should be validated against local evidence",
)

PERSONAS = (
    {
        "key": "tier1_soc",
        "opening": "The alert should be validated quickly against nearby telemetry",
        "focus": "triage, validation, and escalation",
        "action": "confirm whether the event is expected before escalation",
    },
    {
        "key": "tier2_soc",
        "opening": "Inspection of the supplied evidence supports a structured follow-up",
        "focus": "evidence interpretation and investigation planning",
        "action": "pivot into related host, network, and identity telemetry",
    },
    {
        "key": "tier3_soc",
        "opening": "The technical pattern deserves deeper review against detection and control coverage",
        "focus": "technical assessment, detection, and hardening",
        "action": "map the finding to detection coverage and durable controls",
    },
    {
        "key": "threat_hunter",
        "opening": "A reasonable hunting hypothesis is available, but alternate explanations remain possible",
        "focus": "hypotheses, alternate explanations, and telemetry gaps",
        "action": "test the hypothesis with independent telemetry",
    },
    {
        "key": "incident_responder",
        "opening": "The alert should be handled with scoping and containment readiness in mind",
        "focus": "containment, scoping, and next actions",
        "action": "scope affected assets before containment decisions",
    },
    {
        "key": "blue_team_engineer",
        "opening": "The finding is useful for reviewing controls, logging, and detection coverage",
        "focus": "controls, logging, detection engineering, and hardening",
        "action": "check whether existing controls would detect or block the behavior",
    },
    {
        "key": "executive_briefing",
        "opening": "The security impact should be framed around business exposure and operational risk",
        "focus": "business impact, operational risk, and concise action items",
        "action": "confirm exposure and prioritize business-critical assets",
    },
    {
        "key": "security_assurance",
        "opening": "The assessment should emphasize confidence, evidence quality, and limitations",
        "focus": "confidence, limitations, evidence quality, and risk framing",
        "action": "document evidence quality before making risk decisions",
    },
)

NARRATIVE_PATTERNS = (
    ("observation", "evidence", "assessment", "action"),
    ("signal", "contextual interpretation", "limitation", "next step"),
    ("confidence", "corroborating evidence", "caveat", "recommendation"),
    ("risk", "potential consequence", "containment", "validation"),
    ("hypothesis", "supporting evidence", "alternative explanation", "evidence gap"),
    ("technique mapping", "operational significance", "mitigation priority", "review path"),
    ("executive impact", "confidence", "immediate business action", "owner"),
    ("detection gap", "telemetry recommendation", "hardening action", "verification"),
    ("analyst triage", "escalation rationale", "follow-up investigation", "limit"),
    ("classifier signal", "SHAP evidence", "graph context", "uncertainty"),
    ("retrieved intelligence", "candidate evidence", "control mapping", "next action"),
    ("scope question", "available evidence", "missing evidence", "decision point"),
    ("service exposure", "mapped behavior", "risk driver", "containment option"),
    ("confidence check", "graph caveat", "analyst validation", "recommendation"),
    ("telemetry summary", "threat context", "mitigation rationale", "limitation"),
)


def compact_text(value: object, limit: int = 240) -> str:
    """Return a compact one-line string for report-style outputs."""

    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def confidence_band(confidence: float) -> str:
    """Convert classifier confidence to a coarse band."""

    if confidence >= 0.85:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"


def style_for(sequence_index: int) -> Dict[str, str]:
    """Return a deterministic reasoning style."""

    return dict(REASONING_STYLES[(sequence_index - 1) % len(REASONING_STYLES)])


def persona_for(sequence_index: int) -> Dict[str, str]:
    """Return deterministic analyst persona guidance without exposing persona labels."""

    return dict(PERSONAS[(sequence_index - 1) % len(PERSONAS)])


def narrative_pattern_for(sequence_index: int) -> tuple[str, str, str, str]:
    """Return deterministic narrative pattern labels for prose variation."""

    return NARRATIVE_PATTERNS[(sequence_index - 1) % len(NARRATIVE_PATTERNS)]


def seeded_choice(sequence_index: int, options: List[str]) -> str:
    """Choose a phrase deterministically while preserving variation."""

    rng = random.Random(42 + sequence_index)
    return options[rng.randrange(len(options))]


def phrase(sequence_index: int, options: tuple[str, ...], salt: int = 0) -> str:
    """Pick a deterministic phrase from an immutable phrase bank."""

    return seeded_choice(sequence_index + salt, list(options))


def confidence_phrase(confidence: float, sequence_index: int) -> str:
    """Return confidence-aware analyst wording."""

    if confidence > 0.9:
        return seeded_choice(
            sequence_index,
            [
                "The classifier signal is strong, though the graph context is still contextual evidence rather than proof of compromise.",
                "The model confidence is high, so the alert should be treated as credible while preserving normal analyst caveats.",
                "The classifier is highly confident; validate scope and impact before drawing conclusions about compromise.",
            ],
        )
    if confidence < 0.5:
        return seeded_choice(
            sequence_index,
            [
                "Classifier confidence is low, so analyst review should take priority over automated conclusions.",
                "The alert is weakly supported by the classifier and should be handled as a review candidate.",
                "Low confidence means the assessment should stay cautious until additional telemetry is checked.",
            ],
        )
    return seeded_choice(
        sequence_index,
        [
            "Classifier confidence is moderate; the graph context can guide triage but should not be treated as confirmation.",
            "The signal is plausible but not definitive, so the response should balance evidence and uncertainty.",
            "The classifier provides a useful lead; corroborating telemetry is still needed.",
        ],
    )


def confidence_percent(confidence: float) -> str:
    """Format classifier confidence as a human-readable percentage."""

    return f"{confidence * 100:.1f}%"


def shap_feature_names(shap: Mapping[str, Any], limit: int = 3, offset: int = 0) -> List[str]:
    """Return top SHAP feature names."""

    rows = [
        str(item.get("feature"))
        for item in shap.get("top_features", [])
        if item.get("feature")
    ]
    if not rows:
        return []
    start = offset % len(rows)
    rotated = rows[start:] + rows[:start]
    return rotated[: min(limit, len(rotated))]


def shap_narrative(shap: Mapping[str, Any], sequence_index: int) -> str:
    """Summarize SHAP evidence in natural SOC language."""

    limit = 2 + (sequence_index % 3)
    features = shap_feature_names(shap, limit=limit, offset=sequence_index)
    if not features:
        return "No SHAP feature list is available in the supplied input."
    joined = ", ".join(features[:-1]) + (f", and {features[-1]}" if len(features) > 1 else features[0])
    return seeded_choice(
        sequence_index,
        [
            f"The classifier evidence is mainly driven by {joined}.",
            f"SHAP highlights {joined} as the leading contributors.",
            f"The strongest model signals come from {joined}.",
            f"The prediction is supported most clearly by {joined}.",
            f"Feature attribution points first to {joined}.",
            f"The model explanation emphasizes {joined}.",
            f"Key contributing flow characteristics include {joined}.",
            f"The classifier was most influenced by {joined}.",
            f"Observed flow attribution centers on {joined}.",
            f"The most useful model evidence in this sample is {joined}.",
        ],
    )


def analyst_flow(
    prediction: str,
    technique: Mapping[str, Any],
    confidence: float,
    shap: Mapping[str, Any],
    context: Mapping[str, Any],
    sequence_index: int,
) -> List[str]:
    """Create an Observation -> Evidence -> Reasoning -> Conclusion flow."""

    return [
        f"Observation: {phrase(sequence_index, OBSERVATION_PHRASES)} for {prediction}.",
        f"Evidence: {shap_narrative(shap, sequence_index)}",
        f"Reasoning: GraphRAG maps the label to {technique.get('id')} ({technique.get('name')}) as contextual evidence. {phrase(sequence_index, GRAPH_CONTEXT_PHRASES, salt=31)}.",
        f"Conclusion: {phrase(sequence_index, CONCLUSION_PHRASES, salt=3)}",
        f"Limitations: {', '.join(uncertainty_notes(context, confidence, sequence_index)[:2])}",
    ]


def severity_from_context(context: Mapping[str, Any], confidence: float) -> str:
    """Estimate response severity from supplied evidence only."""

    cves = context.get("cves", [])
    max_score = 0.0
    for cve in cves:
        props = cve.get("properties", {})
        for key in ("cvss_base_score", "base_score", "score"):
            try:
                max_score = max(max_score, float(props.get(key) or 0.0))
            except (TypeError, ValueError):
                continue
    if max_score >= 9.0:
        return "critical"
    if max_score >= 7.0 or confidence >= 0.9:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"


def compact_properties(properties: Mapping[str, Any]) -> Dict[str, Any]:
    """Compact verbose descriptions while preserving grounding fields."""

    compacted: Dict[str, Any] = {}
    for key, value in properties.items():
        if key in {"description", "x_mitre_detection", "execution_flow"}:
            compacted[key] = compact_text(value, limit=420)
            if str(value or "") != compacted[key]:
                compacted[f"{key}_summary"] = compacted[key]
        elif isinstance(value, str) and len(value) > 800:
            compacted[key] = compact_text(value, limit=420)
            compacted[f"{key}_summary"] = compacted[key]
        else:
            compacted[key] = value
    return compacted


def compact_entity(entity: Any) -> Any:
    """Compact one graph entity without removing IDs or provenance."""

    if isinstance(entity, list):
        return [compact_entity(item) for item in entity]
    if not isinstance(entity, dict):
        return entity
    compacted = {}
    for key, value in entity.items():
        if key == "properties" and isinstance(value, dict):
            compacted[key] = compact_properties(value)
        else:
            compacted[key] = compact_entity(value)
    return compacted


def limit_graph_context(context: Mapping[str, Any], limits: Mapping[str, int]) -> Dict[str, Any]:
    """Return a deterministic, curriculum-limited copy of graph context."""

    limited = deepcopy(dict(context))
    for key, count in limits.items():
        if key in limited and isinstance(limited[key], list):
            limited[key] = limited[key][:count]
    if "attack" in limited:
        attack = deepcopy(limited["attack"])
        if "mitigations" in attack:
            attack["mitigations"] = attack["mitigations"][:3]
        limited["attack"] = attack
    return compact_entity(limited)


def make_ids_input(seed: Mapping[str, Any], confidence: float) -> Dict[str, Any]:
    """Build the IDS input section for one example."""

    return {
        "prediction": seed["prediction"],
        "confidence": round(confidence, 4),
        "binary_label": 1,
        "source_file": seed.get("source_file", "graph_retrieval_context"),
    }


def make_shap_input(seed: Mapping[str, Any], limit: int = 5) -> Dict[str, Any]:
    """Build the SHAP input section."""

    features = []
    for row in list(seed.get("top_features", []))[:limit]:
        shap_value = float(row.get("shap_value", 0.0))
        abs_value = abs(shap_value)
        if abs_value >= 0.05:
            strength = "high"
        elif abs_value >= 0.02:
            strength = "moderate"
        else:
            strength = "low"
        features.append(
            {
                "feature": row.get("feature"),
                "value": row.get("value"),
                "shap_value": round(shap_value, 4),
                "contribution_strength": strength,
            }
        )
    return {
        "top_features": features,
        "source": seed.get("shap_source", "deterministic_fallback"),
    }


def get_technique(context: Mapping[str, Any]) -> Dict[str, Any]:
    """Return the primary technique object from graph context."""

    return dict(context.get("attack", {}).get("technique") or {})


def get_tactics(context: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Return tactic list."""

    return list(context.get("attack", {}).get("tactics") or [])


def get_mitigations(context: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """Return mitigation list."""

    return list(context.get("attack", {}).get("mitigations") or [])


def ids_of(items: List[Mapping[str, Any]]) -> List[str]:
    """Return stable entity IDs."""

    return [str(item.get("id")) for item in items if item.get("id")]


def names_of(items: List[Mapping[str, Any]], limit: int = 5) -> List[str]:
    """Return stable entity names."""

    return [str(item.get("name") or item.get("id")) for item in items[:limit]]


def first_description(entity: Mapping[str, Any], limit: int = 220) -> str:
    """Return compact description from entity properties."""

    return compact_text(entity.get("properties", {}).get("description", ""), limit=limit)


def base_mapping(context: Mapping[str, Any]) -> Dict[str, Any]:
    """Build a compact ATT&CK mapping object."""

    technique = get_technique(context)
    return {
        "technique_id": technique.get("id"),
        "technique_name": technique.get("name"),
        "tactics": [
            {"id": tactic.get("id"), "name": tactic.get("name")}
            for tactic in get_tactics(context)
        ],
    }


def uncertainty_notes(
    context: Mapping[str, Any], confidence: float, sequence_index: int = 0
) -> List[str]:
    """Generate uncertainty statements grounded in available context."""

    notes: List[str] = []
    if confidence < 0.6:
        notes.append(phrase(sequence_index, LOW_CONFIDENCE_PHRASES, salt=41) + ".")
    if not context.get("cves"):
        notes.append(phrase(sequence_index, NO_CVE_PHRASES, salt=43) + ".")
    if not get_mitigations(context):
        notes.append(phrase(sequence_index, NO_MITIGATION_PHRASES, salt=47) + ".")
    if context.get("groups") or context.get("tools") or context.get("malware"):
        notes.append(phrase(sequence_index, NO_ATTRIBUTION_PHRASES, salt=53) + ".")
    inferred = [
        p for p in context.get("provenance", []) if isinstance(p, dict) and p.get("inferred")
    ]
    if inferred:
        notes.append(phrase(sequence_index, INFERRED_CONTEXT_PHRASES, salt=59) + ".")
    if not notes:
        notes.append(
            seeded_choice(
                sequence_index,
                [
                    "Assessment is limited to the supplied IDS, SHAP, and graph context.",
                    "The conclusion should remain tied to the provided evidence.",
                    "No claim should go beyond the supplied TrustSecAI context.",
                ],
            )
        )
    return notes


def classifier_evidence(
    shap: Mapping[str, Any], sequence_index: int = 0, max_items: int | None = None
) -> List[str]:
    """Turn SHAP features into compact evidence strings."""

    limit = max_items if max_items is not None else 2 + (sequence_index % 3)
    rows = []
    features = list(shap.get("top_features", []))
    if features:
        start = sequence_index % len(features)
        features = features[start:] + features[:start]
    for feature in features[:limit]:
        shap_value = feature.get("shap_value")
        if isinstance(shap_value, float):
            shap_value = round(shap_value, 4)
        rows.append(
            f"{feature.get('feature')}={feature.get('value')} ({feature.get('contribution_strength', 'observed')} contribution, SHAP {shap_value})"
        )
    return rows


def generate_output(
    template_id: str,
    ids: Mapping[str, Any],
    shap: Mapping[str, Any],
    context: Mapping[str, Any],
    difficulty: str,
    variant: str,
    sequence_index: int,
) -> Dict[str, Any]:
    """Generate a deterministic target response for one prompt template."""

    prediction = str(ids["prediction"])
    confidence = float(ids["confidence"])
    technique = get_technique(context)
    tactics = get_tactics(context)
    mitigations = get_mitigations(context)
    capec = list(context.get("capec") or [])
    cwes = list(context.get("cwes") or [])
    cves = list(context.get("cves") or [])
    products = list(context.get("products") or [])
    references = list(context.get("references") or [])
    detection = list(context.get("detection_guidance") or [])
    severity = severity_from_context(context, confidence)
    conf_band = confidence_band(confidence)
    mapping = base_mapping(context)
    uncertainties = uncertainty_notes(context, confidence, sequence_index)
    style = style_for(sequence_index)
    persona = persona_for(sequence_index)
    confidence_note = confidence_phrase(confidence, sequence_index)
    graph_note = phrase(sequence_index, GRAPH_CONTEXT_PHRASES, salt=37) + "."
    flow = analyst_flow(prediction, technique, confidence, shap, context, sequence_index)
    collection_action = phrase(sequence_index, COLLECTION_ACTIONS, salt=11)
    risk_phrase = phrase(sequence_index, RISK_PHRASES, salt=17)

    if variant == "negative":
        uncertainties = [
            "Do not make unsupported conclusions beyond the supplied graph context.",
            *uncertainties,
        ]
    if variant == "agreement":
        uncertainties = [
            (
                "Evidence alignment is strong: the classifier label and retrieved ATT&CK context point to the same mapped behavior."
                if confidence >= 0.8
                else "Evidence alignment is limited because classifier confidence is weak; analyst review should compare the graph mapping with direct telemetry."
            ),
            *uncertainties,
        ]

    if template_id == "incident_report":
        return {
            "title": "Security Incident Assessment",
            "primary_assessment": (
                f"{persona['opening']}. {style['opening']}: TrustSecAI identified {prediction} with "
                f"{confidence_percent(confidence)} classifier confidence. {style['assessment']}: the retrieved graph context maps the "
                f"label to {technique.get('id')} ({technique.get('name')}). {confidence_note}"
            ),
            "analyst_reasoning_flow": flow,
            "classifier_evidence": classifier_evidence(shap, sequence_index),
            "attack_mapping": [mapping],
            "threat_context": [
                f"{style['evidence']}: tactics available: {', '.join(names_of(tactics)) or 'none supplied'}.",
                f"CAPEC context: {', '.join(ids_of(capec)) or 'none supplied'}.",
                f"Detection guidance entries available: {len(detection)}. {graph_note}",
                f"Operational risk: {risk_phrase}.",
            ],
            "candidate_vulnerabilities": [
                {
                    "cve_id": item.get("id"),
                    "name": item.get("name"),
                    "note": "Candidate context from graph retrieval; asset exposure is not confirmed.",
                }
                for item in cves[:5]
            ],
            "recommended_actions": [
                f"{style['action']}: review {m.get('id')} ({m.get('name')}) for applicability."
                for m in mitigations[:3]
            ],
            "detection_recommendations": [
                f"Correlate the alert with host and network telemetry; first check: {collection_action}.",
                "Use retrieved detection guidance as a triage aid, not as confirmation of compromise.",
            ],
            "uncertainties": uncertainties,
            "severity": severity,
            "confidence": conf_band,
        }

    if template_id == "threat_assessment":
        return {
            "threat_summary": (
                f"{style['opening']}: {prediction} is associated with {technique.get('name')} "
                f"({technique.get('id')}) in the supplied graph context. {shap_narrative(shap, sequence_index)} {graph_note}"
            ),
            "likely_objective": (
                first_description(tactics[0], 180)
                if tactics
                else "Objective cannot be determined from supplied tactics."
            ),
            "mapped_technique": {
                "attack_id": technique.get("id"),
                "name": technique.get("name"),
            },
            "tactics": [{"id": t.get("id"), "name": t.get("name")} for t in tactics],
            "risk_drivers": [
                f"{style['evidence']}: {len(capec)} CAPEC pattern(s) retrieved.",
                f"{style['assessment']}: {len(cves)} candidate CVE(s) are available for triage, not confirmation.",
                f"The classifier confidence is {confidence_percent(confidence)} ({conf_band}). {confidence_note}",
                f"Risk framing: {risk_phrase}.",
                f"Investigation focus: {persona['focus']}.",
            ],
            "evidence": classifier_evidence(shap, sequence_index, max_items=3),
            "uncertainties": uncertainties,
        }

    if template_id == "mitigation_recommendation":
        return {
            "immediate_actions": [
                f"{style['opening']}: validate whether the observed traffic is consistent with {technique.get('id')} ({technique.get('name')}); {persona['action']}.",
                f"Preserve network-flow and host evidence for analyst review; start by checking whether to {collection_action}.",
            ],
            "hardening_actions": [
                f"{style['action']}: {phrase(sequence_index + idx, MITIGATION_VERBS, salt=5)} {m.get('id')} ({m.get('name')}) where it matches the environment."
                for idx, m in enumerate(mitigations[:4])
            ],
            "detection_and_validation": [
                compact_text(d.get("properties", {}).get("description") or d.get("name"), 220)
                for d in detection[:2]
            ],
            "mapped_mitigations": [
                {"id": m.get("id"), "name": m.get("name")} for m in mitigations[:5]
            ],
            "rationale": [
                f"{style['evidence']}: recommendations are grounded in mapped technique {technique.get('id')}.",
                shap_narrative(shap, sequence_index),
                f"{style['assessment']}: {graph_note}",
                "Mitigation priority should follow the mapped behavior, local exposure, and control applicability.",
            ],
            "limitations": uncertainties,
        }

    if template_id == "executive_summary":
        return {
            "summary": (
                f"{style['opening']}: TrustSecAI flagged activity as {prediction}. The graph "
                f"context links the alert to {technique.get('name')} ({technique.get('id')}); "
                f"current severity is {severity}. The classifier confidence is {confidence_percent(confidence)}. {confidence_note}"
            ),
            "severity": severity,
            "business_impact": (
                f"{risk_phrase}. Business impact should be judged by asset exposure, service criticality, and recurrence."
            ),
            "confidence": conf_band,
            "next_steps": [
                f"Confirm the alert with network and host telemetry; specifically, {collection_action}.",
                f"Review mapped mitigations and detection guidance. {graph_note}",
            ],
        }

    if template_id == "attack_mapping":
        return {
            "ids_prediction": prediction,
            "attack_mapping": mapping,
            "mitigations": [{"id": m.get("id"), "name": m.get("name")} for m in mitigations[:4]],
            "detection_guidance": [
                {"id": d.get("id"), "name": d.get("name")} for d in detection[:3]
            ],
            "provenance": list(context.get("provenance", []))[:8],
            "mapping_confidence": conf_band,
            "caveats": [
                f"Classifier confidence is {confidence_percent(confidence)}.",
                shap_narrative(shap, sequence_index),
                confidence_note,
                graph_note,
                *uncertainties,
            ],
        }

    if template_id == "security_analyst_reasoning":
        return {
            "reasoning": [
                {
                    "step": 1,
                    "claim": f"{style['opening']}: the classifier predicted {prediction}. {confidence_note}",
                    "evidence": [shap_narrative(shap, sequence_index), *classifier_evidence(shap, sequence_index, max_items=3)],
                },
                {
                    "step": 2,
                    "claim": f"{style['evidence']}: graph retrieval links the label to {technique.get('id')} ({technique.get('name')}).",
                    "evidence": [mapping],
                },
                {
                    "step": 3,
                    "claim": f"{style['assessment']}: vulnerability context is candidate-only unless asset exposure is confirmed.",
                    "evidence": ids_of(cves[:5]),
                },
                {
                    "step": 4,
                    "claim": f"{style['action']}: {collection_action}.",
                    "evidence": ["Recommended as additional telemetry collection, not graph-derived proof."],
                },
            ],
            "classifier_interpretation": classifier_evidence(shap, sequence_index),
            "graph_interpretation": [
                f"{len(mitigations)} mitigation(s), {len(capec)} CAPEC pattern(s), "
                f"and {len(cves)} candidate CVE(s) were retrieved. {graph_note}"
            ],
            "inferred_context": [
                p for p in context.get("provenance", []) if isinstance(p, dict) and p.get("inferred")
            ][:5],
            "uncertainties": uncertainties,
        }

    if template_id == "vulnerability_summary":
        return {
            "weaknesses": [{"id": item.get("id"), "name": item.get("name")} for item in cwes],
            "candidate_cves": [
                {
                    "id": item.get("id"),
                    "name": item.get("name"),
                    "severity": item.get("properties", {}).get("severity"),
                    "cvss_base_score": item.get("properties", {}).get("cvss_base_score"),
                }
                for item in cves[:8]
            ],
            "affected_products": [
                {"id": item.get("id"), "name": item.get("name")} for item in products[:8]
            ],
            "cvss_summary": (
                f"{style['evidence']}: {len(cves)} candidate CVE(s) are present in the supplied context."
                if cves
                else f"{style['evidence']}: no CVEs are present in the supplied context."
            ),
            "asset_exposure_note": (
                f"{style['assessment']}: treat CVEs as candidate context because no asset inventory evidence is supplied. {graph_note}"
            ),
            "references": [
                {"id": item.get("id"), "name": item.get("name")} for item in references[:8]
            ],
        }

    if template_id == "evidence_review":
        return {
            "directly_supported": [
                f"IDS prediction: {prediction}",
                f"Mapped ATT&CK technique: {technique.get('id')} ({technique.get('name')})",
                f"Available provenance entries: {len(context.get('provenance', []))}",
                f"{style['evidence']}: {confidence_note}",
                shap_narrative(shap, sequence_index),
                f"Analyst focus: {persona['focus']}.",
            ],
            "inferred": [
                "CVE relevance is candidate context when reached through CWE or inferred graph edges."
            ]
            if cves
            else [],
            "unsupported_or_missing": uncertainties,
            "recommended_evidence_to_collect": [
                "asset inventory and exposed service data",
                "packet captures or flow records around the alert window",
                "host logs for correlated activity",
                f"{style['action']}: {collection_action}.",
                "Compare GraphRAG context against direct environment evidence.",
            ],
            "overall_confidence": conf_band,
        }

    raise ValueError(f"Unsupported template: {template_id}")


def make_multiturn_output(
    ids: Mapping[str, Any],
    shap: Mapping[str, Any],
    context: Mapping[str, Any],
    sequence_index: int,
) -> Dict[str, Any]:
    """Create a grounded multi-turn training output."""

    technique = get_technique(context)
    mitigations = get_mitigations(context)
    style = style_for(sequence_index)
    confidence_note = confidence_phrase(float(ids["confidence"]), sequence_index)
    collection_action = phrase(sequence_index, COLLECTION_ACTIONS, salt=23)
    return {
        "messages": [
            {
                "role": "assistant",
                "content": {
                    "incident_report": (
                        f"{style['opening']}: the alert is {ids['prediction']} and the graph "
                        f"context maps it to {technique.get('id')} ({technique.get('name')}). "
                        f"The classifier confidence is {confidence_percent(float(ids['confidence']))}. "
                        f"{confidence_note}"
                    ),
                    "evidence": classifier_evidence(shap, sequence_index, max_items=3),
                    "shap_summary": shap_narrative(shap, sequence_index),
                },
            },
            {
                "role": "assistant",
                "content": {
                    "evidence_explanation": (
                        f"{style['evidence']}: the explanation combines classifier SHAP features "
                        "with graph provenance. GraphRAG provides contextual evidence, not proof "
                        "of compromise."
                    ),
                    "mapped_technique": base_mapping(context),
                    "reasoning_flow": analyst_flow(
                        str(ids["prediction"]),
                        technique,
                        float(ids["confidence"]),
                        shap,
                        context,
                        sequence_index,
                    ),
                },
            },
            {
                "role": "assistant",
                "content": {
                    "mitigation_discussion": [
                        {
                            "id": m.get("id"),
                            "name": m.get("name"),
                            "analyst_note": f"{phrase(sequence_index + idx, MITIGATION_VERBS, salt=7)} this control if it fits the affected environment.",
                        }
                        for idx, m in enumerate(mitigations[:3])
                    ],
                    "next_collection_step": collection_action,
                    "caveats": [
                        f"{style['assessment']}: validate recommendations against the actual environment.",
                        *uncertainty_notes(context, float(ids["confidence"]), sequence_index),
                    ],
                },
            },
        ]
    }
