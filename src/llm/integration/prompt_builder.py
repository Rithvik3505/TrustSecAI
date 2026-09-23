"""Prompt construction for TrustSecAI secondary LLM assessment."""

from __future__ import annotations

import json
from typing import Any


SYSTEM_PROMPT = (
    "You are TrustSecAI, a security incident analysis assistant. Use only supplied "
    "classifier, SHAP, and graph context. Do not invent CVEs, CWEs, ATT&CK IDs, "
    "asset exposure, attribution, or vulnerability confirmation. Group, tool, and "
    "malware context is usage context only, not attribution. Your output is a "
    "secondary assessment for a SOC analyst."
)

COMPACT_OUTPUT_KEYS = [
    "ids_label",
    "sample_id",
    "classifier_evidence",
    "shap_evidence",
    "graph_interpretation",
    "limitations",
    "provenance_summary",
    "recommended_actions",
]


def extract_supplied_context(generation_row: dict[str, Any]) -> dict[str, Any]:
    """Extract the JSON TrustSecAI context embedded in an SFT prompt if present."""

    prompt = generation_row.get("prompt", "")
    marker = "Supplied TrustSecAI context:"
    if marker not in prompt:
        return {}
    start = prompt.find("{", prompt.find(marker))
    if start < 0:
        return {}
    depth = 0
    end = -1
    for index, char in enumerate(prompt[start:], start=start):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                end = index + 1
                break
    if end < 0:
        return {}
    try:
        return json.loads(prompt[start:end])
    except json.JSONDecodeError:
        return {}


def build_compact_prompt(
    classifier_evidence: dict[str, Any],
    shap_evidence: dict[str, Any],
    graph_context: dict[str, Any],
    task_type: str = "secondary_assessment",
) -> str:
    """Build a compact prompt for future live LoRA inference."""

    payload = {
        "task_type": task_type,
        "classifier": classifier_evidence,
        "shap": shap_evidence,
        "graph_context": graph_context,
        "constraints": {
            "use_only_supplied_evidence": True,
            "do_not_invent_security_ids": True,
            "group_tool_malware_not_attribution": True,
            "graph_context_is_contextual_not_proof": True,
            "output_is_secondary_assessment": True,
        },
    }
    return (
        f"System:\n{SYSTEM_PROMPT}\n\n"
        "User:\nProduce a compact TrustSecAI secondary assessment from this evidence.\n"
        f"{json.dumps(payload, indent=2, ensure_ascii=False)}\n\n"
        "Return compact JSON with only these keys: "
        f"{', '.join(COMPACT_OUTPUT_KEYS)}."
    )

