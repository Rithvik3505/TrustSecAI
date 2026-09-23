"""Parse and normalize LoRA secondary assessment output."""

from __future__ import annotations

import json
import re
from typing import Any


NORMALIZED_KEYS = [
    "ids_label",
    "sample_id",
    "classifier_evidence",
    "shap_evidence",
    "graph_interpretation",
    "limitations",
    "provenance_summary",
    "recommended_actions",
]


def _strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?", "", stripped, flags=re.IGNORECASE).strip()
        stripped = re.sub(r"```$", "", stripped).strip()
    return stripped


def parse_lora_output(raw_output: str) -> dict[str, Any]:
    """Parse LoRA output as JSON when possible, otherwise return normalized text."""

    cleaned = _strip_code_fence(raw_output or "")
    parsed: dict[str, Any] = {}
    parse_ok = False
    if cleaned.startswith("{"):
        try:
            loaded = json.loads(cleaned)
            if isinstance(loaded, dict):
                parsed = loaded
                parse_ok = True
        except json.JSONDecodeError:
            parse_ok = False

    normalized = {key: parsed.get(key) for key in NORMALIZED_KEYS}
    normalized["parse_ok"] = parse_ok
    normalized["raw_output"] = raw_output or ""
    if not parse_ok:
        normalized["graph_interpretation"] = normalized["graph_interpretation"] or cleaned
        normalized["limitations"] = normalized["limitations"] or ["Output was not valid JSON; review raw_output before relying on structure."]
    return normalized

