"""Parse the latest Enterprise ATT&CK STIX bundle for TrustSecAI graph ingestion."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.utils.paths import DATASETS_DIR


ENTERPRISE_ATTACK_PATH = DATASETS_DIR / "ATTACK" / "attack-stix-data-master" / "enterprise-attack" / "enterprise-attack.json"


@dataclass
class AttackParseResult:
    """Parsed ATT&CK graph payload."""

    attack_version: str
    source_file: str
    ingested_at: str
    nodes: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    relationships: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    skipped_objects: list[dict[str, str]] = field(default_factory=list)
    revoked_objects: list[str] = field(default_factory=list)
    deprecated_objects: list[str] = field(default_factory=list)


def _external_references(obj: dict[str, Any]) -> list[dict[str, Any]]:
    return obj.get("external_references") or []


def get_external_id(obj: dict[str, Any]) -> str | None:
    """Return ATT&CK external ID from a STIX object."""

    for ref in _external_references(obj):
        external_id = ref.get("external_id")
        if external_id:
            return normalize_attack_id(str(external_id))
    return None


def get_external_url(obj: dict[str, Any]) -> str | None:
    """Return first external reference URL."""

    for ref in _external_references(obj):
        url = ref.get("url")
        if url:
            return str(url)
    return None


def normalize_attack_id(value: str) -> str:
    """Normalize ATT&CK IDs, adding T prefix for technique-like numeric IDs."""

    cleaned = value.strip()
    if cleaned and cleaned[0].isdigit():
        return f"T{cleaned}"
    return cleaned


def list_value(value: Any) -> list[str]:
    """Normalize a STIX scalar/list value to list[str]."""

    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def common_properties(obj: dict[str, Any], source_file: str, ingested_at: str) -> dict[str, Any]:
    """Common ATT&CK node properties with provenance."""

    return {
        "stix_id": obj.get("id"),
        "attack_id": get_external_id(obj),
        "name": obj.get("name"),
        "description": obj.get("description"),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
        "revoked": bool(obj.get("revoked", False)),
        "deprecated": bool(obj.get("x_mitre_deprecated", False)),
        "source": "MITRE ATT&CK Enterprise",
        "source_file": source_file,
        "raw_id": obj.get("id"),
        "ingested_at": ingested_at,
        "url": get_external_url(obj),
    }


def parse_tactic(obj: dict[str, Any], source_file: str, ingested_at: str) -> dict[str, Any]:
    """Parse an ATT&CK tactic."""

    props = common_properties(obj, source_file, ingested_at)
    props["short_name"] = obj.get("x_mitre_shortname")
    return props


def parse_attack_pattern(obj: dict[str, Any], source_file: str, ingested_at: str) -> tuple[str, dict[str, Any]]:
    """Parse an ATT&CK attack-pattern as Technique or SubTechnique."""

    label = "SubTechnique" if obj.get("x_mitre_is_subtechnique") else "Technique"
    props = common_properties(obj, source_file, ingested_at)
    props["platforms"] = list_value(obj.get("x_mitre_platforms"))
    props["detection"] = obj.get("x_mitre_detection")
    props["data_sources"] = list_value(obj.get("x_mitre_data_sources"))
    props["tactic_short_names"] = [
        phase.get("phase_name")
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("phase_name")
    ]
    return label, props


def parse_detection_strategy(obj: dict[str, Any], source_file: str, ingested_at: str) -> dict[str, Any]:
    """Parse an ATT&CK detection strategy."""

    props = common_properties(obj, source_file, ingested_at)
    props["analytic_refs"] = list_value(obj.get("x_mitre_analytic_refs"))
    return props


def parse_campaign(obj: dict[str, Any], source_file: str, ingested_at: str) -> dict[str, Any]:
    """Parse an ATT&CK campaign."""

    props = common_properties(obj, source_file, ingested_at)
    props["aliases"] = list_value(obj.get("aliases"))
    props["first_seen"] = obj.get("first_seen")
    props["last_seen"] = obj.get("last_seen")
    return props


def parse_named_actor(obj: dict[str, Any], source_file: str, ingested_at: str) -> dict[str, Any]:
    """Parse group, malware, tool, or mitigation-like ATT&CK objects."""

    props = common_properties(obj, source_file, ingested_at)
    props["aliases"] = list_value(obj.get("aliases"))
    props["platforms"] = list_value(obj.get("x_mitre_platforms"))
    return props


def relationship_properties(rel: dict[str, Any], source_file: str, ingested_at: str) -> dict[str, Any]:
    """Return normalized relationship properties."""

    return {
        "stix_relationship_id": rel.get("id"),
        "description": rel.get("description"),
        "created": rel.get("created"),
        "modified": rel.get("modified"),
        "source": "MITRE ATT&CK Enterprise",
        "source_file": source_file,
        "raw_relationship_id": rel.get("id"),
        "confidence": "source",
        "inferred": False,
        "ingested_at": ingested_at,
    }


def parse_enterprise_attack(path: Path = ENTERPRISE_ATTACK_PATH) -> AttackParseResult:
    """Parse the latest Enterprise ATT&CK bundle."""

    source_file = str(path)
    ingested_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    data = json.loads(path.read_text(encoding="utf-8"))
    objects = data.get("objects", [])
    by_stix_id = {obj.get("id"): obj for obj in objects if obj.get("id")}
    result = AttackParseResult(
        attack_version=_extract_attack_version(objects),
        source_file=source_file,
        ingested_at=ingested_at,
        nodes={label: [] for label in ("Technique", "SubTechnique", "Tactic", "Mitigation", "Group", "Malware", "Tool", "Campaign", "DetectionStrategy")},
        relationships={rtype: [] for rtype in ("HAS_TACTIC", "SUBTECHNIQUE_OF", "MITIGATED_BY", "USES_TECHNIQUE", "USES_TOOL", "USES_MALWARE", "ATTRIBUTED_TO", "DETECTED_BY")},
    )

    stix_to_label: dict[str, str] = {}

    for obj in objects:
        obj_type = obj.get("type")
        stix_id = obj.get("id")
        if obj.get("revoked"):
            result.revoked_objects.append(stix_id)
        if obj.get("x_mitre_deprecated"):
            result.deprecated_objects.append(stix_id)

        if obj_type == "attack-pattern":
            label, props = parse_attack_pattern(obj, source_file, ingested_at)
        elif obj_type == "x-mitre-tactic":
            label, props = "Tactic", parse_tactic(obj, source_file, ingested_at)
        elif obj_type == "course-of-action":
            label, props = "Mitigation", parse_named_actor(obj, source_file, ingested_at)
        elif obj_type == "intrusion-set":
            label, props = "Group", parse_named_actor(obj, source_file, ingested_at)
        elif obj_type == "malware":
            label, props = "Malware", parse_named_actor(obj, source_file, ingested_at)
        elif obj_type == "tool":
            label, props = "Tool", parse_named_actor(obj, source_file, ingested_at)
        elif obj_type == "campaign":
            label, props = "Campaign", parse_campaign(obj, source_file, ingested_at)
        elif obj_type == "x-mitre-detection-strategy":
            label, props = "DetectionStrategy", parse_detection_strategy(obj, source_file, ingested_at)
        else:
            continue

        if not props.get("stix_id"):
            result.skipped_objects.append({"id": str(stix_id), "reason": "missing stix id"})
            continue

        result.nodes[label].append(props)
        stix_to_label[props["stix_id"]] = label

    _build_has_tactic_relationships(result)
    _build_stix_relationships(objects, by_stix_id, stix_to_label, result, source_file, ingested_at)
    return result


def _extract_attack_version(objects: list[dict[str, Any]]) -> str:
    """Best-effort ATT&CK collection version extraction."""

    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            return str(obj.get("x_mitre_version") or obj.get("name") or "unknown")
    return "unknown"


def _build_has_tactic_relationships(result: AttackParseResult) -> None:
    """Build Technique/SubTechnique to Tactic relationships from kill-chain phases."""

    tactic_by_short_name = {
        node.get("short_name"): node
        for node in result.nodes.get("Tactic", [])
        if node.get("short_name")
    }
    for label in ("Technique", "SubTechnique"):
        for node in result.nodes[label]:
            for tactic_short_name in node.get("tactic_short_names", []):
                tactic = tactic_by_short_name.get(tactic_short_name)
                if not tactic:
                    result.warnings.append(f"Missing tactic for phase {tactic_short_name} on {node.get('attack_id')}")
                    continue
                result.relationships["HAS_TACTIC"].append(
                    {
                        "source_id": node["stix_id"],
                        "target_id": tactic["stix_id"],
                        "kill_chain_name": "mitre-attack",
                        "source": "MITRE ATT&CK Enterprise",
                        "source_file": result.source_file,
                        "raw_relationship_id": f"{node['stix_id']}:{tactic_short_name}",
                        "confidence": "source",
                        "inferred": False,
                        "ingested_at": result.ingested_at,
                    }
                )


def _build_stix_relationships(
    objects: list[dict[str, Any]],
    by_stix_id: dict[str, dict[str, Any]],
    stix_to_label: dict[str, str],
    result: AttackParseResult,
    source_file: str,
    ingested_at: str,
) -> None:
    """Convert ATT&CK STIX relationships into approved graph relationships."""

    for rel in objects:
        if rel.get("type") != "relationship":
            continue
        rel_type = rel.get("relationship_type")
        source_ref = rel.get("source_ref")
        target_ref = rel.get("target_ref")
        source_label = stix_to_label.get(source_ref)
        target_label = stix_to_label.get(target_ref)
        source_obj = by_stix_id.get(source_ref, {})
        target_obj = by_stix_id.get(target_ref, {})
        props = relationship_properties(rel, source_file, ingested_at)

        if rel_type == "subtechnique-of" and source_label == "SubTechnique" and target_label == "Technique":
            result.relationships["SUBTECHNIQUE_OF"].append({"source_id": source_ref, "target_id": target_ref, **props})
        elif rel_type == "mitigates" and source_label == "Mitigation" and target_label in {"Technique", "SubTechnique"}:
            result.relationships["MITIGATED_BY"].append({"source_id": target_ref, "target_id": source_ref, **props})
        elif rel_type == "detects" and source_label == "DetectionStrategy" and target_label in {"Technique", "SubTechnique"}:
            result.relationships["DETECTED_BY"].append({"source_id": target_ref, "target_id": source_ref, **props})
        elif rel_type == "uses":
            _append_uses_relationship(result, source_ref, target_ref, source_label, target_label, source_obj, target_obj, props)
        elif rel_type == "attributed-to" and source_label == "Campaign" and target_label == "Group":
            result.relationships["ATTRIBUTED_TO"].append({"source_id": source_ref, "target_id": target_ref, **props})


def _append_uses_relationship(
    result: AttackParseResult,
    source_ref: str,
    target_ref: str,
    source_label: str | None,
    target_label: str | None,
    source_obj: dict[str, Any],
    target_obj: dict[str, Any],
    props: dict[str, Any],
) -> None:
    """Append approved USES relationships."""

    if source_label not in {"Group", "Malware", "Tool", "Campaign"}:
        return
    if target_label in {"Technique", "SubTechnique"}:
        result.relationships["USES_TECHNIQUE"].append({"source_id": source_ref, "target_id": target_ref, **props})
    elif target_label == "Tool" and source_label in {"Group", "Campaign"}:
        result.relationships["USES_TOOL"].append({"source_id": source_ref, "target_id": target_ref, **props})
    elif target_label == "Malware" and source_label in {"Group", "Campaign"}:
        result.relationships["USES_MALWARE"].append({"source_id": source_ref, "target_id": target_ref, **props})


def parse_args() -> argparse.Namespace:
    """Parse CLI args."""

    parser = argparse.ArgumentParser(description="Parse Enterprise ATT&CK STIX bundle.")
    parser.add_argument("--input", type=Path, default=ENTERPRISE_ATTACK_PATH)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    parsed = parse_enterprise_attack(args.input)
    print(json.dumps({
        "attack_version": parsed.attack_version,
        "nodes": {key: len(value) for key, value in parsed.nodes.items()},
        "relationships": {key: len(value) for key, value in parsed.relationships.items()},
        "warnings": len(parsed.warnings),
        "skipped_objects": len(parsed.skipped_objects),
        "revoked_objects": len(parsed.revoked_objects),
        "deprecated_objects": len(parsed.deprecated_objects),
    }, indent=2))


if __name__ == "__main__":
    main()

