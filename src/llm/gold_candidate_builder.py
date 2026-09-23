"""Build a grounded gold-candidate SFT set for TrustSecAI.

This module intentionally avoids scaling by paraphrase. It creates examples from
the evidence that is already present in TrustSecAI artifacts and records when
important evidence, such as local SHAP or classifier confidence, is unavailable.
"""

from __future__ import annotations

import csv
import difflib
import hashlib
import json
import math
import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "artifacts"
REPORTS = ROOT / "reports"
GOLD_DIR = ARTIFACTS / "gold_candidates"
CONTEXT_DIR = GOLD_DIR / "contexts"
REVIEW_DIR = GOLD_DIR / "review_samples"
RANDOM_SEED = 42

SUPPORTED_RETRIEVAL_FILES = {
    "Bot": "Bot.json",
    "DDoS": "DDoS.json",
    "FTP-Patator": "FTP_Patator.json",
    "PortScan": "PortScan.json",
    "Web Attack - Sql Injection": "Web_Attack___Sql_Injection.json",
}

TASK_FAMILIES = {
    "soc_incident_assessment": 0.25,
    "attack_mapping": 0.15,
    "mitigation_detection": 0.15,
    "uncertainty_evidence_gap": 0.10,
    "executive_summary": 0.10,
    "threat_hunting_followup": 0.10,
    "vulnerability_context": 0.10,
    "multi_turn_analyst_interaction": 0.05,
}

DIFFICULTIES = ["easy", "medium", "hard", "expert"]
GRAPH_VARIANTS = [
    "full",
    "focused",
    "sparse",
    "mitigation_focus",
    "usage_context",
    "vulnerability_focus",
    "detection_focus",
    "alternate_entities",
]
TASK_SCENARIOS = {
    "soc_incident_assessment": [
        "initial_triage",
        "escalation_decision",
        "secondary_review",
        "containment_readiness",
        "evidence_prioritization",
    ],
    "attack_mapping": ["mapping_validation", "tactic_context", "analyst_explanation"],
    "mitigation_detection": ["control_review", "detection_tuning", "operational_hardening"],
    "uncertainty_evidence_gap": ["low_evidence_review", "missing_telemetry", "unsupported_claim_filter"],
    "executive_summary": ["business_risk", "operations_brief", "leadership_action"],
    "threat_hunting_followup": ["hypothesis_generation", "telemetry_pivot", "alternate_explanation"],
    "vulnerability_context": ["cve_review", "product_exposure_check", "weakness_context"],
    "multi_turn_analyst_interaction": ["triage_followup", "mitigation_followup"],
}


@dataclass(frozen=True)
class SourceExample:
    """A real evidence context from which SFT tasks may be derived."""

    base_context_id: str
    ids_label: str
    confidence: float | None
    confidence_band: str
    shap: dict[str, Any] | None
    graph: dict[str, Any]
    graph_variant: str
    evidence_conditions: list[str]
    provenance_type: str
    source_artifacts: list[str]
    context_path: str


def read_json(path: Path) -> Any:
    """Read UTF-8 JSON from disk."""

    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any, pretty: bool = True) -> None:
    """Write UTF-8 JSON to disk."""

    path.parent.mkdir(parents=True, exist_ok=True)
    kwargs = {"indent": 2, "ensure_ascii": False} if pretty else {"separators": (",", ":"), "ensure_ascii": False}
    path.write_text(json.dumps(obj, **kwargs), encoding="utf-8")


def slug(value: str) -> str:
    """Create a stable filesystem- and id-safe slug."""

    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def short_hash(value: str, length: int = 10) -> str:
    """Return a deterministic short hash."""

    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:length]


def confidence_band(confidence: float | None) -> str:
    """Map classifier confidence to a review band."""

    if confidence is None:
        return "unavailable"
    if confidence >= 0.9:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"


def entity_id(entity: dict[str, Any]) -> str:
    """Return the best available identifier from a graph entity."""

    return str(
        entity.get("id")
        or entity.get("attack_id")
        or entity.get("capec_id")
        or entity.get("cwe_id")
        or entity.get("cve_id")
        or entity.get("url")
        or entity.get("name")
        or ""
    )


def entity_name(entity: dict[str, Any]) -> str:
    """Return the best available display name from a graph entity."""

    props = entity.get("properties") if isinstance(entity.get("properties"), dict) else {}
    return str(entity.get("name") or props.get("name") or entity_id(entity))


def entity_summary(entity: dict[str, Any], max_chars: int = 260) -> dict[str, Any]:
    """Compact long graph entities while preserving grounding identifiers."""

    props = entity.get("properties") if isinstance(entity.get("properties"), dict) else {}
    desc = entity.get("description") or props.get("description") or props.get("summary") or ""
    desc = " ".join(str(desc).split())
    if len(desc) > max_chars:
        desc = desc[: max_chars - 3].rsplit(" ", 1)[0] + "..."
    out: dict[str, Any] = {
        "id": entity_id(entity),
        "name": entity_name(entity),
    }
    if desc:
        out["summary"] = desc
    for key in ["rank_score", "distance", "severity", "cvss_score", "likelihood", "abstraction"]:
        if key in entity:
            out[key] = entity[key]
        elif key in props:
            out[key] = props[key]
    provenance = entity.get("provenance")
    if provenance:
        out["provenance"] = provenance[:3]
    return out


def get_collection(graph: dict[str, Any], name: str) -> list[dict[str, Any]]:
    """Get a list collection from a retrieval graph context."""

    value = graph.get(name, [])
    return value if isinstance(value, list) else []


def compact_graph_context(graph: dict[str, Any], variant: str) -> dict[str, Any]:
    """Create a compact, deterministic graph context variant."""

    attack = graph.get("attack") if isinstance(graph.get("attack"), dict) else {}
    profiles = {
        "full": {"mitigations": (0, 4), "groups": (0, 3), "tools": (0, 3), "malware": (0, 3), "cves": (0, 5), "products": (0, 4), "references": (0, 4), "capec": (0, 1), "cwes": (0, 2)},
        "focused": {"mitigations": (0, 2), "groups": (0, 1), "tools": (0, 1), "malware": (0, 1), "cves": (0, 2), "products": (0, 2), "references": (0, 2), "capec": (0, 1), "cwes": (0, 1)},
        "sparse": {"mitigations": (0, 1), "groups": (0, 0), "tools": (0, 0), "malware": (0, 0), "cves": (0, 0), "products": (0, 0), "references": (0, 0), "capec": (0, 0), "cwes": (0, 0)},
        "mitigation_focus": {"mitigations": (1, 4), "groups": (0, 0), "tools": (0, 0), "malware": (0, 0), "cves": (0, 0), "products": (0, 0), "references": (0, 1), "capec": (0, 0), "cwes": (0, 0)},
        "usage_context": {"mitigations": (0, 1), "groups": (2, 3), "tools": (1, 3), "malware": (1, 3), "cves": (0, 0), "products": (0, 0), "references": (0, 0), "capec": (0, 0), "cwes": (0, 0)},
        "vulnerability_focus": {"mitigations": (0, 1), "groups": (0, 0), "tools": (0, 0), "malware": (0, 0), "cves": (2, 5), "products": (2, 4), "references": (2, 4), "capec": (0, 1), "cwes": (0, 2)},
        "detection_focus": {"mitigations": (0, 2), "groups": (0, 0), "tools": (0, 0), "malware": (0, 0), "cves": (0, 0), "products": (0, 0), "references": (0, 1), "capec": (0, 0), "cwes": (0, 0)},
        "alternate_entities": {"mitigations": (2, 3), "groups": (5, 3), "tools": (5, 3), "malware": (5, 3), "cves": (5, 5), "products": (5, 4), "references": (5, 4), "capec": (0, 1), "cwes": (1, 1)},
    }
    limit = profiles[variant]

    def selected(collection: str) -> list[dict[str, Any]]:
        start, count = limit[collection]
        values = get_collection(graph, collection)
        return values[start : start + count]

    def selected_attack(collection: str) -> list[dict[str, Any]]:
        start, count = limit[collection]
        values = attack.get(collection, [])
        return values[start : start + count]
    compact: dict[str, Any] = {
        "prediction": graph.get("prediction"),
        "retrieval": graph.get("retrieval", {}),
        "attack": {
            "technique": entity_summary(attack.get("technique", {})) if isinstance(attack.get("technique"), dict) else {},
            "tactics": [entity_summary(x) for x in attack.get("tactics", [])[:2]],
            "mitigations": [entity_summary(x) for x in selected_attack("mitigations")],
        },
        "capec": [entity_summary(x) for x in selected("capec")],
        "cwes": [entity_summary(x) for x in selected("cwes")],
        "cves": [entity_summary(x) for x in selected("cves")],
        "products": [entity_summary(x) for x in selected("products")],
        "references": [entity_summary(x) for x in selected("references")],
        "groups": [entity_summary(x) for x in selected("groups")],
        "tools": [entity_summary(x) for x in selected("tools")],
        "malware": [entity_summary(x) for x in selected("malware")],
        "detection_guidance": [entity_summary(x) for x in get_collection(graph, "detection_guidance")[:1]],
        "provenance": graph.get("provenance", [])[:60],
    }
    return compact


def summarize_graph(graph: dict[str, Any]) -> dict[str, Any]:
    """Summarize important graph coverage flags."""

    attack = graph.get("attack", {})
    technique = attack.get("technique") if isinstance(attack, dict) else {}
    tactic_list = attack.get("tactics", []) if isinstance(attack, dict) else []
    provenance = graph.get("provenance", [])
    return {
        "prediction": graph.get("prediction"),
        "technique": entity_summary(technique) if isinstance(technique, dict) else {},
        "tactics": [entity_summary(t) for t in tactic_list],
        "mitigation_count": len(attack.get("mitigations", [])) if isinstance(attack, dict) else 0,
        "capec_count": len(get_collection(graph, "capec")),
        "cwe_count": len(get_collection(graph, "cwes")),
        "cve_count": len(get_collection(graph, "cves")),
        "product_count": len(get_collection(graph, "products")),
        "group_count": len(get_collection(graph, "groups")),
        "tool_count": len(get_collection(graph, "tools")),
        "malware_count": len(get_collection(graph, "malware")),
        "detection_guidance_count": len(get_collection(graph, "detection_guidance")),
        "provenance_count": len(provenance),
        "inferred_provenance_count": sum(1 for item in provenance if item.get("inferred")),
    }


def load_dataset_label_inventory() -> dict[str, Any]:
    """Inventory labels and source files from the cleaned inspection sample."""

    sample_path = ARTIFACTS / "processed" / "cleaned_cicids_sample.csv"
    labels: Counter[str] = Counter()
    sources: dict[str, Counter[str]] = defaultdict(Counter)
    rows = 0
    if sample_path.exists():
        with sample_path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                rows += 1
                label = row.get("label") or row.get(" Label") or ""
                source = row.get("source_file") or "unknown"
                labels[label] += 1
                sources[label][source] += 1
    return {
        "source_artifact": str(sample_path.as_posix()),
        "sample_rows": rows,
        "labels": dict(labels.most_common()),
        "source_files_by_label": {label: dict(counter.most_common()) for label, counter in sources.items()},
        "note": "Counts are from cleaned_cicids_sample.csv for lightweight inventory; the full cleaned parquet remains available for later export.",
    }


def load_real_artifacts() -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Load retrieval contexts, SHAP explanations, and label mappings."""

    retrievals = {
        label: read_json(ARTIFACTS / "retrieval" / filename)
        for label, filename in SUPPORTED_RETRIEVAL_FILES.items()
        if (ARTIFACTS / "retrieval" / filename).exists()
    }
    shap_samples = read_json(ARTIFACTS / "shap" / "sample_explanations.json")
    mappings = read_json(ARTIFACTS / "attack_label_mapping.json")
    return retrievals, shap_samples, mappings


def build_evidence_inventory() -> dict[str, Any]:
    """Create a transparent inventory of evidence available for the gold set."""

    retrievals, shap_samples, mappings = load_real_artifacts()
    shap_by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sample in shap_samples:
        shap_by_label[sample.get("multiclass_label", "unknown")].append(sample)

    retrieval_inventory = {}
    for label, graph in retrievals.items():
        summary = summarize_graph(graph)
        retrieval_inventory[label] = {
            **summary,
            "source_artifact": f"artifacts/retrieval/{SUPPORTED_RETRIEVAL_FILES[label]}",
            "has_direct_provenance": summary["provenance_count"] > summary["inferred_provenance_count"],
            "has_inferred_relationships": summary["inferred_provenance_count"] > 0,
            "has_cve_evidence": summary["cve_count"] > 0,
            "has_candidate_only_cve_evidence": summary["cve_count"] > 0 and summary["inferred_provenance_count"] > 0,
        }

    shap_inventory = {
        label: {
            "sample_count": len(samples),
            "confidence_values": sorted({sample.get("confidence") for sample in samples}),
            "source_files": dict(Counter(sample.get("source_file") for sample in samples)),
            "distinct_top_feature_patterns": len(
                {
                    tuple(feature.get("feature") for feature in sample.get("top_features", [])[:4])
                    for sample in samples
                }
            ),
        }
        for label, samples in sorted(shap_by_label.items())
    }

    supported_labels = sorted(set(retrievals) | set(shap_by_label))
    unavailable = [
        "Real local SHAP explanations are unavailable for Bot, FTP-Patator, PortScan, and Web Attack - Sql Injection in artifacts/shap/sample_explanations.json.",
        "Medium- and low-confidence classifier examples are not present in the exported local SHAP artifact; all exported local explanations have confidence 1.0.",
        "No asset ownership, exposure, or incident timeline evidence is present in the current artifacts.",
        "Threat actor attribution is unavailable; group/tool/malware nodes from ATT&CK are contextual usage evidence only.",
        "Additional retrieval neighborhoods beyond the saved deterministic retrieval JSON files were not synthesized.",
    ]

    return {
        "created_at": date.today().isoformat(),
        "currently_available_evidence": {
            "cicids_label_inventory": load_dataset_label_inventory(),
            "retrieval_contexts": retrieval_inventory,
            "local_shap_explanations": shap_inventory,
            "attack_label_mappings": {
                label: {
                    "attack_id": value.get("attack_id"),
                    "attack_name": value.get("attack_name"),
                    "mapping_confidence": value.get("confidence"),
                }
                for label, value in sorted(mappings.items())
            },
        },
        "evidence_exportable_from_existing_artifacts": {
            "retrieval_context_json": sorted(f"artifacts/retrieval/{name}" for name in SUPPORTED_RETRIEVAL_FILES.values()),
            "local_shap_json": ["artifacts/shap/sample_explanations.json"],
            "global_shap_importance": ["artifacts/shap/global_feature_importance.csv"],
            "cleaned_dataset_sample": ["artifacts/processed/cleaned_cicids_sample.csv"],
            "cleaned_dataset_full": ["artifacts/processed/cleaned_cicids.parquet"],
            "attack_label_mapping": ["artifacts/attack_label_mapping.json"],
        },
        "unavailable_evidence_not_synthesized_as_fact": unavailable,
        "gold_candidate_scope": {
            "supported_retrieval_labels": sorted(retrievals),
            "labels_with_real_local_shap": sorted(shap_by_label),
            "labels_used_for_sft_generation": sorted(retrievals),
            "reason_for_not_forcing_3000_examples": (
                "Only five deterministic retrieval contexts and three attack-label local SHAP groups are exported. "
                "The gold-candidate set therefore prioritizes base-context diversity and reviewability over target size."
            ),
        },
    }


def write_evidence_inventory(inventory: dict[str, Any]) -> None:
    """Write the evidence inventory JSON and report."""

    write_json(GOLD_DIR / "evidence_inventory.json", inventory)
    current = inventory["currently_available_evidence"]
    lines = [
        "# TrustSecAI Gold-Set Evidence Inventory",
        "",
        "This inventory distinguishes available evidence from unavailable facts that must not be synthesized.",
        "",
        "## Currently Available Evidence",
        "",
        f"- CICIDS inspection sample rows: {current['cicids_label_inventory']['sample_rows']}",
        f"- Retrieval contexts available: {len(current['retrieval_contexts'])}",
        f"- Local SHAP explanation label groups: {len(current['local_shap_explanations'])}",
        f"- ATT&CK label mappings available: {len(current['attack_label_mappings'])}",
        "",
        "## Retrieval Context Coverage",
        "",
        "| IDS label | Technique | Tactics | Mitigations | CAPEC | CWE | CVE | Products | Inferred edges | Source |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for label, item in current["retrieval_contexts"].items():
        tech = item["technique"].get("id", "")
        lines.append(
            f"| {label} | {tech} | {len(item['tactics'])} | {item['mitigation_count']} | "
            f"{item['capec_count']} | {item['cwe_count']} | {item['cve_count']} | "
            f"{item['product_count']} | {item['inferred_provenance_count']} | {item['source_artifact']} |"
        )
    lines.extend(["", "## Local SHAP Coverage", "", "| Label | Samples | Confidence values | Distinct top-feature patterns | Source files |", "|---|---:|---|---:|---|"])
    for label, item in current["local_shap_explanations"].items():
        lines.append(
            f"| {label} | {item['sample_count']} | {item['confidence_values']} | "
            f"{item['distinct_top_feature_patterns']} | {', '.join(item['source_files'])} |"
        )
    lines.extend(
        [
            "",
            "## Evidence Exportable From Existing Artifacts",
            "",
        ]
    )
    for key, values in inventory["evidence_exportable_from_existing_artifacts"].items():
        lines.append(f"- {key}: {', '.join(values)}")
    lines.extend(["", "## Unavailable Evidence Not Synthesized As Fact", ""])
    lines.extend(f"- {item}" for item in inventory["unavailable_evidence_not_synthesized_as_fact"])
    lines.extend(["", "## Generation Scope", ""])
    scope = inventory["gold_candidate_scope"]
    lines.append(f"- Labels used for SFT generation: {', '.join(scope['labels_used_for_sft_generation'])}")
    lines.append(f"- Size rationale: {scope['reason_for_not_forcing_3000_examples']}")
    (REPORTS / "gold_set_evidence_inventory.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_source_examples() -> list[SourceExample]:
    """Build diverse base contexts from existing retrieval and SHAP artifacts."""

    retrievals, shap_samples, _ = load_real_artifacts()
    shap_by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sample in shap_samples:
        shap_by_label[sample.get("multiclass_label", "unknown")].append(sample)

    examples: list[SourceExample] = []
    for label, graph in retrievals.items():
        real_shap_samples = shap_by_label.get(label, [])
        shap_options: list[dict[str, Any] | None] = real_shap_samples[:5] if real_shap_samples else [None]
        for variant in GRAPH_VARIANTS:
            compact = compact_graph_context(graph, variant)
            has_cves = bool(compact["cves"])
            has_capec = bool(compact["capec"])
            inferred_count = sum(1 for item in graph.get("provenance", []) if item.get("inferred"))
            for shap_sample in shap_options:
                confidence = float(shap_sample["confidence"]) if shap_sample and shap_sample.get("confidence") is not None else None
                conditions = [f"{variant}_retrieval_context"]
                if not shap_sample:
                    conditions.append("missing_local_shap_context")
                    conditions.append("classifier_confidence_unavailable")
                else:
                    conditions.extend(["real_local_shap_context", f"{confidence_band(confidence)}_classifier_confidence"])
                if has_cves:
                    conditions.append("cve_context_present")
                else:
                    conditions.append("no_cve_context")
                if has_capec:
                    conditions.append("capec_context_present")
                else:
                    conditions.append("no_capec_context")
                if inferred_count:
                    conditions.append("contains_inferred_graph_relationships")
                    provenance_type = "mixed_direct_and_inferred"
                else:
                    conditions.append("direct_graph_provenance")
                    provenance_type = "direct"
                source_artifacts = [f"artifacts/retrieval/{SUPPORTED_RETRIEVAL_FILES[label]}"]
                if shap_sample:
                    source_artifacts.append("artifacts/shap/sample_explanations.json")
                base = f"{label}|{variant}|{shap_sample.get('sample_id') if shap_sample else 'no-shap'}"
                base_id = f"ctx-{slug(label)}-{variant}-{short_hash(base, 8)}"
                context_path = CONTEXT_DIR / f"{base_id}.json"
                context_obj = {
                    "base_context_id": base_id,
                    "ids_label": label,
                    "classifier": {
                        "prediction": label,
                        **({"confidence": confidence} if confidence is not None else {}),
                        "confidence_band": confidence_band(confidence),
                    },
                    "shap": normalize_shap(shap_sample),
                    "graph_context": compact,
                    "evidence_conditions": conditions,
                    "provenance_type": provenance_type,
                    "source_artifacts": source_artifacts,
                }
                write_json(context_path, context_obj)
                examples.append(
                    SourceExample(
                        base_context_id=base_id,
                        ids_label=label,
                        confidence=confidence,
                        confidence_band=confidence_band(confidence),
                        shap=normalize_shap(shap_sample),
                        graph=compact,
                        graph_variant=variant,
                        evidence_conditions=conditions,
                        provenance_type=provenance_type,
                        source_artifacts=source_artifacts,
                        context_path=str(context_path.relative_to(ROOT).as_posix()),
                    )
                )
    return examples


def normalize_shap(sample: dict[str, Any] | None) -> dict[str, Any]:
    """Return compact real SHAP evidence or an explicit unavailable marker."""

    if not sample:
        return {"available": False, "top_features": []}
    features = []
    for item in sample.get("top_features", [])[:6]:
        features.append(
            {
                "feature": item.get("feature"),
                "value": round(float(item.get("value", 0.0)), 4),
                "shap_value": round(float(item.get("shap_value", 0.0)), 4),
            }
        )
    return {
        "available": True,
        "sample_id": sample.get("sample_id"),
        "true_label": sample.get("true_label"),
        "multiclass_label": sample.get("multiclass_label"),
        "prediction": sample.get("prediction"),
        "prediction_name": sample.get("prediction_name"),
        "confidence": sample.get("confidence"),
        "source_file": sample.get("source_file"),
        "top_features": features,
    }


def write_source_examples(examples: list[SourceExample]) -> None:
    """Write the source-example manifest."""

    GOLD_DIR.mkdir(parents=True, exist_ok=True)
    with (GOLD_DIR / "source_examples.jsonl").open("w", encoding="utf-8") as handle:
        for example in examples:
            handle.write(
                json.dumps(
                    {
                        "base_context_id": example.base_context_id,
                        "ids_label": example.ids_label,
                        "confidence": example.confidence,
                        "confidence_band": example.confidence_band,
                        "graph_variant": example.graph_variant,
                        "evidence_conditions": example.evidence_conditions,
                        "provenance_type": example.provenance_type,
                        "source_artifacts": example.source_artifacts,
                        "context_path": example.context_path,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )


def shap_phrase(shap: dict[str, Any], count: int = 3) -> str:
    """Format real SHAP evidence in analyst language."""

    if not shap.get("available"):
        return "No local SHAP explanation is available in the supplied evidence."
    features = shap.get("top_features", [])[:count]
    parts = [f"{f['feature']} (SHAP {f['shap_value']:.4f})" for f in features if f.get("feature")]
    if not parts:
        return "The local SHAP artifact is present but contains no top-feature details."
    return "The strongest classifier signals are " + ", ".join(parts[:-1]) + (f", and {parts[-1]}" if len(parts) > 1 else parts[0]) + "."


def technique_text(graph: dict[str, Any]) -> str:
    """Return a compact ATT&CK technique phrase."""

    tech = graph.get("attack", {}).get("technique", {})
    tactic = graph.get("attack", {}).get("tactics", [{}])[0] if graph.get("attack", {}).get("tactics") else {}
    if tech:
        suffix = f" under {tactic.get('name')} ({tactic.get('id')})" if tactic else ""
        return f"{tech.get('name')} ({tech.get('id')}){suffix}"
    return "no mapped ATT&CK technique in the supplied graph context"


def names(items: list[dict[str, Any]], limit: int = 3) -> list[str]:
    """Return compact id-name names for graph items."""

    out = []
    for item in items[:limit]:
        ident = item.get("id")
        name = item.get("name")
        out.append(f"{name} ({ident})" if ident and name and ident != name else str(name or ident))
    return out


def confidence_text(example: SourceExample) -> str:
    """Return confidence wording without fabricating unavailable values."""

    if example.confidence is None:
        return "The exported artifacts do not include a classifier confidence value for this context."
    return f"The classifier confidence is {example.confidence:.1%}, which places this sample in the {example.confidence_band} confidence band."


def graph_evidence_text(example: SourceExample) -> str:
    """Summarize graph evidence without overclaiming compromise."""

    graph = example.graph
    mitigations = names(graph.get("attack", {}).get("mitigations", []), 3)
    cves = names(graph.get("cves", []), 3)
    capec = names(graph.get("capec", []), 2)
    parts = [f"Graph retrieval maps the label to {technique_text(graph)} as contextual intelligence, not proof of compromise."]
    if capec:
        parts.append(f"Related CAPEC context includes {', '.join(capec)}.")
    if cves:
        parts.append(f"Candidate CVE context includes {', '.join(cves)}; asset exposure is not established by this evidence.")
    else:
        parts.append("No CVE evidence is present in this retrieval context.")
    if mitigations:
        parts.append(f"Relevant mitigations include {', '.join(mitigations)}.")
    return " ".join(parts)


def build_output(task: str, example: SourceExample, idx: int, scenario: str) -> dict[str, Any]:
    """Create a concise, evidence-specific target output."""

    graph = example.graph
    attack = graph.get("attack", {})
    tech = attack.get("technique", {})
    mitigations = names(attack.get("mitigations", []), 4)
    detections = names(graph.get("detection_guidance", []), 2)
    cves = names(graph.get("cves", []), 4)
    capecs = names(graph.get("capec", []), 2)
    cwes = names(graph.get("cwes", []), 3)
    products = names(graph.get("products", []), 3)
    shap_available = example.shap is not None and example.shap.get("available")
    confidence = example.confidence
    base = {
        "ids_prediction": example.ids_label,
        "confidence_band": example.confidence_band,
        "evidence_basis": {
            "classifier": confidence_text(example),
            "shap": shap_phrase(example.shap or {"available": False}, 3),
            "graph": graph_evidence_text(example),
        },
        "limitations": [],
        "decision_scenario": scenario,
        "provenance": graph.get("provenance", [])[:8],
    }
    if not shap_available:
        base["limitations"].append("No local SHAP explanation is available for this base context.")
    if not graph.get("cves"):
        base["limitations"].append("No CVE evidence is supplied; do not infer vulnerable products.")
    if graph.get("groups") or graph.get("tools") or graph.get("malware"):
        base["limitations"].append("ATT&CK group, tool, and malware links are contextual usage references, not attribution.")
    if "contains_inferred_graph_relationships" in example.evidence_conditions:
        base["limitations"].append("Some graph relationships are inferred and should be weighted below direct source relationships.")

    if task == "soc_incident_assessment":
        severity = "high" if confidence and confidence >= 0.9 else "moderate"
        action_lead = {
            "initial_triage": "Start with alert validation and flow review.",
            "escalation_decision": "Escalate if the same source repeats the behavior or if corroborating telemetry appears.",
            "secondary_review": "Ask a second analyst to verify the mapping and evidence gaps before incident declaration.",
            "containment_readiness": "Prepare containment options, but wait for corroborating telemetry before disruption.",
            "evidence_prioritization": "Prioritize the SHAP-supported flow characteristics and mapped detection guidance.",
        }[scenario]
        return {
            **base,
            "assessment": (
                f"Treat the {example.ids_label} alert as a {severity}-priority triage item. "
                f"The mapped behavior is {technique_text(graph)}, and the graph context supports enrichment rather than confirmation."
            ),
            "analyst_actions": [
                action_lead,
                "Compare the top SHAP signals with packet and connection telemetry.",
                "Apply the listed mitigations only after confirming operational fit.",
            ],
            "mitigations": mitigations,
            "detection_guidance": detections,
        }
    if task == "attack_mapping":
        emphasis = {
            "mapping_validation": "Validate that the observed traffic pattern matches the mapped technique before using it in reporting.",
            "tactic_context": "Use the tactic to frame intent, but do not infer attacker objectives from the mapping alone.",
            "analyst_explanation": "Explain the mapping as a defensible triage hypothesis rather than a final incident finding.",
        }[scenario]
        return {
            **base,
            "attack_mapping": {
                "technique_id": tech.get("id"),
                "technique_name": tech.get("name"),
                "tactics": names(attack.get("tactics", []), 2),
                "mapping_rationale": (
                    f"The IDS label {example.ids_label} aligns with {technique_text(graph)} in the retrieved graph. "
                    f"{emphasis}"
                ),
            },
        }
    if task == "mitigation_detection":
        lead = {
            "control_review": "Review whether the mapped controls already exist and are logging enforcement outcomes.",
            "detection_tuning": "Tune detections around the available classifier and graph evidence, then test for false positives.",
            "operational_hardening": "Prioritize hardening actions that reduce exposure without disrupting normal traffic.",
        }[scenario]
        return {
            **base,
            "recommendations": [
                f"Prioritize {mitigations[0]} for immediate review." if mitigations else "No grounded mitigation is available in this context.",
                lead,
                "Retain graph provenance when escalating so reviewers can separate direct and inferred evidence.",
            ],
            "mitigations": mitigations,
            "detection_guidance": detections,
        }
    if task == "uncertainty_evidence_gap":
        gaps = list(base["limitations"])
        if example.confidence is None:
            gaps.append("Classifier confidence is unavailable in the exported evidence.")
        focus = {
            "low_evidence_review": "The current record is suitable for review, not assertion.",
            "missing_telemetry": "Additional packet, host, or asset telemetry is needed before raising certainty.",
            "unsupported_claim_filter": "Remove claims that are not tied to classifier, SHAP, or graph provenance.",
        }[scenario]
        return {
            **base,
            "uncertainty_assessment": (
                f"{focus} The evidence is sufficient for contextual triage but not for a definitive incident conclusion. "
                "Escalation should focus on confirming telemetry rather than asserting compromise."
            ),
            "evidence_gaps": gaps,
            "unsupported_claims_to_avoid": [
                "Do not claim product exposure unless an affected asset is confirmed.",
                "Do not attribute the activity to ATT&CK groups, tools, or malware from context alone.",
            ],
        }
    if task == "executive_summary":
        risk = "service disruption or unauthorized activity" if example.ids_label in {"DDoS", "Bot"} else "security exposure requiring validation"
        executive_action = {
            "business_risk": "Frame this as operational risk pending SOC confirmation.",
            "operations_brief": "Coordinate with operations to preserve logs and avoid unnecessary disruption.",
            "leadership_action": "Ask leadership for support on rapid validation and control review.",
        }[scenario]
        return {
            **base,
            "executive_summary": (
                f"TrustSecAI flagged {example.ids_label}, which may indicate {risk}. "
                f"The available evidence maps the alert to {tech.get('name')} ({tech.get('id')}) and provides mitigation context, "
                "but it does not by itself prove compromise or business impact."
            ),
            "business_action": executive_action,
            "confidence_statement": confidence_text(example),
        }
    if task == "threat_hunting_followup":
        pivot = {
            "hypothesis_generation": "Start with a falsifiable hypothesis and look for independent supporting telemetry.",
            "telemetry_pivot": "Pivot on related flows, endpoints, and timing before expanding the hunt scope.",
            "alternate_explanation": "Actively test whether benign service behavior could explain the alert.",
        }[scenario]
        return {
            **base,
            "hunt_hypothesis": (
                f"If the {example.ids_label} alert reflects real adversary activity, related telemetry may show behavior consistent with "
                f"{technique_text(graph)}."
            ),
            "follow_up_evidence": [
                pivot,
                "Correlate source/destination flow counts and timing around the alert.",
                "Check whether the SHAP-highlighted flow characteristics recur across hosts or time windows.",
                "Look for independent detections before treating ATT&CK group/tool/malware context as relevant.",
            ],
            "alternate_explanation": "The classifier signal may reflect benign operational traffic unless corroborated by additional telemetry.",
        }
    if task == "vulnerability_context":
        cve_instruction = {
            "cve_review": "Review CVEs as enrichment and require asset matching before risk acceptance.",
            "product_exposure_check": "Check whether affected products appear in the environment before escalating vulnerability risk.",
            "weakness_context": "Use CWE/CAPEC context to guide questions, not to assert exploitability.",
        }[scenario]
        return {
            **base,
            "vulnerability_context": {
                "cves": cves,
                "cwes": cwes,
                "products": products,
                "assessment": (
                    f"{cve_instruction} Use CVE and product entries as candidate enrichment only. "
                    "The supplied graph does not confirm that these products exist in the monitored environment."
                    if cves
                    else "No CVE or affected-product evidence is present for this context."
                ),
            },
            "capec_context": capecs,
        }
    if task == "multi_turn_analyst_interaction":
        followup = {
            "triage_followup": "What should be checked next?",
            "mitigation_followup": "Which controls should be reviewed first?",
        }[scenario]
        answer = (
            "Validate packet and flow telemetry, review detection guidance, and avoid claiming attribution or product exposure "
            "unless separate evidence confirms it."
            if scenario == "triage_followup"
            else "Review the grounded mitigations in priority order and confirm they apply to the affected network segment before change."
        )
        return {
            **base,
            "conversation": [
                {
                    "role": "analyst",
                    "content": f"Summarize the {example.ids_label} alert using only supplied evidence.",
                },
                {
                    "role": "assistant",
                    "content": (
                        f"The alert maps to {technique_text(graph)}. {shap_phrase(example.shap or {'available': False}, 2)} "
                        "The graph context supports enrichment, not confirmation."
                    ),
                },
                {
                    "role": "analyst",
                    "content": followup,
                },
                {
                    "role": "assistant",
                    "content": answer,
                },
            ],
        }
    raise ValueError(f"Unsupported task: {task}")


def build_instruction(task: str, example: SourceExample) -> str:
    """Create a grounded SFT instruction."""

    instructions = {
        "soc_incident_assessment": f"Assess the {example.ids_label} IDS alert for SOC triage using only the supplied evidence.",
        "attack_mapping": f"Explain the ATT&CK mapping for the {example.ids_label} alert and state the evidence limits.",
        "mitigation_detection": f"Recommend mitigations and detection follow-up for the {example.ids_label} alert.",
        "uncertainty_evidence_gap": f"Identify uncertainty and evidence gaps for the {example.ids_label} alert.",
        "executive_summary": f"Write an executive summary for the {example.ids_label} alert without overstating graph evidence.",
        "threat_hunting_followup": f"Create a threat-hunting hypothesis and follow-up evidence plan for {example.ids_label}.",
        "vulnerability_context": f"Analyze vulnerability context for {example.ids_label} using only supplied CVE/CWE/CAPEC evidence.",
        "multi_turn_analyst_interaction": f"Respond to a short analyst follow-up conversation about {example.ids_label}.",
    }
    return instructions[task]


def build_input(example: SourceExample, difficulty: str, task: str) -> dict[str, Any]:
    """Build the SFT input payload."""

    classifier = {"prediction": example.ids_label}
    if example.confidence is not None:
        classifier["confidence"] = example.confidence
    return {
        "ids": classifier,
        "shap": example.shap,
        "graph_context": example.graph,
        "analyst_constraints": {
            "use_only_supplied_context": True,
            "cite_provenance": True,
            "distinguish_context_from_proof": True,
            "difficulty": difficulty,
            "task_type": task,
        },
        "base_context_id": example.base_context_id,
        "evidence_conditions": example.evidence_conditions,
    }


def build_dataset(source_examples: list[SourceExample]) -> list[dict[str, Any]]:
    """Build the evidence-grounded candidate dataset."""

    rng = random.Random(RANDOM_SEED)
    examples: list[dict[str, Any]] = []
    task_sequence: list[tuple[str, str]] = []
    for task, ratio in TASK_FAMILIES.items():
        target_count = max(1, round(ratio * 20))
        scenarios = TASK_SCENARIOS[task]
        for idx in range(target_count):
            task_sequence.append((task, scenarios[idx % len(scenarios)]))
    counter = 1
    for source in source_examples:
        tasks = list(task_sequence)
        rng.shuffle(tasks)
        for task, scenario in tasks:
            difficulty = DIFFICULTIES[(counter - 1) % len(DIFFICULTIES)]
            example_id = f"trustsecai-gold-v0-{counter:05d}"
            record = {
                "instruction": build_instruction(task, source),
                "input": build_input(source, difficulty, task),
                "output": build_output(task, source, counter, scenario),
                "metadata": {
                    "example_id": example_id,
                    "base_context_id": source.base_context_id,
                    "task_type": task,
                    "analyst_decision_scenario": scenario,
                    "difficulty": difficulty,
                    "ids_label": source.ids_label,
                    "confidence_band": source.confidence_band,
                    "provenance_type": source.provenance_type,
                    "evidence_conditions": source.evidence_conditions,
                    "source_artifact_refs": source.source_artifacts,
                    "context_artifact": source.context_path,
                    "review_status": "candidate_unreviewed",
                    "generation_method": "gold_candidate_from_existing_trustsecai_artifacts",
                    "schema_compatibility": "current_sft_jsonl",
                    "created_at": date.today().isoformat(),
                },
            }
            examples.append(record)
            counter += 1
    return examples


def output_text(record: dict[str, Any]) -> str:
    """Return the target-output text used for diversity checks."""

    return json.dumps(record.get("output", {}), sort_keys=True, ensure_ascii=False)


def dedupe_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop exact duplicate target outputs deterministically."""

    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for record in records:
        fingerprint = output_text(record)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduped.append(record)
    for index, record in enumerate(deduped, start=1):
        new_id = f"trustsecai-gold-v0-{index:05d}"
        record["metadata"]["example_id"] = new_id
    return deduped


def text_for_reading(record: dict[str, Any]) -> str:
    """Return a readable approximation of target output."""

    skip_keys = {"provenance"}

    def walk(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            out: list[str] = []
            for item in value:
                out.extend(walk(item))
            return out
        if isinstance(value, dict):
            out = []
            for key, item in value.items():
                if key in skip_keys:
                    continue
                out.extend(walk(item))
            return out
        return []

    return " ".join(walk(record.get("output", {})))


def validation_report(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate gold-candidate records for leakage and unsupported phrasing."""

    ids = [r["metadata"]["example_id"] for r in records]
    duplicate_ids = [item for item, count in Counter(ids).items() if count > 1]
    duplicate_outputs = [item for item, count in Counter(output_text(r) for r in records).items() if count > 1]
    bad_phrases = [
        "training example",
        "future agreement analysis",
        "agreement module is executed",
        "gold-approved",
        "confirmed compromise",
        "attributed to",
    ]
    flagged: list[dict[str, str]] = []
    for record in records:
        text = text_for_reading(record).lower()
        for phrase in bad_phrases:
            if phrase in text:
                flagged.append({"example_id": record["metadata"]["example_id"], "issue": f"contains phrase: {phrase}"})
        if not record["metadata"].get("source_artifact_refs"):
            flagged.append({"example_id": record["metadata"]["example_id"], "issue": "missing source artifact reference"})
        if not record["output"].get("provenance"):
            flagged.append({"example_id": record["metadata"]["example_id"], "issue": "missing graph provenance in output"})
    return {
        "records": len(records),
        "duplicate_ids": duplicate_ids,
        "duplicate_target_outputs": len(duplicate_outputs),
        "flagged_records": flagged,
        "passed": not duplicate_ids and not duplicate_outputs and not flagged,
    }


def split_by_base_context(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Create leakage-safe splits grouped by base_context_id."""

    rng = random.Random(RANDOM_SEED)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[record["metadata"]["base_context_id"]].append(record)
    base_ids = sorted(grouped)
    rng.shuffle(base_ids)
    train_cut = math.floor(len(base_ids) * 0.70)
    val_cut = train_cut + math.floor(len(base_ids) * 0.15)
    splits = {
        "train": base_ids[:train_cut],
        "validation": base_ids[train_cut:val_cut],
        "test": base_ids[val_cut:],
    }
    out: dict[str, list[dict[str, Any]]] = {}
    for split, ids in splits.items():
        split_records: list[dict[str, Any]] = []
        for base_id in ids:
            for record in grouped[base_id]:
                record_copy = json.loads(json.dumps(record))
                record_copy["metadata"]["split"] = split
                split_records.append(record_copy)
        out[split] = split_records
    return out


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    """Write JSONL records."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def review_samples(records: list[dict[str, Any]], size: int = 250) -> list[dict[str, Any]]:
    """Create a deterministic stratified review sample."""

    rng = random.Random(RANDOM_SEED)
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        key = (record["metadata"]["ids_label"], record["metadata"]["task_type"])
        buckets[key].append(record)
    selected: dict[str, dict[str, Any]] = {}
    for bucket_records in buckets.values():
        rng.shuffle(bucket_records)
        for record in bucket_records[:2]:
            selected[record["metadata"]["example_id"]] = record
    remaining = [record for record in records if record["metadata"]["example_id"] not in selected]
    rng.shuffle(remaining)
    for record in remaining:
        if len(selected) >= min(size, len(records)):
            break
        selected[record["metadata"]["example_id"]] = record
    return list(selected.values())


def write_review_package(records: list[dict[str, Any]]) -> None:
    """Write review sample files, manifest, guide, and summary."""

    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    sample = review_samples(records, 250)
    write_json(REVIEW_DIR / "review_samples.json", sample)
    by_task: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in sample:
        by_task[record["metadata"]["task_type"]].append(record)
        by_label[record["metadata"]["ids_label"]].append(record)
    for task, items in by_task.items():
        write_json(REVIEW_DIR / f"task_{slug(task)}.json", items[:25])
    for label, items in by_label.items():
        write_json(REVIEW_DIR / f"label_{slug(label)}.json", items[:25])

    manifest_path = GOLD_DIR / "review_manifest.csv"
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "example_id",
                "base_context_id",
                "task_type",
                "ids_label",
                "confidence_band",
                "provenance_type",
                "review_status",
                "reviewer_decision",
                "reviewer_notes",
            ],
        )
        writer.writeheader()
        for record in sample:
            meta = record["metadata"]
            writer.writerow(
                {
                    "example_id": meta["example_id"],
                    "base_context_id": meta["base_context_id"],
                    "task_type": meta["task_type"],
                    "ids_label": meta["ids_label"],
                    "confidence_band": meta["confidence_band"],
                    "provenance_type": meta["provenance_type"],
                    "review_status": meta["review_status"],
                    "reviewer_decision": "",
                    "reviewer_notes": "",
                }
            )

    guide = [
        "# Gold-Candidate Review Guide",
        "",
        "Use this checklist for every sampled example:",
        "",
        "1. Is every factual claim grounded in supplied evidence?",
        "2. Is uncertainty appropriate for the confidence, SHAP, and graph context?",
        "3. Is there unsupported attribution?",
        "4. Does the output reflect the actual SHAP evidence?",
        "5. Does it confuse graph context with confirmed compromise?",
        "6. Is the tone appropriate for the task?",
        "7. Is the response meaningfully distinct from other examples using the same base_context_id?",
        "8. Mark reviewer_decision as approve, revise, or reject.",
        "",
        f"Review manifest: `{manifest_path.as_posix()}`",
    ]
    (REPORTS / "gold_candidate_review_guide.md").write_text("\n".join(guide) + "\n", encoding="utf-8")

    summary = [
        "# Gold-Candidate Review Summary",
        "",
        f"- Total candidate examples: {len(records)}",
        f"- Review sample examples: {len(sample)}",
        f"- IDS labels covered: {', '.join(sorted(by_label))}",
        f"- Task families covered: {', '.join(sorted(by_task))}",
        f"- Review manifest: artifacts/gold_candidates/review_manifest.csv",
    ]
    (REPORTS / "gold_candidate_review_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")


def ngrams(text: str, n: int = 4) -> list[str]:
    """Return normalized n-grams excluding security identifiers."""

    cleaned = re.sub(r"\b(?:T|TA|M|CAPEC|CWE|CVE)-?[A-Z0-9.-]+\b", " ", text, flags=re.IGNORECASE)
    words = re.findall(r"[a-z][a-z0-9']+", cleaned.lower())
    return [" ".join(words[i : i + n]) for i in range(max(0, len(words) - n + 1))]


def analyze_diversity(records: list[dict[str, Any]], splits: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Analyze target-output diversity and split leakage."""

    texts = [text_for_reading(record) for record in records]
    tokens = re.findall(r"[a-z][a-z0-9']+", " ".join(texts).lower())
    openings = [re.split(r"(?<=[.!?])\s+", text.strip())[0][:180] for text in texts if text.strip()]
    closings = [re.split(r"(?<=[.!?])\s+", text.strip())[-1][:180] for text in texts if text.strip()]
    exact_outputs = Counter(output_text(record) for record in records)
    near_duplicate_pairs = 0
    per_base_task: dict[tuple[str, str], list[str]] = defaultdict(list)
    for record in records:
        per_base_task[(record["metadata"]["base_context_id"], record["metadata"]["task_type"])].append(text_for_reading(record))
    for values in per_base_task.values():
        for i in range(len(values)):
            for j in range(i + 1, len(values)):
                if difflib.SequenceMatcher(None, values[i], values[j]).ratio() > 0.92:
                    near_duplicate_pairs += 1
    split_base_ids = {name: {record["metadata"]["base_context_id"] for record in items} for name, items in splits.items()}
    leakage = {
        "train_validation": sorted(split_base_ids["train"] & split_base_ids["validation"]),
        "train_test": sorted(split_base_ids["train"] & split_base_ids["test"]),
        "validation_test": sorted(split_base_ids["validation"] & split_base_ids["test"]),
    }
    phrase_counts = Counter(ngr for text in texts for ngr in ngrams(text, 4))
    by_base = Counter(record["metadata"]["base_context_id"] for record in records)
    task_by_base: dict[str, set[str]] = defaultdict(set)
    for record in records:
        task_by_base[record["metadata"]["base_context_id"]].add(record["metadata"]["task_type"])
    return {
        "total_examples": len(records),
        "unique_base_contexts": len(by_base),
        "examples_per_base_context": dict(by_base),
        "task_coverage_per_base_context": {key: sorted(value) for key, value in task_by_base.items()},
        "exact_duplicate_target_outputs": sum(count - 1 for count in exact_outputs.values() if count > 1),
        "near_duplicate_target_output_pairs": near_duplicate_pairs,
        "repeated_opening_rate": repeated_rate(openings),
        "repeated_closing_rate": repeated_rate(closings),
        "vocabulary_diversity": round(len(set(tokens)) / max(1, len(tokens)), 4),
        "diversity_by_task": grouped_vocab(records, "task_type"),
        "diversity_by_ids_label": grouped_vocab(records, "ids_label"),
        "diversity_by_confidence_band": grouped_vocab(records, "confidence_band"),
        "diversity_by_provenance_type": grouped_vocab(records, "provenance_type"),
        "split_leakage": leakage,
        "top_repeated_phrases": phrase_counts.most_common(25),
        "flags": build_diversity_flags(by_base, exact_outputs, near_duplicate_pairs, leakage, records),
    }


def repeated_rate(values: list[str]) -> float:
    """Return percentage of repeated values."""

    counts = Counter(values)
    repeated = sum(count for count in counts.values() if count > 1)
    return round(repeated / max(1, len(values)), 4)


def grouped_vocab(records: list[dict[str, Any]], metadata_key: str) -> dict[str, float]:
    """Vocabulary diversity grouped by metadata key."""

    grouped: dict[str, list[str]] = defaultdict(list)
    for record in records:
        grouped[str(record["metadata"].get(metadata_key, "unknown"))].append(text_for_reading(record))
    out = {}
    for key, values in grouped.items():
        tokens = re.findall(r"[a-z][a-z0-9']+", " ".join(values).lower())
        out[key] = round(len(set(tokens)) / max(1, len(tokens)), 4)
    return out


def build_diversity_flags(
    by_base: Counter[str],
    exact_outputs: Counter[str],
    near_duplicate_pairs: int,
    leakage: dict[str, list[str]],
    records: list[dict[str, Any]],
) -> list[str]:
    """Build diversity and quality flags."""

    flags = []
    if any(count > 40 for count in by_base.values()):
        flags.append("Some base contexts have more than 40 derivative examples.")
    if any(count > 1 for count in exact_outputs.values()):
        flags.append("Exact duplicate target outputs were detected.")
    if near_duplicate_pairs:
        flags.append(f"Near-duplicate analyst-text pairs detected for review: {near_duplicate_pairs}.")
    if any(leakage.values()):
        flags.append("Base-context leakage detected across train/validation/test splits.")
    missing_source = [r["metadata"]["example_id"] for r in records if not r["metadata"].get("source_artifact_refs")]
    if missing_source:
        flags.append(f"Examples without source artifact refs: {len(missing_source)}.")
    if not flags:
        flags.append("No split leakage or exact duplicate target outputs detected.")
    return flags


def write_reports(records: list[dict[str, Any]], splits: dict[str, list[dict[str, Any]]], quality: dict[str, Any], diversity: dict[str, Any]) -> None:
    """Write gold-candidate reports."""

    task_counts = Counter(record["metadata"]["task_type"] for record in records)
    label_counts = Counter(record["metadata"]["ids_label"] for record in records)
    difficulty_counts = Counter(record["metadata"]["difficulty"] for record in records)
    conf_counts = Counter(record["metadata"]["confidence_band"] for record in records)
    prov_counts = Counter(record["metadata"]["provenance_type"] for record in records)

    main = [
        "# TrustSecAI Gold-Candidate v0 Report",
        "",
        "This set is intentionally smaller than the previous synthetic corpora. It uses the currently exported TrustSecAI evidence contexts and avoids treating paraphrases over identical evidence as new diversity.",
        "",
        "## Summary",
        "",
        f"- Candidate examples: {len(records)}",
        f"- Unique base contexts: {diversity['unique_base_contexts']}",
        f"- IDS labels: {dict(label_counts)}",
        f"- Task distribution: {dict(task_counts)}",
        f"- Difficulty distribution: {dict(difficulty_counts)}",
        f"- Confidence bands: {dict(conf_counts)}",
        f"- Provenance types: {dict(prov_counts)}",
        "",
        "## Size Rationale",
        "",
        "The requested target of approximately 3,000 examples was not forced because the available real evidence currently consists of five saved retrieval contexts and limited local SHAP coverage. The generated set favors reviewable base-context diversity over repeated wording variants.",
    ]
    (REPORTS / "trustsecai_gold_candidate_v0_report.md").write_text("\n".join(main) + "\n", encoding="utf-8")

    split_lines = [
        "# Gold-Candidate Split Report",
        "",
        "Splits are grouped by `base_context_id`; no base context is shared across splits.",
        "",
    ]
    split_base_ids = {}
    for name, items in splits.items():
        base_ids = {item["metadata"]["base_context_id"] for item in items}
        split_base_ids[name] = base_ids
        split_lines.append(f"- {name}: {len(items)} examples, {len(base_ids)} base contexts")
    split_lines.extend(
        [
            "",
            "## Leakage Check",
            "",
            f"- train/validation overlap: {sorted(split_base_ids['train'] & split_base_ids['validation'])}",
            f"- train/test overlap: {sorted(split_base_ids['train'] & split_base_ids['test'])}",
            f"- validation/test overlap: {sorted(split_base_ids['validation'] & split_base_ids['test'])}",
        ]
    )
    (REPORTS / "gold_candidate_split_report.md").write_text("\n".join(split_lines) + "\n", encoding="utf-8")

    div_lines = [
        "# Gold-Candidate Diversity Report",
        "",
        "Metrics are computed on target outputs only.",
        "",
        f"- Total examples: {diversity['total_examples']}",
        f"- Unique base contexts: {diversity['unique_base_contexts']}",
        f"- Exact duplicate target outputs: {diversity['exact_duplicate_target_outputs']}",
        f"- Near-duplicate target-output pairs: {diversity['near_duplicate_target_output_pairs']}",
        f"- Repeated opening rate: {diversity['repeated_opening_rate']}",
        f"- Repeated closing rate: {diversity['repeated_closing_rate']}",
        f"- Vocabulary diversity: {diversity['vocabulary_diversity']}",
        "",
        "## Top Repeated Phrases",
        "",
    ]
    div_lines.extend(f"- {phrase}: {count}" for phrase, count in diversity["top_repeated_phrases"][:15])
    div_lines.extend(["", "## Flags", ""])
    div_lines.extend(f"- {flag}" for flag in diversity["flags"])
    (REPORTS / "gold_candidate_diversity_report.md").write_text("\n".join(div_lines) + "\n", encoding="utf-8")

    qual_lines = [
        "# Gold-Candidate Quality Report",
        "",
        f"- Records validated: {quality['records']}",
        f"- Duplicate IDs: {len(quality['duplicate_ids'])}",
        f"- Duplicate target outputs: {quality['duplicate_target_outputs']}",
        f"- Flagged records: {len(quality['flagged_records'])}",
        f"- Passed strict automated checks: {quality['passed']}",
    ]
    if quality["flagged_records"]:
        qual_lines.extend(["", "## Flagged Records", ""])
        qual_lines.extend(f"- {item['example_id']}: {item['issue']}" for item in quality["flagged_records"][:50])
    (REPORTS / "gold_candidate_quality_report.md").write_text("\n".join(qual_lines) + "\n", encoding="utf-8")

    readiness = [
        "# Gold-Candidate Training Readiness",
        "",
        "## Status",
        "",
        "Candidate set is ready for human review, not gold-approved training.",
        "",
        "## Recommended Next Steps",
        "",
        "1. Review the stratified sample and mark each row approve, revise, or reject.",
        "2. Export additional real classifier predictions and local SHAP explanations before expanding toward 3,000+ records.",
        "3. Keep train/validation/test grouping by base_context_id for LoRA experiments.",
        "4. Do not treat ATT&CK group/tool/malware context as attribution without separate evidence.",
    ]
    (REPORTS / "gold_candidate_training_readiness.md").write_text("\n".join(readiness) + "\n", encoding="utf-8")


def main() -> None:
    """Run the full gold-candidate construction pipeline."""

    GOLD_DIR.mkdir(parents=True, exist_ok=True)
    CONTEXT_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    inventory = build_evidence_inventory()
    write_evidence_inventory(inventory)

    source_examples = build_source_examples()
    write_source_examples(source_examples)

    raw_records = build_dataset(source_examples)
    records = dedupe_records(raw_records)
    quality = validation_report(records)
    splits = split_by_base_context(records)
    diversity = analyze_diversity(records, splits)

    write_jsonl(GOLD_DIR / "trustsecai_gold_candidate_v0.jsonl", records)
    write_json(GOLD_DIR / "trustsecai_gold_candidate_v0_pretty.json", records)
    write_json(GOLD_DIR / "trustsecai_gold_candidate_v0_quality_report.json", quality)
    for split_name, split_records in splits.items():
        write_jsonl(GOLD_DIR / f"{split_name}.jsonl", split_records)
    write_review_package(records)
    write_reports(records, splits, quality, diversity)


if __name__ == "__main__":
    main()
