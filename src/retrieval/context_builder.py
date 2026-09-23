"""Build deterministic JSON context for future LLM consumption."""

from __future__ import annotations

from typing import Any

from src.retrieval.models import Provenance, RetrievedEntity, RetrievedGraphContext
from src.retrieval.ranking import rank_entities


CATEGORY_LIMITS = {
    "tactics": 5,
    "mitigations": 8,
    "groups": 8,
    "tools": 8,
    "malware": 8,
    "detection_guidance": 5,
    "capec": 8,
    "cwes": 12,
    "cves": 10,
    "products": 10,
    "references": 10,
}


def clean_properties(properties: dict[str, Any]) -> dict[str, Any]:
    """Drop bulky/internal fields but keep provenance-friendly source data."""

    excluded = {"raw_id", "source_file", "ingested_at", "stix_id", "tactic_short_names"}
    return {key: value for key, value in properties.items() if key not in excluded and value not in (None, "", [])}


def provenance_to_dict(item: Provenance) -> dict[str, Any]:
    """Convert provenance to dict."""

    return {
        "source": item.source,
        "confidence": item.confidence,
        "relationship_type": item.relationship_type,
        "inferred": item.inferred,
        "origin_node": item.origin_node,
        "target_node": item.target_node,
        "method": item.method,
    }


def entity_to_dict(entity: RetrievedEntity) -> dict[str, Any]:
    """Convert ranked entity to stable dictionary."""

    return {
        "id": entity.entity_id,
        "name": entity.name,
        "rank_score": entity.rank_score,
        "distance": entity.distance,
        "properties": clean_properties(entity.properties),
        "provenance": [provenance_to_dict(item) for item in entity.provenance],
    }


def flatten_provenance(context: RetrievedGraphContext) -> list[dict[str, Any]]:
    """Collect all provenance entries in deterministic order."""

    rows = []
    for category in sorted(context.entities):
        for entity in context.entities[category]:
            for item in entity.provenance:
                rows.append({"category": category, "entity_id": entity.entity_id, **provenance_to_dict(item)})
    return sorted(rows, key=lambda row: (row["category"], row["entity_id"], row["relationship_type"], str(row["origin_node"])))


def build_context(context: RetrievedGraphContext) -> dict[str, Any]:
    """Build final structured JSON context."""

    ranked = {
        category: rank_entities(entities, CATEGORY_LIMITS.get(category))
        for category, entities in context.entities.items()
    }
    technique = ranked.get("technique", [None])[0]

    output = {
        "prediction": context.prediction,
        "classifier": {"confidence": context.classifier_confidence},
        "retrieval": {
            "latency_ms": round(context.latency_ms, 3),
            "relationships_traversed": context.relationships_traversed,
        },
        "attack": {
            "technique": entity_to_dict(technique) if technique else None,
            "tactics": [entity_to_dict(item) for item in ranked.get("tactics", [])],
            "mitigations": [entity_to_dict(item) for item in ranked.get("mitigations", [])],
        },
        "capec": [entity_to_dict(item) for item in ranked.get("capec", [])],
        "cwes": [entity_to_dict(item) for item in ranked.get("cwes", [])],
        "cves": [entity_to_dict(item) for item in ranked.get("cves", [])],
        "products": [entity_to_dict(item) for item in ranked.get("products", [])],
        "references": [entity_to_dict(item) for item in ranked.get("references", [])],
        "groups": [entity_to_dict(item) for item in ranked.get("groups", [])],
        "tools": [entity_to_dict(item) for item in ranked.get("tools", [])],
        "malware": [entity_to_dict(item) for item in ranked.get("malware", [])],
        "detection_guidance": [entity_to_dict(item) for item in ranked.get("detection_guidance", [])],
        "provenance": flatten_provenance(context),
    }
    return output

