"""Ranking functions for TrustSecAI graph retrieval."""

from __future__ import annotations

from src.retrieval.models import RetrievedEntity


SEVERITY_WEIGHT = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
    "UNSCORED": 0.0,
    None: 0.0,
}

CAPEC_QUALITATIVE_WEIGHT = {
    "Very High": 1.0,
    "High": 0.8,
    "Medium": 0.5,
    "Low": 0.2,
    "Very Low": 0.1,
    "": 0.0,
    None: 0.0,
}

CONFIDENCE_WEIGHT = {
    "high": 1.0,
    "medium": 0.7,
    "low": 0.35,
    "source": 0.95,
    None: 0.5,
}


def relationship_confidence_score(entity: RetrievedEntity) -> float:
    """Score relationship confidence across provenance entries."""

    if not entity.provenance:
        return 0.0
    return max(CONFIDENCE_WEIGHT.get((item.confidence or "").lower(), 0.5) for item in entity.provenance)


def inferred_penalty(entity: RetrievedEntity) -> float:
    """Prefer original source relationships over inferred relationships."""

    if not entity.provenance:
        return 0.0
    if all(item.inferred for item in entity.provenance):
        return -0.25
    if any(item.inferred for item in entity.provenance):
        return -0.1
    return 0.0


def score_entity(entity: RetrievedEntity) -> float:
    """Compute deterministic ranking score."""

    distance_score = max(0.0, 1.0 - (entity.distance * 0.12))
    confidence_score = relationship_confidence_score(entity)
    source_score = inferred_penalty(entity)
    category_score = 0.0

    if entity.category == "cves":
        category_score += SEVERITY_WEIGHT.get(entity.properties.get("severity"), 0.0)
        base_score = entity.properties.get("base_score")
        if isinstance(base_score, (int, float)):
            category_score += min(float(base_score) / 10.0, 1.0)
    elif entity.category == "capec":
        category_score += CAPEC_QUALITATIVE_WEIGHT.get(entity.properties.get("likelihood"), 0.0)
        category_score += CAPEC_QUALITATIVE_WEIGHT.get(entity.properties.get("severity"), 0.0)

    return round(distance_score + confidence_score + source_score + category_score, 6)


def rank_entities(entities: list[RetrievedEntity], limit: int | None = None) -> list[RetrievedEntity]:
    """Rank entities and remove duplicates by category/entity_id."""

    deduped: dict[tuple[str, str], RetrievedEntity] = {}
    for entity in entities:
        key = (entity.category, entity.entity_id)
        entity.rank_score = score_entity(entity)
        existing = deduped.get(key)
        if existing is None or entity.rank_score > existing.rank_score:
            deduped[key] = entity

    ranked = sorted(
        deduped.values(),
        key=lambda item: (-item.rank_score, item.distance, item.entity_id),
    )
    if limit is not None:
        return ranked[:limit]
    return ranked

