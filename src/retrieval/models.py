"""Data models for deterministic graph retrieval context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Provenance:
    """Relationship and source provenance for a retrieved object."""

    source: str | None
    confidence: str | None
    relationship_type: str
    inferred: bool
    origin_node: str
    target_node: str | None = None
    method: str | None = None


@dataclass
class RetrievedEntity:
    """A graph entity retrieved for an IDS label."""

    category: str
    entity_id: str
    name: str | None
    properties: dict[str, Any] = field(default_factory=dict)
    provenance: list[Provenance] = field(default_factory=list)
    distance: int = 0
    rank_score: float = 0.0


@dataclass
class RetrievedGraphContext:
    """Raw retrieved graph context before final JSON assembly."""

    prediction: str
    classifier_confidence: float | None
    entities: dict[str, list[RetrievedEntity]] = field(default_factory=dict)
    latency_ms: float = 0.0
    relationships_traversed: int = 0

    def add(self, entity: RetrievedEntity) -> None:
        """Add an entity under its category."""

        self.entities.setdefault(entity.category, []).append(entity)

