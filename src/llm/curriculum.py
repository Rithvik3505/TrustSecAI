"""Curriculum levels for TrustSecAI corpus examples."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable


@dataclass(frozen=True)
class CurriculumLevel:
    """Difficulty metadata used during deterministic corpus generation."""

    name: str
    description: str
    graph_scope: str
    reasoning_requirements: tuple[str, ...]
    context_limits: Dict[str, int]


CURRICULUM: Dict[str, CurriculumLevel] = {
    "easy": CurriculumLevel(
        name="easy",
        description="Prediction -> Technique -> Mitigation.",
        graph_scope="Technique, tactic, and top mitigations.",
        reasoning_requirements=("direct mapping", "basic mitigation selection"),
        context_limits={"capec": 0, "cwes": 0, "cves": 0, "products": 0, "references": 0},
    ),
    "medium": CurriculumLevel(
        name="medium",
        description="Prediction -> Technique -> CAPEC -> Mitigation.",
        graph_scope="Technique, tactic, CAPEC pattern, and mitigations.",
        reasoning_requirements=("attack-pattern context", "mitigation rationale"),
        context_limits={"capec": 2, "cwes": 1, "cves": 0, "products": 0, "references": 0},
    ),
    "hard": CurriculumLevel(
        name="hard",
        description="Prediction -> Multiple graph entities -> Conflicting evidence -> Uncertainty.",
        graph_scope="Technique, tactics, CAPEC, CWE, CVE, actor context, and detection.",
        reasoning_requirements=("multi-source synthesis", "uncertainty handling"),
        context_limits={"capec": 3, "cwes": 3, "cves": 5, "products": 5, "references": 5},
    ),
    "expert": CurriculumLevel(
        name="expert",
        description=(
            "Prediction -> Complex graph traversal -> Sparse evidence -> Evidence "
            "weighting -> Analyst reasoning."
        ),
        graph_scope="Full ranked retrieval context with provenance and inferred edges.",
        reasoning_requirements=(
            "evidence weighting",
            "sparse-context caveats",
            "candidate vulnerability framing",
        ),
        context_limits={"capec": 5, "cwes": 5, "cves": 10, "products": 10, "references": 10},
    ),
}


def get_level(name: str) -> CurriculumLevel:
    """Return curriculum metadata by level name."""

    return CURRICULUM[name]


def iter_levels() -> Iterable[CurriculumLevel]:
    """Iterate over levels in increasing difficulty."""

    for name in ("easy", "medium", "hard", "expert"):
        yield CURRICULUM[name]

