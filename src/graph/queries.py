"""Clean query helpers for the TrustSecAI ATT&CK Neo4j graph."""

from __future__ import annotations

from typing import Any


def _node_to_dict(node: Any) -> dict[str, Any] | None:
    """Convert a Neo4j node to a plain dictionary."""

    if node is None:
        return None
    return dict(node)


def _records_to_nodes(records: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    """Convert records containing a node key into dictionaries."""

    return [_node_to_dict(record.get(key)) for record in records if record.get(key) is not None]


def get_technique(driver, attack_id: str, database: str | None = None) -> dict[str, Any] | None:
    """Return a Technique or SubTechnique by ATT&CK ID."""

    query = """
    MATCH (t)
    WHERE (t:Technique OR t:SubTechnique) AND t.attack_id = $attack_id
    RETURN t
    LIMIT 1
    """
    with driver.session(database=database) as session:
        record = session.run(query, {"attack_id": attack_id}).single()
        return _node_to_dict(record["t"]) if record else None


def get_tactic(driver, attack_id: str, database: str | None = None) -> list[dict[str, Any]]:
    """Return tactics for a Technique/SubTechnique."""

    query = """
    MATCH (t)-[:HAS_TACTIC]->(ta:Tactic)
    WHERE (t:Technique OR t:SubTechnique) AND t.attack_id = $attack_id
    RETURN ta
    ORDER BY ta.short_name
    """
    with driver.session(database=database) as session:
        return _records_to_nodes([record.data() for record in session.run(query, {"attack_id": attack_id})], "ta")


def get_mitigations(driver, attack_id: str, database: str | None = None) -> list[dict[str, Any]]:
    """Return mitigations for a Technique/SubTechnique."""

    query = """
    MATCH (t)-[:MITIGATED_BY]->(m:Mitigation)
    WHERE (t:Technique OR t:SubTechnique) AND t.attack_id = $attack_id
    RETURN m
    ORDER BY m.attack_id, m.name
    """
    with driver.session(database=database) as session:
        return _records_to_nodes([record.data() for record in session.run(query, {"attack_id": attack_id})], "m")


def get_related_groups(driver, attack_id: str, database: str | None = None) -> list[dict[str, Any]]:
    """Return groups that use a Technique/SubTechnique."""

    query = """
    MATCH (g:Group)-[:USES_TECHNIQUE]->(t)
    WHERE (t:Technique OR t:SubTechnique) AND t.attack_id = $attack_id
    RETURN g
    ORDER BY g.name
    """
    with driver.session(database=database) as session:
        return _records_to_nodes([record.data() for record in session.run(query, {"attack_id": attack_id})], "g")


def get_related_tools(driver, attack_id: str, database: str | None = None) -> list[dict[str, Any]]:
    """Return tools that use a Technique/SubTechnique."""

    query = """
    MATCH (tool:Tool)-[:USES_TECHNIQUE]->(t)
    WHERE (t:Technique OR t:SubTechnique) AND t.attack_id = $attack_id
    RETURN tool
    ORDER BY tool.name
    """
    with driver.session(database=database) as session:
        return _records_to_nodes([record.data() for record in session.run(query, {"attack_id": attack_id})], "tool")


def get_related_malware(driver, attack_id: str, database: str | None = None) -> list[dict[str, Any]]:
    """Return malware that uses a Technique/SubTechnique."""

    query = """
    MATCH (m:Malware)-[:USES_TECHNIQUE]->(t)
    WHERE (t:Technique OR t:SubTechnique) AND t.attack_id = $attack_id
    RETURN m
    ORDER BY m.name
    """
    with driver.session(database=database) as session:
        return _records_to_nodes([record.data() for record in session.run(query, {"attack_id": attack_id})], "m")


def get_detection_guidance(driver, attack_id: str, database: str | None = None) -> list[dict[str, Any]]:
    """Return detection strategies for a Technique/SubTechnique."""

    query = """
    MATCH (t)-[:DETECTED_BY]->(d:DetectionStrategy)
    WHERE (t:Technique OR t:SubTechnique) AND t.attack_id = $attack_id
    RETURN d
    ORDER BY d.name
    """
    with driver.session(database=database) as session:
        return _records_to_nodes([record.data() for record in session.run(query, {"attack_id": attack_id})], "d")


def validate_t1046(driver, database: str | None = None) -> dict[str, Any]:
    """Run the required validation query package for T1046."""

    attack_id = "T1046"
    return {
        "attack_id": attack_id,
        "technique": get_technique(driver, attack_id, database),
        "tactics": get_tactic(driver, attack_id, database),
        "mitigations": get_mitigations(driver, attack_id, database),
        "related_groups": get_related_groups(driver, attack_id, database),
        "related_tools": get_related_tools(driver, attack_id, database),
        "related_malware": get_related_malware(driver, attack_id, database),
        "detection_guidance": get_detection_guidance(driver, attack_id, database),
    }

