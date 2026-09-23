"""Deterministic Cypher graph retrieval for TrustSecAI."""

from __future__ import annotations

import time
from typing import Any

from src.graph.neo4j_utils import get_driver, get_neo4j_config
from src.retrieval.models import Provenance, RetrievedEntity, RetrievedGraphContext


DEFAULT_LIMITS = {
    "mitigations": 10,
    "groups": 10,
    "tools": 10,
    "malware": 10,
    "detection_guidance": 10,
    "capec": 10,
    "cwes": 20,
    "cves": 20,
    "products": 20,
    "references": 20,
}


def node_dict(node: Any) -> dict[str, Any]:
    """Convert Neo4j node to dict."""

    return dict(node) if node is not None else {}


def make_entity(
    category: str,
    node: Any,
    entity_id_key: str,
    relationship_type: str,
    rel: Any | None,
    origin_node: str,
    distance: int,
) -> RetrievedEntity:
    """Create retrieved entity with provenance."""

    properties = node_dict(node)
    rel_props = dict(rel) if rel is not None else {}
    entity_id = str(properties.get(entity_id_key) or properties.get("stix_id") or properties.get("url") or properties.get("cpe_uri"))
    name = properties.get("name") or properties.get("label") or properties.get("description")
    provenance = Provenance(
        source=rel_props.get("source") or properties.get("source"),
        confidence=rel_props.get("confidence"),
        relationship_type=relationship_type,
        inferred=bool(rel_props.get("inferred", False)),
        origin_node=origin_node,
        target_node=entity_id,
        method=rel_props.get("method"),
    )
    return RetrievedEntity(
        category=category,
        entity_id=entity_id,
        name=name,
        properties=properties,
        provenance=[provenance],
        distance=distance,
    )


class GraphRetriever:
    """Retrieve deterministic graph context for an IDS label."""

    def __init__(self, driver=None, database: str | None = None, limits: dict[str, int] | None = None) -> None:
        self._owns_driver = driver is None
        self.config = get_neo4j_config()
        self.driver = driver or get_driver(self.config)
        self.database = database if database is not None else self.config.database
        self.limits = {**DEFAULT_LIMITS, **(limits or {})}

    def close(self) -> None:
        """Close owned Neo4j driver."""

        if self._owns_driver:
            self.driver.close()

    def retrieve(self, prediction: str, classifier_confidence: float | None = None) -> RetrievedGraphContext:
        """Retrieve graph context for an IDS prediction label."""

        start = time.perf_counter()
        context = RetrievedGraphContext(prediction=prediction, classifier_confidence=classifier_confidence)
        with self.driver.session(database=self.database) as session:
            self._retrieve_primary_attack(session, context)
            if not context.entities.get("technique"):
                context.latency_ms = (time.perf_counter() - start) * 1000
                return context

            attack_id = context.entities["technique"][0].entity_id
            self._retrieve_neighbors(session, context, attack_id)
            self._retrieve_capec_cwe_cve(session, context, attack_id)

        context.relationships_traversed = sum(len(items) for key, items in context.entities.items() if key != "ids_label")
        context.latency_ms = (time.perf_counter() - start) * 1000
        return context

    def _retrieve_primary_attack(self, session, context: RetrievedGraphContext) -> None:
        records = session.run(
            """
            MATCH (label:IDSLabel {label: $prediction})-[rel:DETECTED_AS]->(tech)
            WHERE tech:Technique OR tech:SubTechnique
            OPTIONAL MATCH (tech)-[tactic_rel:HAS_TACTIC]->(tactic:Tactic)
            RETURN label, rel, tech, collect({rel: tactic_rel, node: tactic}) AS tactics
            ORDER BY tech.attack_id
            LIMIT 1
            """,
            {"prediction": context.prediction},
        )
        record = records.single()
        if not record:
            return
        label_entity = make_entity("ids_label", record["label"], "label", "SELF", None, context.prediction, 0)
        tech_entity = make_entity("technique", record["tech"], "attack_id", "DETECTED_AS", record["rel"], context.prediction, 1)
        context.add(label_entity)
        context.add(tech_entity)
        for item in record["tactics"]:
            if item["node"] is not None:
                context.add(make_entity("tactics", item["node"], "attack_id", "HAS_TACTIC", item["rel"], tech_entity.entity_id, 2))

    def _retrieve_neighbors(self, session, context: RetrievedGraphContext, attack_id: str) -> None:
        query_specs = [
            ("mitigations", "MITIGATED_BY", "Mitigation", "attack_id", 2, "MATCH (tech {attack_id:$attack_id})-[rel:MITIGATED_BY]->(node:Mitigation) RETURN node, rel ORDER BY node.attack_id LIMIT $limit"),
            ("groups", "USES_TECHNIQUE", "Group", "stix_id", 2, "MATCH (node:Group)-[rel:USES_TECHNIQUE]->(tech {attack_id:$attack_id}) RETURN node, rel ORDER BY node.name LIMIT $limit"),
            ("tools", "USES_TECHNIQUE", "Tool", "stix_id", 2, "MATCH (node:Tool)-[rel:USES_TECHNIQUE]->(tech {attack_id:$attack_id}) RETURN node, rel ORDER BY node.name LIMIT $limit"),
            ("malware", "USES_TECHNIQUE", "Malware", "stix_id", 2, "MATCH (node:Malware)-[rel:USES_TECHNIQUE]->(tech {attack_id:$attack_id}) RETURN node, rel ORDER BY node.name LIMIT $limit"),
            ("detection_guidance", "DETECTED_BY", "DetectionStrategy", "stix_id", 2, "MATCH (tech {attack_id:$attack_id})-[rel:DETECTED_BY]->(node:DetectionStrategy) RETURN node, rel ORDER BY node.name LIMIT $limit"),
        ]
        for category, relationship_type, _label, key, distance, query in query_specs:
            for record in session.run(query, {"attack_id": attack_id, "limit": self.limits[category]}):
                context.add(make_entity(category, record["node"], key, relationship_type, record["rel"], attack_id, distance))

    def _retrieve_capec_cwe_cve(self, session, context: RetrievedGraphContext, attack_id: str) -> None:
        capec_records = session.run(
            """
            MATCH (tech {attack_id:$attack_id})-[rel:HAS_ATTACK_PATTERN]->(capec:CAPECPattern)
            RETURN capec AS node, rel
            ORDER BY capec.capec_id
            LIMIT $limit
            """,
            {"attack_id": attack_id, "limit": self.limits["capec"]},
        )
        capec_ids: list[str] = []
        for record in capec_records:
            entity = make_entity("capec", record["node"], "capec_id", "HAS_ATTACK_PATTERN", record["rel"], attack_id, 2)
            capec_ids.append(entity.entity_id)
            context.add(entity)

        if not capec_ids:
            return

        for record in session.run(
            """
            MATCH (capec:CAPECPattern)-[rel:RELATED_WEAKNESS]->(cwe:CWE)
            WHERE capec.capec_id IN $capec_ids
            RETURN DISTINCT cwe AS node, rel, capec.capec_id AS origin
            ORDER BY cwe.cwe_id
            LIMIT $limit
            """,
            {"capec_ids": capec_ids, "limit": self.limits["cwes"]},
        ):
            context.add(make_entity("cwes", record["node"], "cwe_id", "RELATED_WEAKNESS", record["rel"], record["origin"], 3))

        for record in session.run(
            """
            MATCH (capec:CAPECPattern)-[rel:ASSOCIATED_CVE]->(cve:CVE)
            WHERE capec.capec_id IN $capec_ids
            RETURN DISTINCT cve AS node, rel, capec.capec_id AS origin
            ORDER BY coalesce(cve.base_score, 0) DESC, cve.cve_id
            LIMIT $limit
            """,
            {"capec_ids": capec_ids, "limit": self.limits["cves"]},
        ):
            context.add(make_entity("cves", record["node"], "cve_id", "ASSOCIATED_CVE", record["rel"], record["origin"], 4))

        cve_ids = [entity.entity_id for entity in context.entities.get("cves", [])]
        if not cve_ids:
            return

        for record in session.run(
            """
            MATCH (cve:CVE)-[rel:AFFECTS]->(product:Product)
            WHERE cve.cve_id IN $cve_ids
            RETURN DISTINCT product AS node, rel, cve.cve_id AS origin
            ORDER BY product.vendor, product.product, product.version
            LIMIT $limit
            """,
            {"cve_ids": cve_ids, "limit": self.limits["products"]},
        ):
            context.add(make_entity("products", record["node"], "cpe_uri", "AFFECTS", record["rel"], record["origin"], 5))

        for record in session.run(
            """
            MATCH (cve:CVE)-[rel:REFERENCES]->(reference:Reference)
            WHERE cve.cve_id IN $cve_ids
            RETURN DISTINCT reference AS node, rel, cve.cve_id AS origin
            ORDER BY reference.url
            LIMIT $limit
            """,
            {"cve_ids": cve_ids, "limit": self.limits["references"]},
        ):
            context.add(make_entity("references", record["node"], "url", "REFERENCES", record["rel"], record["origin"], 5))

