"""Neo4j schema definition for the TrustSecAI ATT&CK graph."""

from __future__ import annotations

from dataclasses import dataclass


SCHEMA_VERSION = "attack-v1"

NODE_LABELS = (
    "Technique",
    "SubTechnique",
    "Tactic",
    "Mitigation",
    "Group",
    "Malware",
    "Tool",
    "Campaign",
    "DetectionStrategy",
    "CAPECPattern",
    "CWE",
    "CVE",
    "Product",
    "Reference",
    "IDSLabel",
)

RELATIONSHIP_TYPES = (
    "HAS_TACTIC",
    "SUBTECHNIQUE_OF",
    "MITIGATED_BY",
    "USES_TECHNIQUE",
    "USES_TOOL",
    "USES_MALWARE",
    "ATTRIBUTED_TO",
    "DETECTED_BY",
    "CHILD_OF",
    "CAN_PRECEDE",
    "CAN_FOLLOW",
    "PEER_OF",
    "CAN_ALSO_BE",
    "RELATED_WEAKNESS",
    "MAPS_TO_ATTACK",
    "HAS_WEAKNESS",
    "AFFECTS",
    "REFERENCES",
    "DETECTED_AS",
    "HAS_ATTACK_PATTERN",
    "ASSOCIATED_CVE",
)


@dataclass(frozen=True)
class SchemaStatement:
    """A named Cypher schema statement."""

    name: str
    cypher: str


CONSTRAINTS = (
    SchemaStatement(
        "technique_attack_id",
        "CREATE CONSTRAINT technique_attack_id IF NOT EXISTS FOR (n:Technique) REQUIRE n.attack_id IS UNIQUE",
    ),
    SchemaStatement(
        "subtechnique_attack_id",
        "CREATE CONSTRAINT subtechnique_attack_id IF NOT EXISTS FOR (n:SubTechnique) REQUIRE n.attack_id IS UNIQUE",
    ),
    SchemaStatement(
        "tactic_attack_id",
        "CREATE CONSTRAINT tactic_attack_id IF NOT EXISTS FOR (n:Tactic) REQUIRE n.attack_id IS UNIQUE",
    ),
    SchemaStatement(
        "mitigation_attack_id",
        "CREATE CONSTRAINT mitigation_attack_id IF NOT EXISTS FOR (n:Mitigation) REQUIRE n.attack_id IS UNIQUE",
    ),
    SchemaStatement(
        "group_stix_id",
        "CREATE CONSTRAINT group_stix_id IF NOT EXISTS FOR (n:Group) REQUIRE n.stix_id IS UNIQUE",
    ),
    SchemaStatement(
        "malware_stix_id",
        "CREATE CONSTRAINT malware_stix_id IF NOT EXISTS FOR (n:Malware) REQUIRE n.stix_id IS UNIQUE",
    ),
    SchemaStatement(
        "tool_stix_id",
        "CREATE CONSTRAINT tool_stix_id IF NOT EXISTS FOR (n:Tool) REQUIRE n.stix_id IS UNIQUE",
    ),
    SchemaStatement(
        "campaign_stix_id",
        "CREATE CONSTRAINT campaign_stix_id IF NOT EXISTS FOR (n:Campaign) REQUIRE n.stix_id IS UNIQUE",
    ),
    SchemaStatement(
        "detection_strategy_stix_id",
        "CREATE CONSTRAINT detection_strategy_stix_id IF NOT EXISTS FOR (n:DetectionStrategy) REQUIRE n.stix_id IS UNIQUE",
    ),
    SchemaStatement(
        "capec_id",
        "CREATE CONSTRAINT capec_id IF NOT EXISTS FOR (n:CAPECPattern) REQUIRE n.capec_id IS UNIQUE",
    ),
    SchemaStatement(
        "cwe_id",
        "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (n:CWE) REQUIRE n.cwe_id IS UNIQUE",
    ),
    SchemaStatement(
        "cve_id",
        "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (n:CVE) REQUIRE n.cve_id IS UNIQUE",
    ),
    SchemaStatement(
        "product_cpe_uri",
        "CREATE CONSTRAINT product_cpe_uri IF NOT EXISTS FOR (n:Product) REQUIRE n.cpe_uri IS UNIQUE",
    ),
    SchemaStatement(
        "reference_url",
        "CREATE CONSTRAINT reference_url IF NOT EXISTS FOR (n:Reference) REQUIRE n.url IS UNIQUE",
    ),
    SchemaStatement(
        "ids_label",
        "CREATE CONSTRAINT ids_label IF NOT EXISTS FOR (n:IDSLabel) REQUIRE n.label IS UNIQUE",
    ),
)

INDEXES = (
    SchemaStatement(
        "technique_name",
        "CREATE INDEX technique_name IF NOT EXISTS FOR (n:Technique) ON (n.name)",
    ),
    SchemaStatement(
        "subtechnique_name",
        "CREATE INDEX subtechnique_name IF NOT EXISTS FOR (n:SubTechnique) ON (n.name)",
    ),
    SchemaStatement(
        "mitigation_name",
        "CREATE INDEX mitigation_name IF NOT EXISTS FOR (n:Mitigation) ON (n.name)",
    ),
    SchemaStatement(
        "group_name",
        "CREATE INDEX group_name IF NOT EXISTS FOR (n:Group) ON (n.name)",
    ),
    SchemaStatement(
        "malware_name",
        "CREATE INDEX malware_name IF NOT EXISTS FOR (n:Malware) ON (n.name)",
    ),
    SchemaStatement(
        "tool_name",
        "CREATE INDEX tool_name IF NOT EXISTS FOR (n:Tool) ON (n.name)",
    ),
    SchemaStatement(
        "capec_name",
        "CREATE INDEX capec_name IF NOT EXISTS FOR (n:CAPECPattern) ON (n.name)",
    ),
    SchemaStatement(
        "cve_severity",
        "CREATE INDEX cve_severity IF NOT EXISTS FOR (n:CVE) ON (n.severity)",
    ),
    SchemaStatement(
        "cve_base_score",
        "CREATE INDEX cve_base_score IF NOT EXISTS FOR (n:CVE) ON (n.base_score)",
    ),
    SchemaStatement(
        "product_vendor",
        "CREATE INDEX product_vendor IF NOT EXISTS FOR (n:Product) ON (n.vendor)",
    ),
    SchemaStatement(
        "product_name",
        "CREATE INDEX product_name IF NOT EXISTS FOR (n:Product) ON (n.product)",
    ),
)


def create_schema(session) -> list[str]:
    """Create constraints and indexes idempotently."""

    applied: list[str] = []
    for statement in (*CONSTRAINTS, *INDEXES):
        session.run(statement.cypher).consume()
        applied.append(statement.name)
    return applied
