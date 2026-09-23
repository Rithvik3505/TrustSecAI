"""Validation, statistics, and reporting for the completed knowledge graph."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from src.graph.neo4j_utils import get_driver, get_neo4j_config
from src.graph.schema import NODE_LABELS, RELATIONSHIP_TYPES, SCHEMA_VERSION
from src.utils.paths import GRAPH_ARTIFACTS_DIR, REPORTS_DIR, ensure_project_dirs


VALIDATION_LABELS = ["PortScan", "Web Attack - Sql Injection", "FTP-Patator", "DDoS", "Bot"]


def read_query(session, query: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Run a read query and return dictionaries."""

    return [record.data() for record in session.run(query, params or {})]


def node_counts(session) -> dict[str, int]:
    return {label: session.run(f"MATCH (n:{label}) RETURN count(n) AS c").single()["c"] for label in NODE_LABELS}


def relationship_counts(session) -> dict[str, int]:
    return {rel: session.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS c").single()["c"] for rel in RELATIONSHIP_TYPES}


def validate_label(session, label: str) -> dict[str, Any]:
    """Validate expansion path for one IDS label."""

    records = read_query(
        session,
        """
        MATCH (label:IDSLabel {label: $label})-[:DETECTED_AS]->(tech)
        OPTIONAL MATCH (tech)-[:HAS_TACTIC]->(tactic:Tactic)
        OPTIONAL MATCH (tech)-[:MITIGATED_BY]->(mitigation:Mitigation)
        OPTIONAL MATCH (tech)-[:HAS_ATTACK_PATTERN]->(capec:CAPECPattern)
        OPTIONAL MATCH (capec)-[:RELATED_WEAKNESS]->(cwe:CWE)
        OPTIONAL MATCH (capec)-[:ASSOCIATED_CVE]->(cve:CVE)
        OPTIONAL MATCH (cve)-[:AFFECTS]->(product:Product)
        RETURN tech.attack_id AS attack_id,
               tech.name AS technique,
               collect(DISTINCT tactic.name) AS tactics,
               count(DISTINCT mitigation) AS mitigations,
               count(DISTINCT capec) AS capec_patterns,
               count(DISTINCT cwe) AS cwes,
               count(DISTINCT cve) AS cves,
               count(DISTINCT product) AS products
        """,
        {"label": label},
    )
    if not records:
        return {"label": label, "resolved": False}
    result = records[0]
    return {"label": label, "resolved": result["attack_id"] is not None, **result}


def graph_density(total_nodes: int, total_relationships: int) -> float:
    """Directed graph density estimate."""

    if total_nodes <= 1:
        return 0.0
    return total_relationships / (total_nodes * (total_nodes - 1))


def collect_statistics(session) -> dict[str, Any]:
    """Collect graph analytics requested for reporting."""

    counts = node_counts(session)
    rel_counts = relationship_counts(session)
    total_nodes = sum(counts.values())
    total_relationships = sum(rel_counts.values())
    degree_techniques = read_query(
        session,
        """
        MATCH (t)
        WHERE t:Technique OR t:SubTechnique
        OPTIONAL MATCH (t)-[r]-()
        RETURN t.attack_id AS attack_id, t.name AS name, count(r) AS degree
        ORDER BY degree DESC
        LIMIT 20
        """,
    )
    degree_capec = read_query(
        session,
        """
        MATCH (c:CAPECPattern)
        OPTIONAL MATCH (c)-[r]-()
        RETURN c.capec_id AS capec_id, c.name AS name, count(r) AS degree
        ORDER BY degree DESC
        LIMIT 20
        """,
    )
    top_cwes = read_query(
        session,
        """
        MATCH (cwe:CWE)
        OPTIONAL MATCH (cwe)-[r]-()
        RETURN cwe.cwe_id AS cwe_id, count(r) AS references
        ORDER BY references DESC
        LIMIT 20
        """,
    )
    top_cves = read_query(
        session,
        """
        MATCH (cve:CVE)
        OPTIONAL MATCH (cve)-[r]-()
        RETURN cve.cve_id AS cve_id, cve.severity AS severity, cve.base_score AS base_score, count(r) AS references
        ORDER BY references DESC
        LIMIT 20
        """,
    )
    component_count = connected_components_count(session)
    isolated = read_query(
        session,
        """
        MATCH (n)
        WHERE NOT (n)--()
        RETURN labels(n)[0] AS label, coalesce(n.attack_id, n.capec_id, n.cwe_id, n.cve_id, n.label, n.name, n.url, n.cpe_uri) AS id
        LIMIT 50
        """,
    )
    isolated_count = session.run("MATCH (n) WHERE NOT (n)--() RETURN count(n) AS c").single()["c"]
    return {
        "node_counts": counts,
        "relationship_counts": rel_counts,
        "total_nodes": total_nodes,
        "total_relationships": total_relationships,
        "graph_density": graph_density(total_nodes, total_relationships),
        "average_node_degree": (2 * total_relationships / total_nodes) if total_nodes else 0,
        "connected_components_estimate": component_count,
        "isolated_node_count": isolated_count,
        "isolated_node_samples": isolated,
        "top_20_highest_degree_techniques": degree_techniques,
        "top_20_highest_degree_capec_patterns": degree_capec,
        "top_referenced_cwes": top_cwes,
        "top_referenced_cves": top_cves,
    }


def connected_components_count(session) -> int:
    """Compute weakly connected components with union-find over direct graph edges."""

    node_ids = [record["id"] for record in session.run("MATCH (n) RETURN elementId(n) AS id")]
    parent = {node_id: node_id for node_id in node_ids}

    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        root_left = find(left)
        root_right = find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    for record in session.run("MATCH (a)-[r]->(b) RETURN elementId(a) AS a, elementId(b) AS b"):
        union(record["a"], record["b"])
    return len({find(node_id) for node_id in node_ids})


def markdown_table(rows: list[dict[str, Any]]) -> str:
    """Render rows as markdown table."""

    if not rows:
        return "_No rows._"
    headers = list(rows[0].keys())
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(header, "")) for header in headers) + " |")
    return "\n".join(lines)


def write_statistics_report(path: Path, stats: dict[str, Any]) -> None:
    """Write graph statistics report."""

    node_rows = [{"label": k, "count": v} for k, v in stats["node_counts"].items()]
    rel_rows = [{"relationship": k, "count": v} for k, v in stats["relationship_counts"].items()]
    report = f"""# Knowledge Graph Statistics

## Summary

| Metric | Value |
|---|---:|
| Total nodes | {stats['total_nodes']:,} |
| Total relationships | {stats['total_relationships']:,} |
| Graph density | {stats['graph_density']:.8f} |
| Average node degree | {stats['average_node_degree']:.4f} |
| Connected components estimate | {stats['connected_components_estimate']} |
| Isolated nodes | {stats['isolated_node_count']:,} |

## Node Counts

{markdown_table(node_rows)}

## Relationship Counts

{markdown_table(rel_rows)}

## Top 20 Highest-Degree Techniques

{markdown_table(stats['top_20_highest_degree_techniques'])}

## Top 20 Highest-Degree CAPEC Patterns

{markdown_table(stats['top_20_highest_degree_capec_patterns'])}

## Top Referenced CWEs

{markdown_table(stats['top_referenced_cwes'])}

## Top Referenced CVEs

{markdown_table(stats['top_referenced_cves'])}

## Isolated Node Samples

{markdown_table(stats['isolated_node_samples'])}
"""
    path.write_text(report, encoding="utf-8")


def write_kg_report(path: Path, stats: dict[str, Any], validations: list[dict[str, Any]], data_quality: list[str]) -> None:
    """Write summary knowledge graph report."""

    report = f"""# TrustSecAI Knowledge Graph Report

## Summary

The TrustSecAI graph now contains ATT&CK, CAPEC, CWE, NVD/CVE, product/reference, and IDS label mapping layers. ATT&CK remains the behavioral spine. CAPEC and NVD are connected through CWE bridge nodes, and inferred relationships are explicitly marked.

## Total Graph Size

- Total nodes: {stats['total_nodes']:,}
- Total relationships: {stats['total_relationships']:,}

## Validation Results

{markdown_table(validations)}

## Data Quality Issues

{chr(10).join(f'- {issue}' for issue in data_quality) if data_quality else '- None'}

## Remaining Work Before GraphRAG

- Implement ranked graph retrieval functions.
- Add context packaging for LLM prompts.
- Add query tests for key IDS labels.
- Add retrieval provenance filtering.
- Tune inferred CVE retrieval to avoid over-broad CWE matches.

## Not Implemented In This Phase

- GraphRAG
- Vector embeddings
- LLM integration
- LoRA
- Agreement analysis
- Attack-chain agent
"""
    path.write_text(report, encoding="utf-8")


def validate_and_report() -> dict[str, Any]:
    """Validate the completed graph and write reports/artifacts."""

    ensure_project_dirs()
    config = get_neo4j_config()
    driver = get_driver(config)
    try:
        with driver.session(database=config.database) as session:
            validations = [validate_label(session, label) for label in VALIDATION_LABELS]
            all_label_resolution = read_query(
                session,
                """
                MATCH (label:IDSLabel)
                RETURN label.label AS label, EXISTS { MATCH (label)-[:DETECTED_AS]->() } AS resolved
                ORDER BY label
                """,
            )
            stats = collect_statistics(session)
    finally:
        driver.close()

    data_quality = []
    unresolved = [row["label"] for row in all_label_resolution if not row["resolved"]]
    if unresolved:
        data_quality.append(f"Unresolved IDS labels: {', '.join(unresolved)}")
    no_capec = [row["label"] for row in validations if row.get("resolved") and row.get("capec_patterns", 0) == 0]
    if no_capec:
        data_quality.append(
            "Resolved IDS labels without direct CAPEC expansion from local CAPEC taxonomy mappings: "
            + ", ".join(no_capec)
        )
    data_quality.append("CAPEC to CVE links are inferred through shared CWE and may over-retrieve without asset context.")
    data_quality.append("NVD local feeds are partial/recent snapshots, not a full historical NVD mirror.")

    write_statistics_report(REPORTS_DIR / "graph_statistics.md", stats)
    write_kg_report(REPORTS_DIR / "knowledge_graph_report.md", stats, validations, data_quality)
    summary = {"schema_version": SCHEMA_VERSION, **stats, "validation_results": validations, "ids_label_resolution": all_label_resolution}
    (GRAPH_ARTIFACTS_DIR / "complete_graph_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return summary


def main() -> None:
    print(json.dumps(validate_and_report(), indent=2, default=str))


if __name__ == "__main__":
    main()
