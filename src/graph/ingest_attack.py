"""Ingest Enterprise ATT&CK into Neo4j for TrustSecAI."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import psutil

from src.graph.neo4j_utils import batched, get_driver, get_neo4j_config
from src.graph.parse_attack import ENTERPRISE_ATTACK_PATH, AttackParseResult, parse_enterprise_attack
from src.graph.queries import validate_t1046
from src.graph.schema import NODE_LABELS, RELATIONSHIP_TYPES, SCHEMA_VERSION, create_schema
from src.utils.logging import get_logger
from src.utils.paths import GRAPH_ARTIFACTS_DIR, REPORTS_DIR, ensure_project_dirs


LOGGER = get_logger(__name__)

NODE_KEY_BY_LABEL = {
    "Technique": "attack_id",
    "SubTechnique": "attack_id",
    "Tactic": "attack_id",
    "Mitigation": "attack_id",
    "Group": "stix_id",
    "Malware": "stix_id",
    "Tool": "stix_id",
    "Campaign": "stix_id",
    "DetectionStrategy": "stix_id",
}


def _clean_props(item: dict[str, Any]) -> dict[str, Any]:
    """Drop None values because Neo4j properties cannot be null."""

    return {key: value for key, value in item.items() if value is not None}


def _node_merge_query(label: str, merge_key: str) -> str:
    """Return a safe node MERGE query for an approved label."""

    if label not in NODE_LABELS:
        raise ValueError(f"Unsupported label: {label}")
    return f"""
    UNWIND $rows AS row
    MERGE (n:{label} {{{merge_key}: row.{merge_key}}})
    SET n += row
    """


def _relationship_merge_query(rel_type: str) -> str:
    """Return a safe relationship MERGE query for an approved type."""

    if rel_type not in RELATIONSHIP_TYPES:
        raise ValueError(f"Unsupported relationship type: {rel_type}")
    return f"""
    UNWIND $rows AS row
    MATCH (source {{stix_id: row.source_id}})
    MATCH (target {{stix_id: row.target_id}})
    MERGE (source)-[r:{rel_type} {{raw_relationship_id: row.raw_relationship_id}}]->(target)
    SET r += row
    """


def ingest_nodes(session, parsed: AttackParseResult, batch_size: int) -> dict[str, int]:
    """Ingest ATT&CK nodes."""

    counts: dict[str, int] = {}
    for label, nodes in parsed.nodes.items():
        merge_key = NODE_KEY_BY_LABEL[label]
        rows = [_clean_props(node) for node in nodes if node.get(merge_key)]
        query = _node_merge_query(label, merge_key)
        count = 0
        for batch in batched(rows, batch_size):
            session.run(query, {"rows": batch}).consume()
            count += len(batch)
        counts[label] = count
        LOGGER.info("Ingested %s %s nodes", count, label)
    return counts


def ingest_relationships(session, parsed: AttackParseResult, batch_size: int) -> dict[str, int]:
    """Ingest ATT&CK relationships."""

    counts: dict[str, int] = {}
    for rel_type, relationships in parsed.relationships.items():
        rows = [_clean_props(rel) for rel in relationships if rel.get("source_id") and rel.get("target_id") and rel.get("raw_relationship_id")]
        query = _relationship_merge_query(rel_type)
        count = 0
        for batch in batched(rows, batch_size):
            session.run(query, {"rows": batch}).consume()
            count += len(batch)
        counts[rel_type] = count
        LOGGER.info("Ingested %s %s relationships", count, rel_type)
    return counts


def get_node_counts(session) -> dict[str, int]:
    """Return node counts by approved label."""

    counts: dict[str, int] = {}
    for label in NODE_LABELS:
        result = session.run(f"MATCH (n:{label}) RETURN count(n) AS count").single()
        counts[label] = int(result["count"])
    return counts


def get_relationship_counts(session) -> dict[str, int]:
    """Return relationship counts by approved type."""

    counts: dict[str, int] = {}
    for rel_type in RELATIONSHIP_TYPES:
        result = session.run(f"MATCH ()-[r:{rel_type}]->() RETURN count(r) AS count").single()
        counts[rel_type] = int(result["count"])
    return counts


def get_sample_attack_ids(session) -> dict[str, list[str]]:
    """Return sample ATT&CK IDs for export."""

    samples: dict[str, list[str]] = {}
    for label in ("Technique", "SubTechnique", "Tactic", "Mitigation"):
        result = session.run(f"MATCH (n:{label}) WHERE n.attack_id IS NOT NULL RETURN n.attack_id AS id ORDER BY id LIMIT 10")
        samples[label] = [record["id"] for record in result]
    return samples


def write_graph_summary(
    path: Path,
    parsed: AttackParseResult,
    node_counts: dict[str, int],
    relationship_counts: dict[str, int],
    sample_attack_ids: dict[str, list[str]],
) -> None:
    """Write graph summary JSON artifact."""

    payload = {
        "schema_version": SCHEMA_VERSION,
        "attack_version": parsed.attack_version,
        "source_file": parsed.source_file,
        "node_counts_by_label": node_counts,
        "relationship_counts_by_type": relationship_counts,
        "sample_attack_ids": sample_attack_ids,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    LOGGER.info("Wrote graph summary: %s", path)


def write_ingestion_report(
    path: Path,
    parsed: AttackParseResult,
    node_counts: dict[str, int],
    relationship_counts: dict[str, int],
    ingestion_time_seconds: float,
    memory_mb: float,
    validation: dict[str, Any],
    schema_items: list[str],
) -> None:
    """Write graph ingestion Markdown report."""

    node_rows = "\n".join(f"| {label} | {count:,} |" for label, count in node_counts.items())
    rel_rows = "\n".join(f"| {rel_type} | {count:,} |" for rel_type, count in relationship_counts.items())
    warnings = "\n".join(f"- {warning}" for warning in parsed.warnings[:50]) or "- None"
    skipped = "\n".join(f"- `{item.get('id')}`: {item.get('reason')}" for item in parsed.skipped_objects[:50]) or "- None"
    validation_summary = {
        "technique_exists": validation.get("technique") is not None,
        "technique_name": (validation.get("technique") or {}).get("name"),
        "tactics": len(validation.get("tactics") or []),
        "mitigations": len(validation.get("mitigations") or []),
        "related_groups": len(validation.get("related_groups") or []),
        "related_tools": len(validation.get("related_tools") or []),
        "related_malware": len(validation.get("related_malware") or []),
        "detection_guidance": len(validation.get("detection_guidance") or []),
    }
    report = f"""# ATT&CK Graph Ingestion Report

## Summary

| Metric | Value |
|---|---:|
| Schema version | {SCHEMA_VERSION} |
| ATT&CK version | {parsed.attack_version} |
| Ingestion time seconds | {ingestion_time_seconds:.3f} |
| Process RSS memory MB | {memory_mb:.2f} |
| Revoked objects observed | {len(parsed.revoked_objects):,} |
| Deprecated objects observed | {len(parsed.deprecated_objects):,} |
| Skipped objects | {len(parsed.skipped_objects):,} |
| Warnings | {len(parsed.warnings):,} |

## Node Counts

| Label | Count |
|---|---:|
{node_rows}

## Relationship Counts

| Relationship | Count |
|---|---:|
{rel_rows}

## T1046 Validation

```json
{json.dumps(validation_summary, indent=2, sort_keys=True)}
```

## Schema Items Applied

```json
{json.dumps(schema_items, indent=2)}
```

## Warnings

{warnings}

## Skipped Objects

{skipped}

## Notes

- Ingestion uses `MERGE` for idempotent re-runs.
- ATT&CK remains the behavioral spine.
- CAPEC, NVD, GraphRAG, vector search, LLM integration, agreement analysis, and attack-chain prediction were not implemented in this phase.
- Revoked and deprecated objects are preserved with boolean status properties for provenance-aware retrieval.
"""
    path.write_text(report, encoding="utf-8")
    LOGGER.info("Wrote graph ingestion report: %s", path)


def ingest_attack(
    input_path: Path = ENTERPRISE_ATTACK_PATH,
    batch_size: int = 1000,
) -> dict[str, Any]:
    """Parse and ingest Enterprise ATT&CK into Neo4j."""

    ensure_project_dirs()
    start = time.perf_counter()
    parsed = parse_enterprise_attack(input_path)
    config = get_neo4j_config()
    driver = get_driver(config)

    try:
        with driver.session(database=config.database) as session:
            schema_items = create_schema(session)
            node_ingest_counts = ingest_nodes(session, parsed, batch_size)
            relationship_ingest_counts = ingest_relationships(session, parsed, batch_size)
            node_counts = get_node_counts(session)
            relationship_counts = get_relationship_counts(session)
            sample_attack_ids = get_sample_attack_ids(session)
        validation = validate_t1046(driver, config.database)
    finally:
        driver.close()

    ingestion_time_seconds = time.perf_counter() - start
    memory_mb = psutil.Process().memory_info().rss / (1024 * 1024)
    write_graph_summary(
        GRAPH_ARTIFACTS_DIR / "graph_summary.json",
        parsed,
        node_counts,
        relationship_counts,
        sample_attack_ids,
    )
    write_ingestion_report(
        REPORTS_DIR / "graph_ingestion_report.md",
        parsed,
        node_counts,
        relationship_counts,
        ingestion_time_seconds,
        memory_mb,
        validation,
        schema_items,
    )
    return {
        "node_ingest_counts": node_ingest_counts,
        "relationship_ingest_counts": relationship_ingest_counts,
        "node_counts": node_counts,
        "relationship_counts": relationship_counts,
        "validation": validation,
        "ingestion_time_seconds": ingestion_time_seconds,
    }


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Ingest Enterprise ATT&CK into Neo4j.")
    parser.add_argument("--input", type=Path, default=ENTERPRISE_ATTACK_PATH)
    parser.add_argument("--batch-size", type=int, default=1000)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    result = ingest_attack(args.input, args.batch_size)
    print(json.dumps({
        "node_counts": result["node_counts"],
        "relationship_counts": result["relationship_counts"],
        "validation": {
            "technique": result["validation"]["technique"],
            "tactics": len(result["validation"]["tactics"]),
            "mitigations": len(result["validation"]["mitigations"]),
            "related_groups": len(result["validation"]["related_groups"]),
            "related_tools": len(result["validation"]["related_tools"]),
            "related_malware": len(result["validation"]["related_malware"]),
            "detection_guidance": len(result["validation"]["detection_guidance"]),
        },
        "ingestion_time_seconds": result["ingestion_time_seconds"],
    }, indent=2, default=str))


if __name__ == "__main__":
    main()

