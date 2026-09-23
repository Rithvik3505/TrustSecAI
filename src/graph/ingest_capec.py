"""Ingest CAPEC patterns, CWE bridge nodes, and CAPEC/ATT&CK mappings."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from src.graph.cwe_builder import build_cwe_nodes
from src.graph.neo4j_utils import batched, get_driver, get_neo4j_config
from src.graph.parse_capec import CAPEC_PRIMARY_PATH, parse_capec
from src.graph.schema import create_schema
from src.utils.logging import get_logger


LOGGER = get_logger(__name__)


def _clean(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if value is not None}


def ingest_rows(session, query: str, rows: list[dict[str, Any]], batch_size: int, label: str) -> int:
    """Run a batched Cypher ingestion query."""

    count = 0
    for batch in batched([_clean(row) for row in rows], batch_size):
        session.run(query, {"rows": batch}).consume()
        count += len(batch)
    LOGGER.info("Ingested %s %s", count, label)
    return count


def ingest_capec(input_path: Path = CAPEC_PRIMARY_PATH, batch_size: int = 1000) -> dict[str, Any]:
    """Ingest CAPEC into Neo4j."""

    started = time.perf_counter()
    parsed = parse_capec(input_path)
    config = get_neo4j_config()
    driver = get_driver(config)
    counts: dict[str, int] = {}

    try:
        with driver.session(database=config.database) as session:
            create_schema(session)
            counts["CWE"] = ingest_rows(
                session,
                """
                UNWIND $rows AS row
                MERGE (n:CWE {cwe_id: row.cwe_id})
                SET n += row
                """,
                build_cwe_nodes(parsed.cwe_ids, "CAPEC", str(input_path)),
                batch_size,
                "CWE nodes",
            )
            counts["CAPECPattern"] = ingest_rows(
                session,
                """
                UNWIND $rows AS row
                MERGE (n:CAPECPattern {capec_id: row.capec_id})
                SET n += row
                """,
                parsed.patterns,
                batch_size,
                "CAPECPattern nodes",
            )
            for rel_type, rows in parsed.relationships.items():
                counts[rel_type] = ingest_rows(
                    session,
                    f"""
                    UNWIND $rows AS row
                    MATCH (source:CAPECPattern {{capec_id: row.source_id}})
                    MATCH (target:CAPECPattern {{capec_id: row.target_id}})
                    MERGE (source)-[r:{rel_type} {{raw_relationship_id: row.raw_relationship_id}}]->(target)
                    SET r += row
                    """,
                    rows,
                    batch_size,
                    f"{rel_type} relationships",
                )
            counts["RELATED_WEAKNESS"] = ingest_rows(
                session,
                """
                UNWIND $rows AS row
                MATCH (source:CAPECPattern {capec_id: row.source_id})
                MATCH (target:CWE {cwe_id: row.target_id})
                MERGE (source)-[r:RELATED_WEAKNESS {raw_relationship_id: row.raw_relationship_id}]->(target)
                SET r += row
                """,
                parsed.related_weakness,
                batch_size,
                "RELATED_WEAKNESS relationships",
            )
            counts["MAPS_TO_ATTACK"] = ingest_rows(
                session,
                """
                UNWIND $rows AS row
                MATCH (source:CAPECPattern {capec_id: row.source_id})
                MATCH (target)
                WHERE (target:Technique OR target:SubTechnique) AND target.attack_id = row.target_attack_id
                MERGE (source)-[r:MAPS_TO_ATTACK {raw_relationship_id: row.raw_relationship_id}]->(target)
                SET r += row
                """,
                parsed.attack_mappings,
                batch_size,
                "MAPS_TO_ATTACK relationships",
            )
            session.run(
                """
                MATCH (capec:CAPECPattern)-[m:MAPS_TO_ATTACK]->(tech)
                WHERE tech:Technique OR tech:SubTechnique
                MERGE (tech)-[r:HAS_ATTACK_PATTERN {raw_relationship_id: 'inferred:HAS_ATTACK_PATTERN:' + tech.attack_id + ':' + capec.capec_id}]->(capec)
                SET r.source = 'TrustSecAI',
                    r.method = 'inverse_capec_attack_mapping',
                    r.confidence = m.confidence,
                    r.inferred = true,
                    r.ingested_at = m.ingested_at
                """
            ).consume()
            counts["HAS_ATTACK_PATTERN"] = session.run("MATCH ()-[r:HAS_ATTACK_PATTERN]->() RETURN count(r) AS count").single()["count"]
    finally:
        driver.close()

    return {
        "counts": counts,
        "warnings": parsed.warnings,
        "elapsed_seconds": time.perf_counter() - started,
        "patterns": len(parsed.patterns),
        "cwe_ids": len(parsed.cwe_ids),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest CAPEC into Neo4j.")
    parser.add_argument("--input", type=Path, default=CAPEC_PRIMARY_PATH)
    parser.add_argument("--batch-size", type=int, default=1000)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(json.dumps(ingest_capec(args.input, args.batch_size), indent=2, default=str))


if __name__ == "__main__":
    main()

