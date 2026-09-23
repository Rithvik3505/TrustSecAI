"""Ingest NVD/CVE, product, reference, and inferred CVE relationships."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from src.graph.cwe_builder import build_cwe_nodes
from src.graph.neo4j_utils import batched, get_driver, get_neo4j_config
from src.graph.parse_nvd import NVD_DIR, parse_nvd
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


def ingest_nvd(nvd_dir: Path = NVD_DIR, batch_size: int = 1000) -> dict[str, Any]:
    """Ingest local NVD feeds into Neo4j."""

    started = time.perf_counter()
    parsed = parse_nvd(nvd_dir)
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
                build_cwe_nodes(parsed.cwe_ids, "NVD", ";".join(parsed.source_files)),
                batch_size,
                "CWE nodes",
            )
            counts["CVE"] = ingest_rows(
                session,
                """
                UNWIND $rows AS row
                MERGE (n:CVE {cve_id: row.cve_id})
                SET n += row
                """,
                parsed.cves,
                batch_size,
                "CVE nodes",
            )
            counts["Product"] = ingest_rows(
                session,
                """
                UNWIND $rows AS row
                MERGE (n:Product {cpe_uri: row.cpe_uri})
                SET n += row
                """,
                parsed.products,
                batch_size,
                "Product nodes",
            )
            counts["Reference"] = ingest_rows(
                session,
                """
                UNWIND $rows AS row
                MERGE (n:Reference {url: row.url})
                SET n += row
                """,
                parsed.references,
                batch_size,
                "Reference nodes",
            )
            counts["HAS_WEAKNESS"] = ingest_rows(
                session,
                """
                UNWIND $rows AS row
                MATCH (source:CVE {cve_id: row.source_id})
                MATCH (target:CWE {cwe_id: row.target_id})
                MERGE (source)-[r:HAS_WEAKNESS {raw_relationship_id: row.raw_relationship_id}]->(target)
                SET r += row
                """,
                parsed.has_weakness,
                batch_size,
                "HAS_WEAKNESS relationships",
            )
            counts["AFFECTS"] = ingest_rows(
                session,
                """
                UNWIND $rows AS row
                MATCH (source:CVE {cve_id: row.source_id})
                MATCH (target:Product {cpe_uri: row.target_id})
                MERGE (source)-[r:AFFECTS {raw_relationship_id: row.raw_relationship_id}]->(target)
                SET r += row
                """,
                parsed.affects,
                batch_size,
                "AFFECTS relationships",
            )
            counts["REFERENCES"] = ingest_rows(
                session,
                """
                UNWIND $rows AS row
                MATCH (source:CVE {cve_id: row.source_id})
                MATCH (target:Reference {url: row.target_id})
                MERGE (source)-[r:REFERENCES {raw_relationship_id: row.raw_relationship_id}]->(target)
                SET r += row
                """,
                parsed.reference_edges,
                batch_size,
                "REFERENCES relationships",
            )
            session.run(
                """
                MATCH (capec:CAPECPattern)-[:RELATED_WEAKNESS]->(cwe:CWE)<-[:HAS_WEAKNESS]-(cve:CVE)
                MERGE (capec)-[r:ASSOCIATED_CVE {raw_relationship_id: 'inferred:ASSOCIATED_CVE:' + capec.capec_id + ':' + cve.cve_id}]->(cve)
                SET r.source = 'TrustSecAI',
                    r.method = 'shared_cwe_bridge',
                    r.confidence = 'medium',
                    r.inferred = true
                """
            ).consume()
            counts["ASSOCIATED_CVE"] = session.run("MATCH ()-[r:ASSOCIATED_CVE]->() RETURN count(r) AS count").single()["count"]
    finally:
        driver.close()

    return {
        "counts": counts,
        "elapsed_seconds": time.perf_counter() - started,
        "cves": len(parsed.cves),
        "products": len(parsed.products),
        "references": len(parsed.references),
        "rejected_cves": len(parsed.rejected_cves),
        "warnings": parsed.warnings,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest NVD into Neo4j.")
    parser.add_argument("--nvd-dir", type=Path, default=NVD_DIR)
    parser.add_argument("--batch-size", type=int, default=1000)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(json.dumps(ingest_nvd(args.nvd_dir, args.batch_size), indent=2, default=str))


if __name__ == "__main__":
    main()

