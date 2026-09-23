"""Ingest TrustSecAI IDS label to ATT&CK mappings."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.graph.neo4j_utils import batched, get_driver, get_neo4j_config
from src.graph.schema import create_schema
from src.utils.logging import get_logger
from src.utils.paths import ARTIFACTS_DIR


LOGGER = get_logger(__name__)
DEFAULT_MAPPING_PATH = ARTIFACTS_DIR / "attack_label_mapping.json"


def load_label_mapping(path: Path = DEFAULT_MAPPING_PATH) -> list[dict[str, Any]]:
    """Load IDS label mapping rows."""

    data = json.loads(path.read_text(encoding="utf-8"))
    ingested_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    rows = []
    for label, mapping in data.items():
        rows.append(
            {
                "label": label,
                "binary_label": 1,
                "description": f"TrustSecAI IDS attack label: {label}",
                "attack_id": mapping["attack_id"],
                "attack_name": mapping.get("attack_name"),
                "confidence": mapping.get("confidence"),
                "rationale": mapping.get("rationale"),
                "source": "TrustSecAI",
                "source_file": str(path),
                "raw_id": label,
                "raw_relationship_id": f"{label}:DETECTED_AS:{mapping['attack_id']}",
                "inferred": False,
                "ingested_at": ingested_at,
            }
        )
    return rows


def ingest_ids(mapping_path: Path = DEFAULT_MAPPING_PATH, batch_size: int = 1000) -> dict[str, Any]:
    """Ingest IDSLabel nodes and DETECTED_AS relationships."""

    rows = load_label_mapping(mapping_path)
    config = get_neo4j_config()
    driver = get_driver(config)
    try:
        with driver.session(database=config.database) as session:
            create_schema(session)
            count = 0
            for batch in batched(rows, batch_size):
                session.run(
                    """
                    UNWIND $rows AS row
                    MERGE (label:IDSLabel {label: row.label})
                    SET label.binary_label = row.binary_label,
                        label.description = row.description,
                        label.source = row.source,
                        label.source_file = row.source_file,
                        label.raw_id = row.raw_id,
                        label.ingested_at = row.ingested_at
                    WITH row, label
                    MATCH (tech)
                    WHERE (tech:Technique OR tech:SubTechnique) AND tech.attack_id = row.attack_id
                    MERGE (label)-[r:DETECTED_AS {raw_relationship_id: row.raw_relationship_id}]->(tech)
                    SET r.source = row.source,
                        r.source_file = row.source_file,
                        r.confidence = row.confidence,
                        r.rationale = row.rationale,
                        r.inferred = row.inferred,
                        r.ingested_at = row.ingested_at,
                        r.attack_name = row.attack_name
                    """,
                    {"rows": batch},
                ).consume()
                count += len(batch)
            unresolved = session.run(
                """
                MATCH (label:IDSLabel)
                WHERE NOT (label)-[:DETECTED_AS]->()
                RETURN label.label AS label
                ORDER BY label
                """
            )
            unresolved_labels = [record["label"] for record in unresolved]
    finally:
        driver.close()
    LOGGER.info("Ingested %s IDS labels", count)
    return {"ids_labels": count, "unresolved_labels": unresolved_labels}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest IDS label mappings.")
    parser.add_argument("--mapping", type=Path, default=DEFAULT_MAPPING_PATH)
    parser.add_argument("--batch-size", type=int, default=1000)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(json.dumps(ingest_ids(args.mapping, args.batch_size), indent=2))


if __name__ == "__main__":
    main()

