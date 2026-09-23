"""Neo4j connection and execution helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Iterable

from neo4j import GraphDatabase


@dataclass(frozen=True)
class Neo4jConfig:
    """Neo4j connection configuration."""

    uri: str
    user: str
    password: str
    database: str | None = None


def get_neo4j_config() -> Neo4jConfig:
    """Read Neo4j configuration from environment variables."""

    return Neo4jConfig(
        uri=os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687"),
        user=os.getenv("NEO4J_USER", "neo4j"),
        password=os.getenv("NEO4J_PASSWORD", "password"),
        database=os.getenv("NEO4J_DATABASE") or None,
    )


def get_driver(config: Neo4jConfig | None = None):
    """Create and verify a Neo4j driver."""

    cfg = config or get_neo4j_config()
    driver = GraphDatabase.driver(cfg.uri, auth=(cfg.user, cfg.password))
    driver.verify_connectivity()
    return driver


def run_read(driver, query: str, parameters: dict[str, Any] | None = None, database: str | None = None) -> list[dict[str, Any]]:
    """Run a read query and return record dictionaries."""

    with driver.session(database=database) as session:
        result = session.run(query, parameters or {})
        return [record.data() for record in result]


def run_write(driver, query: str, parameters: dict[str, Any] | None = None, database: str | None = None) -> None:
    """Run a write query."""

    with driver.session(database=database) as session:
        session.execute_write(lambda tx: tx.run(query, parameters or {}).consume())


def batched(items: list[dict[str, Any]], batch_size: int) -> Iterable[list[dict[str, Any]]]:
    """Yield list batches."""

    for index in range(0, len(items), batch_size):
        yield items[index : index + batch_size]
