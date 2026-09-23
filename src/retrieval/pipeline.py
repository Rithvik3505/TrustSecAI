"""TrustSecAI deterministic graph retrieval pipeline."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path
from typing import Any

from src.retrieval.cache import RetrievalCache
from src.retrieval.context_builder import build_context
from src.retrieval.graph_retriever import GraphRetriever
from src.utils.paths import ARTIFACTS_DIR, PROJECT_ROOT, REPORTS_DIR, ensure_project_dirs


VALIDATION_LABELS = ["PortScan", "FTP-Patator", "Bot", "DDoS", "Web Attack - Sql Injection"]


class RetrievalPipeline:
    """IDS label -> graph retrieval -> ranking -> structured JSON."""

    def __init__(self, retriever: GraphRetriever | None = None, cache: RetrievalCache | None = None) -> None:
        self.retriever = retriever or GraphRetriever()
        self.cache = cache or RetrievalCache()

    def close(self) -> None:
        """Close resources."""

        self.retriever.close()

    def run(self, prediction: str, classifier_confidence: float | None = None, use_cache: bool = True) -> dict[str, Any]:
        """Run the retrieval pipeline for one IDS label."""

        cache_key = f"{prediction}:{classifier_confidence}"
        if use_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached
        raw_context = self.retriever.retrieve(prediction, classifier_confidence)
        structured = build_context(raw_context)
        if use_cache:
            self.cache.set(cache_key, structured)
        return structured


def validate_context(context: dict[str, Any]) -> list[str]:
    """Validate mandatory context fields and duplicate/provenance constraints."""

    errors: list[str] = []
    mandatory = ["prediction", "classifier", "attack", "capec", "cwes", "cves", "products", "references", "groups", "tools", "malware", "detection_guidance", "provenance"]
    for field in mandatory:
        if field not in context:
            errors.append(f"missing field: {field}")
    if not context.get("attack", {}).get("technique"):
        errors.append("missing attack.technique")
    if not context.get("provenance"):
        errors.append("empty provenance")

    for category in ["capec", "cwes", "cves", "products", "references", "groups", "tools", "malware", "detection_guidance"]:
        ids = [item.get("id") for item in context.get(category, [])]
        if len(ids) != len(set(ids)):
            errors.append(f"duplicate entities in {category}")
    return errors


def count_nodes(context: dict[str, Any]) -> int:
    """Count retrieved entities in final context."""

    total = 0
    total += 1 if context.get("attack", {}).get("technique") else 0
    total += len(context.get("attack", {}).get("tactics", []))
    total += len(context.get("attack", {}).get("mitigations", []))
    for category in ["capec", "cwes", "cves", "products", "references", "groups", "tools", "malware", "detection_guidance"]:
        total += len(context.get(category, []))
    return total


def write_json(path: Path, payload: Any) -> None:
    """Write deterministic JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def markdown_table(rows: list[dict[str, Any]]) -> str:
    """Render rows as Markdown."""

    if not rows:
        return "_No rows._"
    headers = list(rows[0].keys())
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(header, "")) for header in headers) + " |")
    return "\n".join(lines)


def write_readiness_report(path: Path, validation_rows: list[dict[str, Any]], contexts: dict[str, dict[str, Any]]) -> None:
    """Write GraphRAG readiness report."""

    latencies = [row["latency_ms"] for row in validation_rows]
    nodes = [row["nodes_retrieved"] for row in validation_rows]
    relationships = [row["relationships_traversed"] for row in validation_rows]
    report = f"""# GraphRAG Readiness Report

## Summary

| Metric | Value |
|---|---:|
| Labels validated | {len(validation_rows)} |
| Average retrieval latency ms | {statistics.mean(latencies):.3f} |
| Max retrieval latency ms | {max(latencies):.3f} |
| Average nodes retrieved | {statistics.mean(nodes):.2f} |
| Average relationships traversed | {statistics.mean(relationships):.2f} |

## Validation Results

{markdown_table(validation_rows)}

## Ranking Behaviour

- Ranking prioritizes shorter graph distance from the IDS label.
- Source/original relationships are preferred over inferred relationships.
- Relationship confidence contributes to score.
- CVEs are boosted by CVSS severity and base score.
- CAPEC patterns are boosted by likelihood and severity when present.

## Known Limitations

- No vector search or semantic expansion is used yet.
- CAPEC to CVE links are inferred through shared CWE and may over-retrieve without asset/product context.
- Some labels resolve to ATT&CK and mitigations but do not have local CAPEC mappings.
- Actor context is evidence of observed technique usage in ATT&CK, not attribution.

## Potential Retrieval Ambiguity

- IDS labels such as `Bot` and broad web attack labels can map to techniques that are context-dependent.
- Inferred CVEs are vulnerability candidates, not confirmed affected assets.
- CAPEC taxonomy coverage is incomplete for some ATT&CK techniques.

## Future LLM Integration Point

The JSON produced by `RetrievalPipeline.run()` should be passed directly as structured context to the future Llama 3.1 prompt. The LLM should be instructed to cite provenance entries and preserve uncertainty.
"""
    path.write_text(report, encoding="utf-8")


def write_api_docs(path: Path) -> None:
    """Write retrieval API documentation."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """# TrustSecAI Retrieval API

## Retriever

`GraphRetriever.retrieve(prediction, classifier_confidence=None)` performs deterministic Cypher retrieval from Neo4j.

Input:

```python
context = retriever.retrieve("PortScan", classifier_confidence=0.98)
```

It retrieves:

- Technique/SubTechnique
- Tactic
- Mitigations
- Groups
- Malware
- Tools
- CAPEC patterns
- CWEs
- CVEs
- Affected products
- References
- Detection guidance

## Ranking

`ranking.py` scores entities using:

- graph distance from IDS label
- relationship confidence
- original vs inferred relationship status
- CVSS severity/base score
- CAPEC likelihood/severity

## Context Builder

`build_context(raw_context)` converts retrieved entities to deterministic JSON.

## Pipeline

`RetrievalPipeline.run(prediction, classifier_confidence=None)` executes:

```text
IDS Label -> Graph Retrieval -> Ranking -> Context Builder -> JSON
```

No LLM is called.

## JSON Schema

Top-level fields:

```json
{
  "prediction": "PortScan",
  "classifier": {"confidence": 0.98},
  "retrieval": {"latency_ms": 0.0, "relationships_traversed": 0},
  "attack": {
    "technique": {},
    "tactics": [],
    "mitigations": []
  },
  "capec": [],
  "cwes": [],
  "cves": [],
  "products": [],
  "references": [],
  "groups": [],
  "tools": [],
  "malware": [],
  "detection_guidance": [],
  "provenance": []
}
```

Every entity includes:

- `id`
- `name`
- `rank_score`
- `distance`
- `properties`
- `provenance`

Every provenance item includes:

- `source`
- `confidence`
- `relationship_type`
- `inferred`
- `origin_node`
- `target_node`
- `method`

## Future LLM Integration

The future Llama 3.1 integration should pass this JSON as structured context. The prompt should require the model to cite graph provenance and distinguish confirmed graph facts from inferred CVE candidates.
""",
        encoding="utf-8",
    )


def run_validation(output_dir: Path = ARTIFACTS_DIR / "retrieval") -> dict[str, Any]:
    """Run validation labels, write examples and reports."""

    ensure_project_dirs()
    output_dir.mkdir(parents=True, exist_ok=True)
    pipeline = RetrievalPipeline()
    contexts: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    try:
        for label in VALIDATION_LABELS:
            started = time.perf_counter()
            context = pipeline.run(label, classifier_confidence=None, use_cache=False)
            elapsed_ms = (time.perf_counter() - started) * 1000
            errors = validate_context(context)
            contexts[label] = context
            write_json(output_dir / f"{label.replace(' ', '_').replace('-', '_')}.json", context)
            rows.append(
                {
                    "label": label,
                    "technique": (context.get("attack", {}).get("technique") or {}).get("id"),
                    "nodes_retrieved": count_nodes(context),
                    "relationships_traversed": context.get("retrieval", {}).get("relationships_traversed", 0),
                    "latency_ms": round(elapsed_ms, 3),
                    "valid": not errors,
                    "errors": "; ".join(errors),
                }
            )
    finally:
        pipeline.close()

    write_json(output_dir / "validation_summary.json", {"results": rows})
    write_readiness_report(REPORTS_DIR / "graphrag_readiness.md", rows, contexts)
    write_api_docs(PROJECT_ROOT / "docs" / "retrieval_api.md")
    return {"results": rows, "output_dir": str(output_dir)}


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Run deterministic graph retrieval pipeline.")
    parser.add_argument("--label", type=str, help="Single IDS label to retrieve.")
    parser.add_argument("--confidence", type=float, default=None)
    parser.add_argument("--validate", action="store_true", help="Run validation suite and write reports.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.validate:
        print(json.dumps(run_validation(), indent=2, sort_keys=True))
        return
    if not args.label:
        raise SystemExit("Provide --label or --validate")
    pipeline = RetrievalPipeline()
    try:
        print(json.dumps(pipeline.run(args.label, args.confidence), indent=2, sort_keys=True))
    finally:
        pipeline.close()


if __name__ == "__main__":
    main()

