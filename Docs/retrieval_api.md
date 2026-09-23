# TrustSecAI Retrieval API

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
