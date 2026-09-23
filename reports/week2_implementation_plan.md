# Week 2 Implementation Plan

## Scope

Week 2 should implement the knowledge graph foundation for TrustSecAI. This plan is based on the graph dataset analysis and schema design. It does not implement Neo4j, ingestion, GraphRAG, vector stores, or LLM pipelines yet.

## Phase 1: Neo4j Preparation and Ingestion Design

Goal:

- Prepare the local Neo4j data model and ingestion plan.

Tasks:

- Finalize node labels and relationship names from `reports/neo4j_schema.md`.
- Decide Neo4j deployment mode: local desktop, Docker, or managed service.
- Create ingestion configuration files.
- Define data provenance fields.
- Define constraints and indexes.
- Decide how to handle deprecated/revoked ATT&CK objects and rejected CVEs.

Complexity: Medium

Dependencies:

- Neo4j installation
- Python Neo4j driver
- Dataset parser utilities

Risks:

- Schema drift if ingestion starts before ID normalization rules are final.
- Duplicate CVEs due to overlapping NVD feeds.
- Overly broad inferred CVE links through CWE.

## Phase 2: Graph Construction

Goal:

- Build initial graph nodes and relationships from ATT&CK, CAPEC, and NVD.

Recommended order:

1. ATT&CK techniques, sub-techniques, tactics, mitigations.
2. ATT&CK relationships: tactic, sub-technique, mitigation, detection, uses.
3. CAPEC patterns and CAPEC relationships.
4. CAPEC to ATT&CK mappings.
5. CWE bridge nodes.
6. NVD CVE, CPE/product, reference nodes.
7. CVE to CWE and CVE to product/reference relationships.
8. IDS label to ATT&CK mappings.

Complexity: High

Dependencies:

- Robust STIX parser
- CAPEC relationship parser
- NVD deduplication logic
- Batch import strategy

Risks:

- CAPEC taxonomy IDs require normalization to ATT&CK IDs.
- CAPEC text fields are delimiter-heavy.
- NVD configuration trees are nested.
- CWE nodes may be minimal unless CWE metadata is added later.

## Phase 3: Graph Query Layer

Goal:

- Implement reusable query functions for TrustSecAI retrieval.

Core queries:

- `get_technique_context(attack_id)`
- `get_mitigations(attack_id)`
- `get_capec_patterns(attack_id)`
- `get_cves_for_technique(attack_id)`
- `get_actor_tool_malware_context(attack_id)`
- `get_attack_chain_candidates(attack_id)`

Complexity: Medium

Dependencies:

- Neo4j Python driver
- Stable schema and indexes

Risks:

- Queries may over-retrieve without path depth limits.
- CVE retrieval through CWE may need ranking and filtering.

## Phase 4: GraphRAG Retrieval

Goal:

- Convert graph query outputs into compact, ranked context packages for the LLM.

Tasks:

- Define context JSON schema.
- Rank retrieved nodes by directness, confidence, severity, and recency.
- Add provenance to each retrieved fact.
- Create context compression rules.
- Add retrieval tests for labels such as `PortScan`, `DDoS`, `FTP-Patator`, and `Web Attack - Sql Injection`.

Complexity: Medium/high

Dependencies:

- Query layer
- Label mapping
- Ranking functions

Risks:

- Context may become too large for prompts.
- Incorrect ranking can make weak evidence appear authoritative.
- CVE and actor context can cause overclaiming.

## Phase 5: LLM Integration

Goal:

- Feed classifier output, SHAP explanations, and GraphRAG context to the domain-adaptive LLM.

Tasks:

- Define LLM input schema.
- Create prompt templates.
- Include uncertainty and provenance requirements.
- Generate draft security assessment reports.
- Add hooks for agreement analysis.
- Add hooks for attack-chain prediction output.

Complexity: High

Dependencies:

- GraphRAG retrieval
- SHAP output schema
- Model serving/fine-tuning plan

Risks:

- LLM may overstate graph evidence.
- Prompt context may mix confirmed and inferred facts.
- Fine-tuned model availability may constrain implementation.

## Implementation Recommendations

- Build deterministic graph retrieval before adding vector retrieval.
- Use ATT&CK as the graph spine.
- Use CWE as the bridge between CAPEC and NVD.
- Store all inferred relationships with `inferred=true` and `confidence`.
- Keep raw IDs and normalized IDs.
- Create small ingestion tests before importing full datasets.
- Use day-aware IDS results as motivation for GraphRAG uncertainty handling.

## Deliverables for Week 2 Implementation

Suggested implementation deliverables after this design phase:

- `src/graph/schema.py`
- `src/graph/parse_attack.py`
- `src/graph/parse_capec.py`
- `src/graph/parse_nvd.py`
- `src/graph/ingest_neo4j.py`
- `src/graph/queries.py`
- `artifacts/graph/`
- `reports/graph_ingestion_report.md`
- `reports/graphrag_retrieval_report.md`

## Go/No-Go Criteria Before GraphRAG

Proceed to GraphRAG only after:

- ATT&CK technique lookup works by ATT&CK ID.
- IDS label to ATT&CK mapping works.
- Technique to mitigation retrieval works.
- Technique to CAPEC retrieval works.
- CAPEC/CWE/CVE bridge is validated on at least five examples.
- Retrieval output includes provenance and confidence.

