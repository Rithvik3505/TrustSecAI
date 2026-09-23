# GraphRAG Integration Design

## Objective

Design how TrustSecAI will connect classifier output and SHAP explanations to the future Neo4j knowledge graph and LLM. This is design-only; no GraphRAG, vector store, Neo4j import, or LLM code is implemented here.

## Pipeline Context

Current intended pipeline:

```text
XGBoost
↓
SHAP
↓
GraphRAG
↓
Fine-Tuned LLM
↓
Agreement Analysis
↓
Attack Chain Prediction
```

## Inputs to GraphRAG

GraphRAG should receive a structured incident object:

```json
{
  "prediction": "PortScan",
  "binary_label": 1,
  "confidence": 0.97,
  "top_shap_features": [
    {
      "feature": "Destination Port",
      "value": 80,
      "shap_value": 0.036
    }
  ],
  "source_file": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
}
```

Required fields:

- classifier prediction
- classifier confidence
- binary attack decision
- top SHAP features
- source file or incident metadata

Optional future fields:

- destination port
- protocol
- flow duration
- packet statistics
- analyst feedback
- observed asset/service context

## Label to Technique Entry Point

The first graph hop should use `IDSLabel -DETECTED_AS-> Technique/SubTechnique`.

Example:

```text
PortScan
↓ DETECTED_AS
T1046 Network Service Discovery
```

Starter mappings live in:

- `artifacts/attack_label_mapping.json`

The graph should preserve mapping confidence and rationale.

## Retrieval Flow

Example for `PortScan`:

```text
XGBoost predicts PortScan
↓
Lookup IDSLabel(label="PortScan")
↓
Traverse DETECTED_AS
↓
Retrieve ATT&CK Technique T1046
↓
Retrieve:
  - Tactics
  - Sub-techniques or parent techniques
  - CAPEC patterns mapped to T1046
  - Related CWE weaknesses
  - CVEs sharing those CWE weaknesses
  - Mitigations
  - Detection strategies
  - Groups, malware, tools, campaigns that use T1046
↓
Rank and compress context
↓
Pass context to LLM
```

## Graph Query Categories

### Primary Technique Context

Retrieve:

- technique name
- ATT&CK ID
- description
- tactics
- platforms
- detection guidance

### Mitigation Context

Retrieve:

- mitigations connected by `MITIGATED_BY`
- mitigation descriptions
- mitigation IDs

### CAPEC Context

Retrieve:

- CAPEC patterns connected by `MAPS_TO_ATTACK`
- execution flow
- prerequisites
- consequences
- CAPEC mitigations
- CAPEC indicators

### CVE Context

Retrieve through CWE:

```text
Technique <-MAPS_TO_ATTACK- CAPECPattern -RELATED_WEAKNESS-> CWE <-HAS_WEAKNESS- CVE
```

Rank CVEs by:

- severity
- CVSS base score
- recency
- status
- whether affected product matches observed environment, if available

### Actor and Tool Context

Retrieve:

- groups that use the technique
- malware that uses the technique
- tools that use the technique
- campaigns linked to the technique

This context should be summarized carefully to avoid implying attribution from a single IDS alert.

## Context Ranking

Recommended ranking signals:

1. Directness of graph path.
2. Mapping confidence.
3. ATT&CK/CAPEC relationship type.
4. CVSS severity and score.
5. Recency for CVEs.
6. Match with SHAP features, for example port/service-related features.
7. Analyst feedback in later phases.

Suggested retrieval limits:

- 1 primary technique
- up to 3 tactics
- up to 5 CAPEC patterns
- up to 10 CVEs
- up to 5 mitigations
- up to 5 detection strategies
- up to 5 related tools/malware/groups

## LLM Context Package

The graph should produce a compact JSON context package:

```json
{
  "classifier": {
    "prediction": "PortScan",
    "confidence": 0.97,
    "top_features": []
  },
  "attack_mapping": {
    "attack_id": "T1046",
    "name": "Network Service Discovery",
    "mapping_confidence": "high"
  },
  "tactics": [],
  "capec_patterns": [],
  "cves": [],
  "mitigations": [],
  "detections": [],
  "provenance": []
}
```

## Prompt Use

The LLM should use GraphRAG context to produce:

- primary assessment
- why the classifier likely predicted the class
- relevant ATT&CK mapping
- related attack patterns
- plausible consequences
- recommended mitigations
- confidence and uncertainty

The LLM should be instructed not to overclaim attribution, malware family, or specific CVEs unless graph evidence supports the claim.

## Agreement Analysis Hook

Later agreement analysis should compare:

- classifier label
- SHAP-supported reasoning
- graph-retrieved ATT&CK/CAPEC/CVE evidence
- LLM assessment

Example:

```text
Classifier: PortScan
Graph: T1046 Network Service Discovery
LLM: reconnaissance/service discovery
Agreement: high
```

## Design Risks

- IDS labels are broad and may map to multiple ATT&CK techniques.
- CAPEC to ATT&CK mappings need ID normalization and confidence handling.
- CVE retrieval through CWE can over-retrieve unrelated vulnerabilities.
- Graph context can create false specificity if not ranked and summarized carefully.
- LLM prompts must preserve uncertainty.

## Recommendation

GraphRAG should begin with deterministic graph retrieval before adding vector retrieval. Use the graph to enforce provenance and relationship correctness, then optionally add embeddings for long descriptions, CAPEC execution flows, and CVE descriptions.

