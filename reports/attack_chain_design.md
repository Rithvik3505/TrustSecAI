# Attack Chain Prediction Design

## Objective

Design how TrustSecAI will predict likely next attack stages using the future knowledge graph. This is design-only; no attack-chain algorithm is implemented in this phase.

## Starting Point

Attack-chain prediction should begin from the mapped ATT&CK technique produced by GraphRAG.

Example:

```text
Classifier: PortScan
Mapped Technique: T1046 Network Service Discovery
Tactic: Discovery
```

The prediction task is to identify plausible next techniques or tactics, not to claim certainty.

## Useful Graph Evidence

### ATT&CK Evidence

Useful ATT&CK structures:

- `Technique -HAS_TACTIC-> Tactic`
- `SubTechnique -SUBTECHNIQUE_OF-> Technique`
- `Group/Malware/Tool/Campaign -USES_TECHNIQUE-> Technique`
- `Technique -MITIGATED_BY-> Mitigation`
- `Technique -DETECTED_BY-> DetectionStrategy`

ATT&CK does not provide a universal ordered kill chain from one technique to the next. Technique ordering should therefore be inferred cautiously.

Useful inferred signals:

- techniques used by the same groups
- techniques used by the same malware
- techniques used by the same campaigns
- techniques in later tactics
- techniques linked through CAPEC `CanPrecede` relationships

### CAPEC Evidence

Useful CAPEC relationships:

- `CAN_PRECEDE`
- `CAN_FOLLOW`
- `CHILD_OF`
- `PEER_OF`
- `CAN_ALSO_BE`

`CAN_PRECEDE` and `CAN_FOLLOW` are the most directly useful for attack-chain prediction. `CHILD_OF` is useful for abstraction expansion but should not be treated as temporal sequence.

### CVE Evidence

CVE data can support attack-chain prediction when vulnerability exploitation is plausible:

```text
Technique -> CAPECPattern -> CWE <- CVE -> Product
```

Use CVE context to prioritize likely exploitation paths only when asset/product context exists. Without asset context, CVEs should be treated as generic vulnerability intelligence.

## Traversal Strategy

Recommended traversal pipeline:

1. Start from the mapped technique.
2. Expand to tactics.
3. Expand to CAPEC patterns mapped to that technique.
4. Follow CAPEC `CAN_PRECEDE` and `CAN_FOLLOW`.
5. Map resulting CAPEC patterns back to ATT&CK techniques where possible.
6. Expand to techniques co-used by the same malware/groups/tools.
7. Rank candidates by tactic progression, path confidence, and evidence count.

## Example: PortScan

```text
PortScan
↓ DETECTED_AS
T1046 Network Service Discovery
↓ HAS_TACTIC
Discovery
↓ likely progression
Credential Access / Initial Access / Lateral Movement candidates
↓ candidate examples
T1110 Brute Force
T1021 Remote Services
T1040 Network Sniffing
```

This is a hypothesis path, not a deterministic claim.

## Graph Algorithms

### Breadth-First Search

Use BFS for bounded neighborhood expansion.

Recommended use:

- retrieve 1-hop and 2-hop technique/CAPEC neighborhoods
- avoid missing close related context

Default depth:

- depth 1 for primary context
- depth 2 for attack-chain candidates
- depth 3 only with strict relationship filters

### Shortest Path

Use shortest path to explain how two techniques are connected.

Recommended use:

- explain why a predicted next technique was suggested
- validate relation between starting technique and candidate

### Weighted Path Ranking

Use weighted traversal rather than raw shortest path for final ranking.

Suggested weights:

- `CAN_PRECEDE`: high
- `CAN_FOLLOW`: high
- same campaign uses both techniques: medium/high
- same malware uses both techniques: medium
- same group uses both techniques: medium
- same tactic only: low
- shared CWE only: low/medium

### PageRank

Use PageRank as a background importance score, not as the main chain predictor.

Recommended use:

- prioritize central techniques or CAPEC patterns
- support ranking when multiple candidates have similar path evidence

### Community Detection

Use community detection for offline analysis of technique clusters.

Recommended use:

- identify clusters of related techniques, malware, and groups
- support research analysis and graph quality checks

### DFS

Use DFS only for path enumeration with tight limits.

Risk:

- can produce long speculative chains.

## Candidate Ranking Formula

Initial scoring design:

```text
score =
  relationship_weight
  + tactic_progression_weight
  + mapping_confidence_weight
  + evidence_count_weight
  + cvss_weight_if_asset_context_exists
  + shap_context_weight
```

Candidate fields:

- candidate technique
- candidate tactic
- path used
- evidence nodes
- confidence score
- explanation
- recommended mitigations

## Useful Tactic Progression

ATT&CK tactics can guide coarse progression:

```text
Reconnaissance / Discovery
↓
Initial Access / Credential Access
↓
Execution / Persistence / Privilege Escalation
↓
Defense Evasion / Lateral Movement
↓
Collection / Exfiltration / Impact
```

Do not force every incident into this order. Use it only as a ranking prior.

## Output Design

Attack-chain prediction should return:

```json
{
  "current_technique": "T1046",
  "current_stage": "Discovery",
  "likely_next_steps": [
    {
      "technique_id": "T1110",
      "name": "Brute Force",
      "tactic": "Credential Access",
      "confidence": 0.62,
      "evidence_path": [
        "T1046",
        "CAPEC pattern",
        "T1110"
      ],
      "recommended_mitigations": []
    }
  ]
}
```

## Risks

- ATT&CK relationships are not inherently temporal.
- CAPEC sequence relationships are partial and not available for all patterns.
- Co-use by the same group or malware does not prove sequence.
- Without host, asset, service, and timeline context, attack-chain prediction is probabilistic.
- CVE enrichment can overfit to generic weaknesses.

## Recommendation

Use bounded BFS plus weighted path ranking as the first attack-chain strategy. Add PageRank/community scores later as ranking features, not as replacements for explicit relationship evidence.

