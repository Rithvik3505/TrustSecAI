# ATT&CK Graph Ingestion Report

## Summary

| Metric | Value |
|---|---:|
| Schema version | attack-v1 |
| ATT&CK version | 19.1 |
| Ingestion time seconds | 165.211 |
| Process RSS memory MB | 203.82 |
| Revoked objects observed | 157 |
| Deprecated objects observed | 289 |
| Skipped objects | 0 |
| Warnings | 0 |

## Node Counts

| Label | Count |
|---|---:|
| Technique | 365 |
| SubTechnique | 493 |
| Tactic | 15 |
| Mitigation | 268 |
| Group | 189 |
| Malware | 729 |
| Tool | 95 |
| Campaign | 56 |
| DetectionStrategy | 699 |

## Relationship Counts

| Relationship | Count |
|---|---:|
| HAS_TACTIC | 1,090 |
| SUBTECHNIQUE_OF | 477 |
| MITIGATED_BY | 1,448 |
| USES_TECHNIQUE | 16,903 |
| USES_TOOL | 553 |
| USES_MALWARE | 764 |
| ATTRIBUTED_TO | 26 |
| DETECTED_BY | 697 |

## T1046 Validation

```json
{
  "detection_guidance": 1,
  "mitigations": 3,
  "related_groups": 31,
  "related_malware": 26,
  "related_tools": 9,
  "tactics": 1,
  "technique_exists": true,
  "technique_name": "Network Service Discovery"
}
```

## Schema Items Applied

```json
[
  "technique_attack_id",
  "subtechnique_attack_id",
  "tactic_attack_id",
  "mitigation_attack_id",
  "group_stix_id",
  "malware_stix_id",
  "tool_stix_id",
  "campaign_stix_id",
  "detection_strategy_stix_id",
  "technique_name",
  "subtechnique_name",
  "mitigation_name",
  "group_name",
  "malware_name",
  "tool_name"
]
```

## Warnings

- None

## Skipped Objects

- None

## Notes

- Ingestion uses `MERGE` for idempotent re-runs.
- ATT&CK remains the behavioral spine.
- CAPEC, NVD, GraphRAG, vector search, LLM integration, agreement analysis, and attack-chain prediction were not implemented in this phase.
- Revoked and deprecated objects are preserved with boolean status properties for provenance-aware retrieval.
