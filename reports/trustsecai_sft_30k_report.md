# TrustSecAI Final Corpus Report

## Summary

- Final examples: 30000
- Accepted by validation: 30000
- Rejected by validation: 0
- Validation warnings: 0
- Negative examples: 9000
- Multi-turn examples: 3000
- Agreement-analysis examples: 9000
- Average response length: 176.48 words
- Vocabulary diversity: 0.6628

## Generation Scope

The final corpus was generated from IDS predictions, SHAP feature evidence, and Graph Retrieval JSON. No LoRA training, model inference, Neo4j changes, GraphRAG changes, IDS changes, or SHAP regeneration were performed.

## Quality Improvements

- SOC-style analyst language with varied reasoning structures.
- Natural SHAP feature summaries using only supplied feature names.
- Confidence-aware wording for high, medium, and low confidence cases.
- Executive summaries focused on business impact, operational risk, confidence, and recommended action.
- Explicit uncertainty language for missing graph evidence, candidate CVEs, and non-attribution of actor/tool/malware context.
- Compact graph descriptions while preserving IDs, relationships, provenance, confidence, and retrieval structure.

## Distribution

### Difficulty

| Difficulty | Count |
|---|---:|
| easy | 6760 |
| expert | 7720 |
| hard | 7760 |
| medium | 7760 |

### Tasks

| Task | Count |
|---|---:|
| attack_mapping | 3375 |
| executive_summary | 3375 |
| incident_report_generation | 3375 |
| mitigation_recommendation | 3375 |
| multi_turn_security_analysis | 3000 |
| security_analyst_reasoning | 3375 |
| threat_assessment | 3375 |
| uncertainty_analysis | 3375 |
| vulnerability_summary | 3375 |

### IDS Labels

| Label | Count |
|---|---:|
| Bot | 6000 |
| DDoS | 6000 |
| FTP-Patator | 6000 |
| PortScan | 6000 |
| Web Attack - Sql Injection | 6000 |

## Known Limitations

- Local retrieval artifacts currently cover five IDS labels; final label coverage depends on exported retrieval contexts.
- Synthetic examples are deterministic and should receive manual review before LoRA training.
- CVE relevance remains candidate context unless asset evidence confirms exposure.
- Group, tool, malware, and campaign context remains behavior-usage context, not attribution.
