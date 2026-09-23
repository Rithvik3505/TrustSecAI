# TrustSecAI SFT 30k Statistics

## Summary

- Examples: 30000
- Accepted by validation: 30000
- Rejected by validation: 0
- Validation warnings: 0
- JSON schema: unchanged
- Metadata structure: unchanged
- Provenance required: yes
- Generation mode: full regeneration from latest finalized corpus pipeline

## IDS Label Distribution

| IDS Label | Count |
|---|---:|
| Bot | 6000 |
| DDoS | 6000 |
| FTP-Patator | 6000 |
| PortScan | 6000 |
| Web Attack - Sql Injection | 6000 |

## Curriculum Distribution

| Difficulty | Count |
|---|---:|
| easy | 6760 |
| medium | 7760 |
| hard | 7760 |
| expert | 7720 |

## Task Distribution

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

## Variant Distribution

| Variant | Count |
|---|---:|
| standard | 9000 |
| negative | 9000 |
| agreement | 9000 |
| multi_turn | 3000 |

## Coverage

| Coverage Area | Count |
|---|---:|
| T1046 | 6000 |
| T1105 | 6000 |
| T1110 | 6000 |
| T1190 | 6000 |
| T1498 | 6000 |
| CAPEC-112 | 4648 |
| CAPEC-300 | 4648 |
| CWE-200 | 4648 |
| CWE-330 | 4648 |
| CWE-521 | 3096 |

## Diversity Metrics

- Vocabulary diversity: 0.6628
- Average response length: 176.48 words
- Average provenance references: 42.4
- Average reasoning depth: 2.28
- Average SHAP features referenced: 5
- Repeated sentence %: 98.93
- Repeated paragraph %: 1.98
- Repeated mitigation %: 100.0
- Repeated reasoning %: 23.53

## Notes

The high repeated sentence and mitigation percentages are expected for a deterministic, provenance-grounded corpus generated from five fixed retrieval contexts and repeated source mitigations. The dataset preserves factual consistency, provenance, and validation safeguards.
