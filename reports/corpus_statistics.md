# TrustSecAI Corpus Statistics

## Summary

- Number of examples: 240
- Negative examples: 70
- Multi-turn examples: 25
- Agreement-analysis examples: 70
- Average prompt length: 30.73 words
- Average response length: 149.35 words
- Accepted by validation: 240
- Rejected by validation: 0

## Difficulty Distribution

| Difficulty | Count |
|---|---:|
| easy | 55 |
| expert | 58 |
| hard | 63 |
| medium | 64 |

## Task Distribution

| Task | Count |
|---|---:|
| attack_mapping | 30 |
| executive_summary | 30 |
| incident_report_generation | 25 |
| mitigation_recommendation | 25 |
| multi_turn_security_analysis | 25 |
| security_analyst_reasoning | 30 |
| threat_assessment | 25 |
| uncertainty_analysis | 25 |
| vulnerability_summary | 25 |

## Variant Distribution

| Variant | Count |
|---|---:|
| agreement | 70 |
| multi_turn | 25 |
| negative | 70 |
| standard | 75 |

## Dataset Balance By IDS Label

| IDS Label | Count |
|---|---:|
| Bot | 48 |
| DDoS | 48 |
| FTP-Patator | 48 |
| PortScan | 48 |
| Web Attack - Sql Injection | 48 |

## Validation Notes

- The validation framework rejects malformed JSON, duplicate examples, missing provenance, invented security IDs, and unsupported attribution phrasing.
- The pilot corpus is deterministic and intended for manual review before scaling.
