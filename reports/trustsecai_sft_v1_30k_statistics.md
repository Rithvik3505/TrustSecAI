# TrustSecAI SFT v1 30k Statistics

## Summary

- Examples: 30000
- Accepted by validation: 30000
- Rejected by validation: 0
- Validation warnings: 0
- JSON schema: unchanged
- Metadata structure: unchanged
- Provenance required: yes
- Generation mode: full v1 regeneration from latest refined corpus pipeline

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

## Output Diversity Summary

- Target-output vocabulary diversity: 0.6609
- Target-output unique sentence ratio: 0.0065
- Target-output repeated exact sentence %: 99.12
- Full-record repeated exact sentence %: 10.41
- Target-output diversity flags: 0

## Notes

The target-output repeated exact sentence metric remains high because the corpus is intentionally deterministic and grounded in five fixed retrieval contexts, repeated ATT&CK mappings, repeated mitigations, and repeated uncertainty safeguards. The v1 analyzer separates full-record diagnostics from target-output diversity so metadata, prompts, provenance, and graph context do not inflate the primary LoRA-readiness metric.
