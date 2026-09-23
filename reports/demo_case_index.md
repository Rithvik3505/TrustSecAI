# TrustSecAI Multi-Case Demo Index

This demo set was generated from frozen compact LoRA evaluation outputs using the offline demo pipeline. No model training or LoRA inference was run.

## Selected Cases

| IDS label | example_id | task_type | model confidence | attack_chain_mode | JSON path | Markdown path | Demo value |
|---|---|---:|---:|---|---|---|---|
| Web Attack - Sql Injection | `trustsecai-gold-v1-00575` | `mitigation_detection` | 0.983210 | `graph` | `artifacts/demo/demo_trustsecai-gold-v1-00575.json` | `artifacts/demo/demo_trustsecai-gold-v1-00575.md` | Shows public-facing web exploit mapping, graph-backed attack-chain traversal, mitigation recommendations, SHAP support, and explicit no-CVE/no-attribution limitations. |
| PortScan | `trustsecai-gold-v1-00178` | `soc_incident_assessment` | 0.998606 | `graph` | `artifacts/demo/demo_trustsecai-gold-v1-00178.json` | `artifacts/demo/demo_trustsecai-gold-v1-00178.md` | Demonstrates discovery-stage triage with ATT&CK T1046, graph-backed pivots, and downstream investigation framing. |
| FTP-Patator | `trustsecai-gold-v1-00810` | `executive_summary` | 0.999981 | `graph` | `artifacts/demo/demo_trustsecai-gold-v1-00810.json` | `artifacts/demo/demo_trustsecai-gold-v1-00810.md` | Provides a business-readable credential-access/brute-force example with graph-backed mitigation and vulnerability context. |
| Bot | `trustsecai-gold-v1-00381` | `soc_incident_assessment` | 0.999968 | `graph` | `artifacts/demo/demo_trustsecai-gold-v1-00381.json` | `artifacts/demo/demo_trustsecai-gold-v1-00381.md` | Shows command-and-control/tool-transfer style graph context while preserving no-attribution language. |
| DDoS | `trustsecai-gold-v1-00128` | `mitigation_detection` | 0.999999 | `graph` | `artifacts/demo/demo_trustsecai-gold-v1-00128.json` | `artifacts/demo/demo_trustsecai-gold-v1-00128.md` | Covers impact-oriented denial-of-service handling with graph-backed defensive pivots and service-disruption caveats. |

## Summary

Five examples were selected, one for each requested IDS label:

- `trustsecai-gold-v1-00575` for Web Attack - Sql Injection
- `trustsecai-gold-v1-00178` for PortScan
- `trustsecai-gold-v1-00810` for FTP-Patator
- `trustsecai-gold-v1-00381` for Bot
- `trustsecai-gold-v1-00128` for DDoS

Generated demo files:

- `artifacts/demo/demo_trustsecai-gold-v1-00575.json`
- `artifacts/demo/demo_trustsecai-gold-v1-00575.md`
- `artifacts/demo/demo_trustsecai-gold-v1-00178.json`
- `artifacts/demo/demo_trustsecai-gold-v1-00178.md`
- `artifacts/demo/demo_trustsecai-gold-v1-00810.json`
- `artifacts/demo/demo_trustsecai-gold-v1-00810.md`
- `artifacts/demo/demo_trustsecai-gold-v1-00381.json`
- `artifacts/demo/demo_trustsecai-gold-v1-00381.md`
- `artifacts/demo/demo_trustsecai-gold-v1-00128.json`
- `artifacts/demo/demo_trustsecai-gold-v1-00128.md`

## Failures Or Missing Labels

No generation failures were encountered. All five requested IDS labels were present in `artifacts/evaluation/lora_v1/lora_generations_compact.jsonl` and all five offline demo reports were generated successfully. With Neo4j running, all five demo cases now show graph-backed attack-chain traversal.
