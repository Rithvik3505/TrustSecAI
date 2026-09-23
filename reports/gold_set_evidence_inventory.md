# TrustSecAI Gold-Set Evidence Inventory

This inventory distinguishes available evidence from unavailable facts that must not be synthesized.

## Currently Available Evidence

- CICIDS inspection sample rows: 10000
- Retrieval contexts available: 5
- Local SHAP explanation label groups: 3
- ATT&CK label mappings available: 14

## Retrieval Context Coverage

| IDS label | Technique | Tactics | Mitigations | CAPEC | CWE | CVE | Products | Inferred edges | Source |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| Bot | T1105 | 1 | 2 | 0 | 0 | 0 | 0 | 0 | artifacts/retrieval/Bot.json |
| DDoS | T1498 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | artifacts/retrieval/DDoS.json |
| FTP-Patator | T1110 | 1 | 4 | 1 | 2 | 3 | 2 | 4 | artifacts/retrieval/FTP_Patator.json |
| PortScan | T1046 | 1 | 3 | 1 | 1 | 10 | 10 | 21 | artifacts/retrieval/PortScan.json |
| Web Attack - Sql Injection | T1190 | 1 | 8 | 0 | 0 | 0 | 0 | 0 | artifacts/retrieval/Web_Attack___Sql_Injection.json |

## Local SHAP Coverage

| Label | Samples | Confidence values | Distinct top-feature patterns | Source files |
|---|---:|---|---:|---|
| BENIGN | 10 | [1.0] | 10 | Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv, Wednesday-workingHours.pcap_ISCX.csv, Monday-WorkingHours.pcap_ISCX.csv, Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv, Tuesday-WorkingHours.pcap_ISCX.csv, Friday-WorkingHours-Morning.pcap_ISCX.csv, Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv |
| DDoS | 3 | [1.0] | 2 | Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv |
| DoS Hulk | 7 | [1.0] | 4 | Wednesday-workingHours.pcap_ISCX.csv |

## Evidence Exportable From Existing Artifacts

- retrieval_context_json: artifacts/retrieval/Bot.json, artifacts/retrieval/DDoS.json, artifacts/retrieval/FTP_Patator.json, artifacts/retrieval/PortScan.json, artifacts/retrieval/Web_Attack___Sql_Injection.json
- local_shap_json: artifacts/shap/sample_explanations.json
- global_shap_importance: artifacts/shap/global_feature_importance.csv
- cleaned_dataset_sample: artifacts/processed/cleaned_cicids_sample.csv
- cleaned_dataset_full: artifacts/processed/cleaned_cicids.parquet
- attack_label_mapping: artifacts/attack_label_mapping.json

## Unavailable Evidence Not Synthesized As Fact

- Real local SHAP explanations are unavailable for Bot, FTP-Patator, PortScan, and Web Attack - Sql Injection in artifacts/shap/sample_explanations.json.
- Medium- and low-confidence classifier examples are not present in the exported local SHAP artifact; all exported local explanations have confidence 1.0.
- No asset ownership, exposure, or incident timeline evidence is present in the current artifacts.
- Threat actor attribution is unavailable; group/tool/malware nodes from ATT&CK are contextual usage evidence only.
- Additional retrieval neighborhoods beyond the saved deterministic retrieval JSON files were not synthesized.

## Generation Scope

- Labels used for SFT generation: Bot, DDoS, FTP-Patator, PortScan, Web Attack - Sql Injection
- Size rationale: Only five deterministic retrieval contexts and three attack-label local SHAP groups are exported. The gold-candidate set therefore prioritizes base-context diversity and reviewability over target size.
