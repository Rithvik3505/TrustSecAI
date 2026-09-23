# TrustSecAI Knowledge Graph Report

## Summary

The TrustSecAI graph now contains ATT&CK, CAPEC, CWE, NVD/CVE, product/reference, and IDS label mapping layers. ATT&CK remains the behavioral spine. CAPEC and NVD are connected through CWE bridge nodes, and inferred relationships are explicitly marked.

## Total Graph Size

- Total nodes: 10,034
- Total relationships: 39,748

## Validation Results

| label | resolved | attack_id | technique | tactics | mitigations | capec_patterns | cwes | cves | products |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PortScan | True | T1046 | Network Service Discovery | ['Discovery'] | 3 | 1 | 1 | 37 | 30 |
| Web Attack - Sql Injection | True | T1190 | Exploit Public-Facing Application | ['Initial Access'] | 8 | 0 | 0 | 0 | 0 |
| FTP-Patator | True | T1110 | Brute Force | ['Credential Access'] | 4 | 1 | 2 | 3 | 2 |
| DDoS | True | T1498 | Network Denial of Service | ['Impact'] | 1 | 0 | 0 | 0 | 0 |
| Bot | True | T1105 | Ingress Tool Transfer | ['Command and Control'] | 2 | 0 | 0 | 0 | 0 |

## Data Quality Issues

- Resolved IDS labels without direct CAPEC expansion from local CAPEC taxonomy mappings: Web Attack - Sql Injection, DDoS, Bot
- CAPEC to CVE links are inferred through shared CWE and may over-retrieve without asset context.
- NVD local feeds are partial/recent snapshots, not a full historical NVD mirror.

## Remaining Work Before GraphRAG

- Implement ranked graph retrieval functions.
- Add context packaging for LLM prompts.
- Add query tests for key IDS labels.
- Add retrieval provenance filtering.
- Tune inferred CVE retrieval to avoid over-broad CWE matches.

## Not Implemented In This Phase

- GraphRAG
- Vector embeddings
- LLM integration
- LoRA
- Agreement analysis
- Attack-chain agent
