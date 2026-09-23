# TrustSecAI Dataset Diversity Report

## Summary

- Examples: 30000
- Vocabulary diversity: 0.6628
- Unique words: 837
- Average response length: 176.48 words
- Repeated sentence %: 98.93
- Repeated paragraph %: 1.98
- Repeated mitigation %: 100.0
- Repeated reasoning %: 23.53
- Average provenance references: 42.4
- Average reasoning depth: 2.28
- Average SHAP features referenced: 5

## Flags

- Repeated sentence percentage is high.

## Task Distribution

| Item | Count |
|---|---:|
| `attack_mapping` | 3375 |
| `executive_summary` | 3375 |
| `incident_report_generation` | 3375 |
| `mitigation_recommendation` | 3375 |
| `multi_turn_security_analysis` | 3000 |
| `security_analyst_reasoning` | 3375 |
| `threat_assessment` | 3375 |
| `uncertainty_analysis` | 3375 |
| `vulnerability_summary` | 3375 |

## Technique Distribution

| Item | Count |
|---|---:|
| `T1046` | 6000 |
| `T1105` | 6000 |
| `T1110` | 6000 |
| `T1190` | 6000 |
| `T1498` | 6000 |

## Mitigation Distribution

| Item | Count |
|---|---:|
| `M1031` | 5250 |
| `M1037` | 5250 |
| `M1030` | 5250 |
| `M1018` | 2625 |
| `M1027` | 2625 |
| `M1032` | 2625 |
| `M1042` | 2625 |
| `M1016` | 2625 |
| `M1026` | 2625 |

## ATT&CK Coverage

| Item | Count |
|---|---:|
| `T1046` | 6000 |
| `T1105` | 6000 |
| `T1110` | 6000 |
| `T1190` | 6000 |
| `T1498` | 6000 |
| `TA0001` | 6000 |
| `TA0006` | 6000 |
| `TA0007` | 6000 |
| `TA0011` | 6000 |
| `TA0040` | 6000 |

## CAPEC Coverage

| Item | Count |
|---|---:|
| `CAPEC-112` | 4648 |
| `CAPEC-300` | 4648 |

## CWE Coverage

| Item | Count |
|---|---:|
| `CWE-200` | 4648 |
| `CWE-330` | 4648 |
| `CWE-521` | 3096 |

## CVE Coverage

| Item | Count |
|---|---:|
| `CVE-2026-41838` | 3096 |
| `CVE-2026-42906` | 1544 |
| `CVE-2026-42907` | 3096 |
| `CVE-2026-42970` | 1544 |
| `CVE-2026-44486` | 3096 |
| `CVE-2026-44784` | 3096 |
| `CVE-2026-44786` | 3096 |
| `CVE-2026-45329` | 3096 |
| `CVE-2026-45673` | 3096 |
| `CVE-2026-46443` | 1544 |
| `CVE-2026-47124` | 1544 |
| `CVE-2026-47284` | 1544 |
| `CVE-2026-50009` | 3096 |

## Top Repeated Phrases

| Item | Count |
|---|---:|
| `total length of bwd` | 19800 |
| `length of bwd packets` | 19800 |
| `the supplied graph context` | 14824 |
| `should not be treated` | 10507 |
| `not be treated as` | 10507 |
| `and subflow bwd bytes` | 10500 |
| `contribution shap init_win_bytes_backward moderate` | 9900 |
| `shap init_win_bytes_backward moderate contribution` | 9900 |
| `init_win_bytes_backward moderate contribution shap` | 9900 |
| `the classifier confidence is` | 9750 |
| `maps the label to` | 9750 |
| `of bwd packets moderate` | 9300 |
| `bwd packets moderate contribution` | 9300 |
| `packets moderate contribution shap` | 9300 |
| `this example prepares future` | 9000 |
| `example prepares future agreement` | 9000 |
| `prepares future agreement analysis` | 9000 |
| `future agreement analysis no` | 9000 |
| `agreement analysis no agreement` | 9000 |
| `analysis no agreement module` | 9000 |

## Most Common Openings

| Item | Count |
|---|---:|
| `FTP-Patator User Account Management Password Policies Multi-factor Authentication Brute Force Authentication Failures with Multi-Platform Lo` | 675 |
| `PortScan Network Segmentation Network Intrusion Prevention Disable or Remove Feature or Program Behavioral Detection Strategy for Network Se` | 675 |
| `Web Attack - Sql Injection Vulnerability Scanning Privileged Account Management Network Segmentation Exploit Public-Facing Application – mul` | 675 |
| `IDS prediction: Web Attack - Sql Injection Mapped ATT&CK technique: T1190 (Exploit Public-Facing Application) Available provenance entries: ` | 675 |
| `Context: no CVEs are present in the supplied context.` | 506 |
| `Initial observation: TrustSecAI flagged activity as Bot.` | 338 |
| `Evidence review: TrustSecAI flagged activity as DDoS.` | 338 |
| `Confidence view: TrustSecAI flagged activity as FTP-Patator.` | 338 |
| `Mapping: TrustSecAI flagged activity as PortScan.` | 338 |
| `Signal: TrustSecAI flagged activity as Web Attack - Sql Injection.` | 338 |
| `Initial observation: validate whether the observed traffic is consistent with T1105 (Ingress Tool Transfer).` | 338 |
| `Evidence review: validate whether the observed traffic is consistent with T1498 (Network Denial of Service).` | 338 |
| `Confidence view: validate whether the observed traffic is consistent with T1110 (Brute Force).` | 338 |
| `Mapping: validate whether the observed traffic is consistent with T1046 (Network Service Discovery).` | 338 |
| `Signal: validate whether the observed traffic is consistent with T1190 (Exploit Public-Facing Application).` | 338 |

## Most Common Closings

| Item | Count |
|---|---:|
| `This example prepares future agreement analysis; no agreement module is executed.` | 6750 |
| `Unsupported conclusions should be refused or framed as uncertainty.` | 2250 |
| `Retrieved actor or software links are not attribution evidence.` | 1479 |
| `Actor, tool, and malware context shows observed ATT&CK usage, not attribution.` | 1474 |
| `Usage relationships provide context but do not identify the attacker.` | 1468 |
| `Related groups, tools, or malware should not be treated as the identified operator.` | 1418 |
| `Threat-actor context is behavioral background only.` | 1361 |
| `Candidate graph links should be validated against local evidence.` | 1233 |
| `Some graph context is inferred and should be described as candidate evidence.` | 1210 |
| `Treat inferred relationships as leads rather than confirmed facts.` | 1184 |
| `Inferred graph edges require cautious wording.` | 1173 |
| `low` | 1125 |
| `low low` | 1013 |
| `high` | 565 |
| `high This example prepares future agreement analysis; no agreement module is executed.` | 563 |
