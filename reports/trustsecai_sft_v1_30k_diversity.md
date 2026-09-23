# TrustSecAI Dataset Diversity Report

## Summary

- Examples: 30000
- Primary metric scope: target output text only
- Target-output vocabulary diversity: 0.6609
- Target-output unique sentence ratio: 0.0065
- Target-output repeated exact sentence %: 99.12
- Target-output repeated paragraph %: 1.26
- Target-output repeated opening %: 100.0
- Target-output repeated closing %: 100.0
- Full-record vocabulary diversity: 0.2172
- Full-record repeated exact sentence %: 10.41
- Repeated mitigation %: 100.0
- Repeated reasoning %: 27.95
- Average provenance references: 42.4
- Average reasoning depth: 2.32
- Average SHAP features referenced: 5

## Flags

- None.

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
| `total length of bwd` | 25650 |
| `length of bwd packets` | 25650 |
| `the supplied graph context` | 14824 |
| `should not be treated` | 10507 |
| `not be treated as` | 10507 |
| `of bwd packets moderate` | 9900 |
| `bwd packets moderate contribution` | 9900 |
| `packets moderate contribution shap` | 9900 |
| `the classifier confidence is` | 9750 |
| `maps the label to` | 9750 |
| `fwd packet length max` | 8550 |
| `where it matches the` | 8100 |
| `it matches the environment` | 8100 |
| `are present in the` | 8074 |
| `present in the supplied` | 8074 |
| `in the supplied graph` | 8074 |
| `no cves are present` | 7400 |
| `cves are present in` | 7400 |
| `network denial of service` | 7275 |
| `this control if it` | 7200 |

## Most Common Openings

| Item | Count |
|---|---:|
| `FTP-Patator User Account Management Password Policies Multi-factor Authentication Brute Force Authentication Failures with Multi-Platform Lo` | 675 |
| `PortScan Network Segmentation Network Intrusion Prevention Disable or Remove Feature or Program Behavioral Detection Strategy for Network Se` | 675 |
| `Web Attack - Sql Injection Vulnerability Scanning Privileged Account Management Network Segmentation Exploit Public-Facing Application – mul` | 675 |
| `IDS prediction: Web Attack - Sql Injection Mapped ATT&CK technique: T1190 (Exploit Public-Facing Application) Available provenance entries: ` | 675 |
| `Context: no CVEs are present in the supplied context.` | 506 |
| `Security Incident Assessment The finding is useful for reviewing controls, logging, and detection coverage.` | 422 |
| `Security Incident Assessment The security impact should be framed around business exposure and operational risk.` | 422 |
| `Security Incident Assessment The assessment should emphasize confidence, evidence quality, and limitations.` | 422 |
| `Security Incident Assessment The alert should be validated quickly against nearby telemetry.` | 422 |
| `Security Incident Assessment Inspection of the supplied evidence supports a structured follow-up.` | 422 |
| `Security Incident Assessment The technical pattern deserves deeper review against detection and control coverage.` | 422 |
| `Security Incident Assessment A reasonable hunting hypothesis is available, but alternate explanations remain possible.` | 422 |
| `Security Incident Assessment The alert should be handled with scoping and containment readiness in mind.` | 421 |
| `Initial observation: TrustSecAI flagged activity as Bot.` | 338 |
| `Evidence review: TrustSecAI flagged activity as DDoS.` | 338 |

## Most Common Closings

| Item | Count |
|---|---:|
| `Unsupported conclusions should be avoided; use only supplied IDS, SHAP, graph context, and provenance.` | 2250 |
| `Usage relationships provide context but do not identify the attacker.` | 2025 |
| `Actor, tool, and malware context shows observed ATT&CK usage, not attribution.` | 2018 |
| `Retrieved actor or software links are not attribution evidence.` | 2007 |
| `Related groups, tools, or malware should not be treated as the identified operator.` | 1940 |
| `Threat-actor context is behavioral background only.` | 1910 |
| `low` | 1687 |
| `Candidate graph links should be validated against local evidence.` | 1686 |
| `Treat inferred relationships as leads rather than confirmed facts.` | 1662 |
| `Some graph context is inferred and should be described as candidate evidence.` | 1629 |
| `Inferred graph edges require cautious wording.` | 1623 |
| `low low` | 1518 |
| `high` | 1128 |
| `high high` | 848 |
| `GraphRAG adds context for triage, but it does not prove compromise on its own.` | 597 |

## Target-Output Diversity By Variant

### Agreement Output Diversity

- Vocabulary diversity: 0.6698
- Unique sentence ratio: 0.0161
- Repeated exact sentence %: 92.69

### Negative Example Diversity

- Vocabulary diversity: 0.6769
- Unique sentence ratio: 0.0135
- Repeated exact sentence %: 97.82

### Multi-Turn Response Diversity

- Vocabulary diversity: 0.476
- Unique sentence ratio: 0.0177
- Repeated exact sentence %: 99.89

