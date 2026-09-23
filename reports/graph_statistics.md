# Knowledge Graph Statistics

## Summary

| Metric | Value |
|---|---:|
| Total nodes | 10,034 |
| Total relationships | 39,748 |
| Graph density | 0.00039483 |
| Average node degree | 7.9227 |
| Connected components estimate | 570 |
| Isolated nodes | 301 |

## Node Counts

| label | count |
| --- | --- |
| Technique | 365 |
| SubTechnique | 493 |
| Tactic | 15 |
| Mitigation | 268 |
| Group | 189 |
| Malware | 729 |
| Tool | 95 |
| Campaign | 56 |
| DetectionStrategy | 699 |
| CAPECPattern | 615 |
| CWE | 353 |
| CVE | 1448 |
| Product | 383 |
| Reference | 4312 |
| IDSLabel | 14 |

## Relationship Counts

| relationship | count |
| --- | --- |
| HAS_TACTIC | 1090 |
| SUBTECHNIQUE_OF | 477 |
| MITIGATED_BY | 1448 |
| USES_TECHNIQUE | 16903 |
| USES_TOOL | 553 |
| USES_MALWARE | 764 |
| ATTRIBUTED_TO | 26 |
| DETECTED_BY | 697 |
| CHILD_OF | 533 |
| CAN_PRECEDE | 162 |
| CAN_FOLLOW | 10 |
| PEER_OF | 19 |
| CAN_ALSO_BE | 3 |
| RELATED_WEAKNESS | 779 |
| MAPS_TO_ATTACK | 270 |
| HAS_WEAKNESS | 1412 |
| AFFECTS | 2914 |
| REFERENCES | 4663 |
| DETECTED_AS | 14 |
| HAS_ATTACK_PATTERN | 270 |
| ASSOCIATED_CVE | 6741 |

## Top 20 Highest-Degree Techniques

| attack_id | name | degree |
| --- | --- | --- |
| T1105 | Ingress Tool Transfer | 520 |
| T1082 | System Information Discovery | 432 |
| T1071.001 | Web Protocols | 424 |
| T1059.003 | Windows Command Shell | 390 |
| T1083 | File and Directory Discovery | 375 |
| T1140 | Deobfuscate/Decode Files or Information | 352 |
| T1057 | Process Discovery | 322 |
| T1070.004 | File Deletion | 311 |
| T1016 | System Network Configuration Discovery | 291 |
| T1547.001 | Registry Run Keys / Startup Folder | 266 |
| T1027.013 | Encrypted/Encoded File | 251 |
| T1033 | System Owner/User Discovery | 245 |
| T1059.001 | PowerShell | 241 |
| T1005 | Data from Local System | 240 |
| T1106 | Native API | 232 |
| T1036.005 | Match Legitimate Resource Name or Location | 226 |
| T1041 | Exfiltration Over C2 Channel | 205 |
| T1204.002 | Malicious File | 202 |
| T1053.005 | Scheduled Task | 199 |
| T1573.001 | Symmetric Cryptography | 188 |

## Top 20 Highest-Degree CAPEC Patterns

| capec_id | name | degree |
| --- | --- | --- |
| CAPEC-85 | AJAX Footprinting | 116 |
| CAPEC-79 | Using Slashes in Alternate Encoding | 99 |
| CAPEC-64 | Using Slashes and URL Encoding Combined to Bypass Validation Logic | 98 |
| CAPEC-88 | OS Command Injection | 76 |
| CAPEC-22 | Exploiting Trust in Client | 75 |
| CAPEC-59 | Session Credential Falsification through Prediction | 75 |
| CAPEC-108 | Command Line Execution through SQL Injection | 75 |
| CAPEC-592 | Stored XSS | 74 |
| CAPEC-588 | DOM-Based XSS | 73 |
| CAPEC-10 | Buffer Overflow via Environment Variables | 73 |
| CAPEC-63 | Cross-Site Scripting (XSS) | 72 |
| CAPEC-267 | Leverage Alternate Encoding | 71 |
| CAPEC-591 | Reflected XSS | 71 |
| CAPEC-45 | Buffer Overflow via Symbolic Links | 68 |
| CAPEC-473 | Signature Spoof | 68 |
| CAPEC-104 | Cross Zone Scripting | 67 |
| CAPEC-46 | Overflow Variables and Tags | 67 |
| CAPEC-9 | Buffer Overflow in Local Command-Line Utilities | 66 |
| CAPEC-540 | Overread Buffers | 65 |
| CAPEC-665 | Exploitation of Thunderbolt Protection Flaws | 64 |

## Top Referenced CWEs

| cwe_id | references |
| --- | --- |
| CWE-416 | 93 |
| CWE-200 | 93 |
| NVD-CWE-noinfo | 89 |
| CWE-20 | 79 |
| CWE-79 | 66 |
| CWE-125 | 64 |
| CWE-284 | 51 |
| CWE-787 | 47 |
| CWE-22 | 47 |
| CWE-862 | 45 |
| CWE-863 | 41 |
| CWE-770 | 36 |
| CWE-122 | 31 |
| CWE-74 | 30 |
| CWE-476 | 29 |
| CWE-639 | 28 |
| CWE-400 | 27 |
| CWE-693 | 27 |
| CWE-78 | 26 |
| CWE-89 | 26 |

## Top Referenced CVEs

| cve_id | severity | base_score | references |
| --- | --- | --- | --- |
| CVE-2026-45329 | HIGH | 7.1 | 97 |
| CVE-2026-12203 | MEDIUM | 5.3 | 84 |
| CVE-2026-42970 | MEDIUM | 5.5 | 82 |
| CVE-2026-11459 | LOW | 3.3 | 81 |
| CVE-2026-45594 | MEDIUM | 5.5 | 80 |
| CVE-2026-42971 | MEDIUM | 5.5 | 80 |
| CVE-2026-42907 | MEDIUM | 6.5 | 77 |
| CVE-2026-42906 | MEDIUM | 5.5 | 74 |
| CVE-2025-13462 | LOW | 3.3 | 68 |
| CVE-2026-49397 | MEDIUM | 5.3 | 66 |
| CVE-2026-49219 | MEDIUM | 5.5 | 65 |
| CVE-2026-9210 | UNSCORED | None | 64 |
| CVE-2026-41539 | MEDIUM | 6.1 | 64 |
| CVE-2026-49742 | UNSCORED | None | 63 |
| CVE-2026-50009 | MEDIUM | 4.8 | 63 |
| CVE-2026-0411 | UNSCORED | None | 63 |
| CVE-2026-45536 | MEDIUM | 4.0 | 62 |
| CVE-2026-47351 | UNSCORED | None | 62 |
| CVE-2026-45085 | MEDIUM | 5.3 | 60 |
| CVE-2026-46443 | MEDIUM | 6.5 | 60 |

## Isolated Node Samples

| label | id |
| --- | --- |
| Mitigation | T1174 |
| Mitigation | T1151 |
| Mitigation | T1148 |
| Mitigation | T1081 |
| Mitigation | T1212 |
| Mitigation | T1012 |
| Mitigation | T1162 |
| Mitigation | T1166 |
| Mitigation | T1223 |
| Mitigation | T1488 |
| Mitigation | T1084 |
| Mitigation | T1044 |
| Mitigation | T1103 |
| Mitigation | T1159 |
| Mitigation | T1117 |
| Mitigation | T1147 |
| Mitigation | T1213 |
| Mitigation | T1210 |
| Mitigation | T1482 |
| Mitigation | T1072 |
| Mitigation | T1009 |
| Mitigation | T1123 |
| Mitigation | T1033 |
| Mitigation | T1120 |
| Mitigation | T1115 |
| Mitigation | T1144 |
| Mitigation | T1029 |
| Mitigation | T1217 |
| Mitigation | T1013 |
| Mitigation | T1155 |
| Mitigation | T1202 |
| Mitigation | T1135 |
| Mitigation | T1130 |
| Mitigation | T1169 |
| Mitigation | T1079 |
| Mitigation | T1493 |
| Mitigation | T1020 |
| Mitigation | T1010 |
| Mitigation | T1019 |
| Mitigation | T1002 |
| Mitigation | T1022 |
| Mitigation | T1083 |
| Mitigation | T1062 |
| Mitigation | T1150 |
| Mitigation | T1077 |
| Mitigation | T1004 |
| Mitigation | T1494 |
| Mitigation | T1183 |
| Mitigation | T1186 |
| Mitigation | T1107 |
