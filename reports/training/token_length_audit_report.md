# TrustSecAI Token Length Audit

- Tokenizer/model: `meta-llama/Llama-3.1-8B-Instruct`
- Configured max_seq_length: `2048`

## train

- Count: 338
- Min tokens: 3511
- Max tokens: 6110
- Mean tokens: 4822.21
- Median tokens: 4894
- p90: 5485
- p95: 5546
- p99: 6107
- Above max_seq_length: 338 (100.0%)
- Long task distribution: {'soc_incident_assessment': 51, 'attack_mapping': 44, 'threat_hunting_followup': 39, 'executive_summary': 35, 'mitigation_detection': 38, 'vulnerability_context': 47, 'multi_turn_analyst_interaction': 49, 'uncertainty_evidence_gap': 35}
- Long label distribution: {'Bot': 90, 'PortScan': 56, 'FTP-Patator': 65, 'Web Attack - Sql Injection': 69, 'DDoS': 58}

### Longest 20

- trustsecai-gold-v1-00228 | 6110 tokens | vulnerability_context | PortScan | train
- trustsecai-gold-v1-00198 | 6109 tokens | vulnerability_context | PortScan | train
- trustsecai-gold-v1-00321 | 6108 tokens | vulnerability_context | PortScan | train
- trustsecai-gold-v1-00338 | 6107 tokens | vulnerability_context | PortScan | train
- trustsecai-gold-v1-00308 | 6106 tokens | vulnerability_context | PortScan | train
- trustsecai-gold-v1-00270 | 6103 tokens | vulnerability_context | PortScan | train
- trustsecai-gold-v1-00245 | 6101 tokens | vulnerability_context | PortScan | train
- trustsecai-gold-v1-00216 | 6101 tokens | vulnerability_context | PortScan | train
- trustsecai-gold-v1-00230 | 5555 tokens | multi_turn_analyst_interaction | PortScan | train
- trustsecai-gold-v1-00201 | 5554 tokens | multi_turn_analyst_interaction | PortScan | train
- trustsecai-gold-v1-00304 | 5551 tokens | multi_turn_analyst_interaction | PortScan | train
- trustsecai-gold-v1-00346 | 5551 tokens | multi_turn_analyst_interaction | PortScan | train
- trustsecai-gold-v1-00261 | 5551 tokens | multi_turn_analyst_interaction | PortScan | train
- trustsecai-gold-v1-00227 | 5551 tokens | soc_incident_assessment | PortScan | train
- trustsecai-gold-v1-00200 | 5550 tokens | soc_incident_assessment | PortScan | train
- trustsecai-gold-v1-00325 | 5549 tokens | soc_incident_assessment | PortScan | train
- trustsecai-gold-v1-00298 | 5548 tokens | multi_turn_analyst_interaction | PortScan | train
- trustsecai-gold-v1-00239 | 5546 tokens | multi_turn_analyst_interaction | PortScan | train
- trustsecai-gold-v1-00319 | 5545 tokens | soc_incident_assessment | PortScan | train
- trustsecai-gold-v1-00348 | 5541 tokens | soc_incident_assessment | PortScan | train

## validation

- Count: 78
- Min tokens: 3528
- Max tokens: 5548
- Mean tokens: 4858.85
- Median tokens: 5011
- p90: 5421
- p95: 5471
- p99: 5540
- Above max_seq_length: 78 (100.0%)
- Long task distribution: {'soc_incident_assessment': 16, 'vulnerability_context': 6, 'uncertainty_evidence_gap': 11, 'executive_summary': 11, 'threat_hunting_followup': 10, 'multi_turn_analyst_interaction': 10, 'attack_mapping': 7, 'mitigation_detection': 7}
- Long label distribution: {'Bot': 8, 'Web Attack - Sql Injection': 28, 'FTP-Patator': 22, 'PortScan': 9, 'DDoS': 11}

### Longest 20

- trustsecai-gold-v1-00291 | 5548 tokens | multi_turn_analyst_interaction | PortScan | validation
- trustsecai-gold-v1-00193 | 5540 tokens | soc_incident_assessment | PortScan | validation
- trustsecai-gold-v1-00278 | 5539 tokens | soc_incident_assessment | PortScan | validation
- trustsecai-gold-v1-00196 | 5482 tokens | mitigation_detection | PortScan | validation
- trustsecai-gold-v1-00825 | 5471 tokens | vulnerability_context | FTP-Patator | validation
- trustsecai-gold-v1-00277 | 5434 tokens | threat_hunting_followup | PortScan | validation
- trustsecai-gold-v1-00192 | 5434 tokens | attack_mapping | PortScan | validation
- trustsecai-gold-v1-00292 | 5422 tokens | executive_summary | PortScan | validation
- trustsecai-gold-v1-00275 | 5421 tokens | executive_summary | PortScan | validation
- trustsecai-gold-v1-00235 | 5421 tokens | executive_summary | PortScan | validation
- trustsecai-gold-v1-00773 | 5194 tokens | multi_turn_analyst_interaction | FTP-Patator | validation
- trustsecai-gold-v1-00772 | 5188 tokens | soc_incident_assessment | FTP-Patator | validation
- trustsecai-gold-v1-00824 | 5187 tokens | multi_turn_analyst_interaction | FTP-Patator | validation
- trustsecai-gold-v1-00697 | 5182 tokens | multi_turn_analyst_interaction | FTP-Patator | validation
- trustsecai-gold-v1-00723 | 5181 tokens | multi_turn_analyst_interaction | FTP-Patator | validation
- trustsecai-gold-v1-00826 | 5181 tokens | soc_incident_assessment | FTP-Patator | validation
- trustsecai-gold-v1-00728 | 5179 tokens | soc_incident_assessment | FTP-Patator | validation
- trustsecai-gold-v1-00694 | 5176 tokens | soc_incident_assessment | FTP-Patator | validation
- trustsecai-gold-v1-00771 | 5132 tokens | uncertainty_evidence_gap | FTP-Patator | validation
- trustsecai-gold-v1-00777 | 5126 tokens | mitigation_detection | FTP-Patator | validation

## test

- Count: 76
- Min tokens: 3514
- Max tokens: 6105
- Mean tokens: 4901.66
- Median tokens: 4898
- p90: 5491
- p95: 5547
- p99: 6102
- Above max_seq_length: 76 (100.0%)
- Long task distribution: {'mitigation_detection': 10, 'soc_incident_assessment': 14, 'uncertainty_evidence_gap': 8, 'vulnerability_context': 13, 'attack_mapping': 7, 'multi_turn_analyst_interaction': 8, 'threat_hunting_followup': 9, 'executive_summary': 7}
- Long label distribution: {'Web Attack - Sql Injection': 22, 'Bot': 24, 'FTP-Patator': 8, 'PortScan': 14, 'DDoS': 8}

### Longest 20

- trustsecai-gold-v1-00311 | 6105 tokens | vulnerability_context | PortScan | test
- trustsecai-gold-v1-00181 | 6102 tokens | vulnerability_context | PortScan | test
- trustsecai-gold-v1-00223 | 6102 tokens | vulnerability_context | PortScan | test
- trustsecai-gold-v1-00313 | 5550 tokens | multi_turn_analyst_interaction | PortScan | test
- trustsecai-gold-v1-00176 | 5547 tokens | multi_turn_analyst_interaction | PortScan | test
- trustsecai-gold-v1-00224 | 5547 tokens | multi_turn_analyst_interaction | PortScan | test
- trustsecai-gold-v1-00178 | 5539 tokens | soc_incident_assessment | PortScan | test
- trustsecai-gold-v1-00257 | 5491 tokens | uncertainty_evidence_gap | PortScan | test
- trustsecai-gold-v1-00314 | 5482 tokens | mitigation_detection | PortScan | test
- trustsecai-gold-v1-00259 | 5480 tokens | mitigation_detection | PortScan | test
- trustsecai-gold-v1-00812 | 5474 tokens | vulnerability_context | FTP-Patator | test
- trustsecai-gold-v1-00312 | 5437 tokens | threat_hunting_followup | PortScan | test
- trustsecai-gold-v1-00177 | 5434 tokens | threat_hunting_followup | PortScan | test
- trustsecai-gold-v1-00180 | 5431 tokens | attack_mapping | PortScan | test
- trustsecai-gold-v1-00222 | 5421 tokens | executive_summary | PortScan | test
- trustsecai-gold-v1-00701 | 5178 tokens | soc_incident_assessment | FTP-Patator | test
- trustsecai-gold-v1-00811 | 5122 tokens | mitigation_detection | FTP-Patator | test
- trustsecai-gold-v1-00706 | 5116 tokens | uncertainty_evidence_gap | FTP-Patator | test
- trustsecai-gold-v1-00705 | 5110 tokens | mitigation_detection | FTP-Patator | test
- trustsecai-gold-v1-00807 | 5074 tokens | threat_hunting_followup | FTP-Patator | test
