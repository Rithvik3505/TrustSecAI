# TrustSecAI SFT Dataset Preparation Report

Prepared from strict reviewed gold v1 split files only.

## train

- Rows: 338
- IDS labels: {'Bot': 90, 'PortScan': 56, 'FTP-Patator': 65, 'Web Attack - Sql Injection': 69, 'DDoS': 58}
- Tasks: {'soc_incident_assessment': 51, 'attack_mapping': 44, 'threat_hunting_followup': 39, 'executive_summary': 35, 'mitigation_detection': 38, 'vulnerability_context': 47, 'multi_turn_analyst_interaction': 49, 'uncertainty_evidence_gap': 35}
- Confidence bands: {'high': 298, 'medium': 28, 'low': 12}
- Average text chars: 9957.49

## validation

- Rows: 78
- IDS labels: {'Bot': 8, 'Web Attack - Sql Injection': 28, 'FTP-Patator': 22, 'PortScan': 9, 'DDoS': 11}
- Tasks: {'soc_incident_assessment': 16, 'vulnerability_context': 6, 'uncertainty_evidence_gap': 11, 'executive_summary': 11, 'threat_hunting_followup': 10, 'multi_turn_analyst_interaction': 10, 'attack_mapping': 7, 'mitigation_detection': 7}
- Confidence bands: {'medium': 3, 'high': 75}
- Average text chars: 10068.68

## test

- Rows: 76
- IDS labels: {'Web Attack - Sql Injection': 22, 'Bot': 24, 'FTP-Patator': 8, 'PortScan': 14, 'DDoS': 8}
- Tasks: {'mitigation_detection': 10, 'soc_incident_assessment': 14, 'uncertainty_evidence_gap': 8, 'vulnerability_context': 13, 'attack_mapping': 7, 'multi_turn_analyst_interaction': 8, 'threat_hunting_followup': 9, 'executive_summary': 7}
- Confidence bands: {'high': 74, 'medium': 2}
- Average text chars: 9966.59


Compact context mode: True

Compact mode writes compact train/validation/test files only; existing tiny files are unchanged.

Reviewer notes and checklist fields are not included in training text.
