# TrustSecAI Gold-Candidate v0 Report

This set is intentionally smaller than the previous synthetic corpora. It uses the currently exported TrustSecAI evidence contexts and avoids treating paraphrases over identical evidence as new diversity.

## Summary

- Candidate examples: 760
- Unique base contexts: 38
- IDS labels: {'Bot': 120, 'DDoS': 180, 'FTP-Patator': 160, 'PortScan': 160, 'Web Attack - Sql Injection': 140}
- Task distribution: {'multi_turn_analyst_interaction': 38, 'attack_mapping': 114, 'executive_summary': 76, 'soc_incident_assessment': 190, 'mitigation_detection': 114, 'threat_hunting_followup': 76, 'vulnerability_context': 76, 'uncertainty_evidence_gap': 76}
- Difficulty distribution: {'easy': 190, 'medium': 190, 'hard': 190, 'expert': 190}
- Confidence bands: {'unavailable': 580, 'high': 180}
- Provenance types: {'direct': 440, 'mixed_direct_and_inferred': 320}

## Size Rationale

The requested target of approximately 3,000 examples was not forced because the available real evidence currently consists of five saved retrieval contexts and limited local SHAP coverage. The generated set favors reviewable base-context diversity over repeated wording variants.
