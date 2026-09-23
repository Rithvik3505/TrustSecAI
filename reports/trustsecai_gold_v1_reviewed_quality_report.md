# TrustSecAI Gold v1 Reviewed Quality Report

## Strict Reviewed Corpus

```json
{
  "corpus": "strict_reviewed",
  "total_examples": 492,
  "approved_count": 492,
  "revised_count": 0,
  "rejected_count": 0,
  "unreviewed_count": 0,
  "duplicate_example_ids": [],
  "duplicate_target_outputs": 0,
  "flagged": [],
  "split_leakage": {
    "train_validation": [],
    "train_test": [],
    "validation_test": []
  },
  "split_counts": {
    "train": 338,
    "validation": 78,
    "test": 76
  },
  "ids_label_distribution": {
    "DDoS": 77,
    "PortScan": 79,
    "Bot": 122,
    "Web Attack - Sql Injection": 119,
    "FTP-Patator": 95
  },
  "task_distribution": {
    "vulnerability_context": 66,
    "threat_hunting_followup": 58,
    "soc_incident_assessment": 81,
    "attack_mapping": 58,
    "executive_summary": 53,
    "multi_turn_analyst_interaction": 67,
    "mitigation_detection": 55,
    "uncertainty_evidence_gap": 54
  },
  "confidence_band_distribution": {
    "high": 447,
    "medium": 33,
    "low": 12
  },
  "cve_distribution": {
    "cve_absent": 318,
    "cve_present": 174
  },
  "shap_coverage": {
    "True": 492
  },
  "provenance_type_distribution": {
    "direct": 318,
    "mixed_direct_and_inferred": 174
  },
  "passed": true
}
```

## Candidate-Plus-Approved Corpus

```json
{
  "corpus": "candidate_plus_reviewed",
  "total_examples": 847,
  "approved_count": 492,
  "revised_count": 0,
  "rejected_count": 0,
  "unreviewed_count": 355,
  "duplicate_example_ids": [],
  "duplicate_target_outputs": 0,
  "flagged": [],
  "split_leakage": {
    "train_validation": [],
    "train_test": [],
    "validation_test": []
  },
  "split_counts": {},
  "ids_label_distribution": {
    "DDoS": 175,
    "PortScan": 175,
    "Bot": 175,
    "Web Attack - Sql Injection": 147,
    "FTP-Patator": 175
  },
  "task_distribution": {
    "mitigation_detection": 87,
    "threat_hunting_followup": 99,
    "vulnerability_context": 105,
    "uncertainty_evidence_gap": 88,
    "multi_turn_analyst_interaction": 103,
    "attack_mapping": 92,
    "executive_summary": 98,
    "soc_incident_assessment": 175
  },
  "confidence_band_distribution": {
    "high": 777,
    "medium": 56,
    "low": 14
  },
  "cve_distribution": {
    "cve_absent": 497,
    "cve_present": 350
  },
  "shap_coverage": {
    "True": 847
  },
  "provenance_type_distribution": {
    "direct": 497,
    "mixed_direct_and_inferred": 350
  },
  "passed": true
}
```
