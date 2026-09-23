# Gold-Candidate v1 Review Workbook Report

Created: 2026-07-10

- Workbook path: `C:/Users/LENOVO/WORK/Projects/TrustSecAI/artifacts/gold_candidates/v1/review_workbook.xlsx`
- CSV path: `C:/Users/LENOVO/WORK/Projects/TrustSecAI/artifacts/gold_candidates/v1/review_workbook.csv`
- Review rows: 492
- Examples by task: {'mitigation_detection': 55, 'threat_hunting_followup': 58, 'vulnerability_context': 66, 'uncertainty_evidence_gap': 54, 'multi_turn_analyst_interaction': 67, 'attack_mapping': 58, 'executive_summary': 53, 'soc_incident_assessment': 81}
- Examples by IDS label: {'DDoS': 77, 'PortScan': 79, 'Bot': 122, 'Web Attack - Sql Injection': 119, 'FTP-Patator': 95}
- Examples by confidence band: {'high': 447, 'medium': 33, 'low': 12}
- CVE present/absent: {'cve_absent': 318, 'cve_present': 174}

## Reviewer Workflow

1. Open `review_workbook.xlsx` and work mainly in the `Review_All` sheet.
2. Use dropdowns to set `reviewer_decision` to approve, revise, or reject.
3. If revising, set `needs_revision=yes` and write the corrected target in `revised_output`.
4. Use the check columns to mark grounding, uncertainty, attribution, graph-proof, SHAP, and tone review.
5. Save the workbook and/or export decisions through `review_workbook.csv` for the later approved-dataset task.

No dataset examples were modified by this script.
