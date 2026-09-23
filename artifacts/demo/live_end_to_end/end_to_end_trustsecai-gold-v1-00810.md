# TrustSecAI Security Assessment Report

## Executive Summary

The classifier identified FTP-Patator with 100.00% confidence and prediction ATTACK. SHAP evidence is led by Destination Port, Init_Win_bytes_backward, and graph context maps the behavior to T1110 Brute Force as contextual intelligence. CVE/CWE candidate enrichment is present, but asset exposure is not established.

## Incident Summary

- IDS label: `FTP-Patator`
- Binary classifier prediction: `ATTACK`
- Classifier confidence: `100.00%`
- Sample ID: `classifier-demo-015`

## Classifier And SHAP Evidence

- Destination Port = 21.0, SHAP +4.8365, supports attack
- Init_Win_bytes_backward = 227.0, SHAP +0.9310, supports attack
- Bwd Packet Length Mean = 12.53333333, SHAP +0.7523, supports attack
- Bwd Packet Length Std = 14.54975045, SHAP -0.6869, supports benign
- Bwd IAT Total = 8864161.0, SHAP +0.4666, supports attack

## Graph Context

- Technique: `T1110` Brute Force
- Tactics: TA0006 Credential Access
- Mitigations: M1018, M1027, M1032, M1036

Graph context is contextual intelligence and does not prove compromise or attribution.

## LLM Secondary Assessment

- LLM output parsed successfully.
- Graph interpretation: Retrieved graph context maps the subtype to Brute Force (T1110) under Credential Access (TA0006) as contextual intelligence, not proof of compromise.

### Recommended Actions

- Alert immediately if independent telemetry corroborates this context.
- Review password policies and user account management.
- Enable multi-factor authentication if not already enabled.

### LLM Limitations

- No CVE evidence should be cited as proof of exploitation.
- ATT&CK group, tool, and malware entries are usage context, not attribution.
- Some graph relationships are inferred and should be weighted below direct provenance.

## Classifier vs LLM Agreement

- Category: `agree_attack_high_confidence`
- Rationale: Classifier and LLM both support an attack-oriented assessment for FTP-Patator with high classifier confidence.

## Defensive Attack Chain Hypothesis

- Attack-chain mode: static fallback
- Seed technique: `T1110` Brute Force
- Confidence: `medium`

### Likely Next Tactics/Techniques

- Persistence: T1078 Valid Accounts
- Discovery: T1083 File and Directory Discovery
- Collection: T1005 Data from Local System

### Chain Mitigations

- M1036 Account Use Policies
- M1032 Multi-factor Authentication
- M1027 Password Policies

### Vulnerability Context

- CAPEC: none reached
- CWE: none reached
- CVE: none reached

### Caveats

- This is a defensive hypothesis for prioritizing investigation, not an instruction sequence.
- Graph context and ATT&CK mappings provide contextual intelligence, not proof of attacker behavior.
- This output is not attribution and does not confirm compromise.
- Neo4j unavailable; used static ATT&CK seed mapping.

## Overall Limitations

- Live demo runs classifier inference, response parsing, agreement analysis, attack-chain logic, and report assembly.
- LoRA text generation is cached from HPC compact evaluation outputs and is not executed locally.
- Graph context in the report is contextual intelligence, not proof of compromise or attribution.
