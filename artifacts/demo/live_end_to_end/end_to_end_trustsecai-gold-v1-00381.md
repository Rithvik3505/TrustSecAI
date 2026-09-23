# TrustSecAI Security Assessment Report

## Executive Summary

The classifier identified Bot with 59.93% confidence and prediction ATTACK. SHAP evidence is led by Init_Win_bytes_backward, Bwd Packet Length Mean, and graph context maps the behavior to T1105 Ingress Tool Transfer as contextual intelligence. No CVE or asset exposure evidence is present, so this is a triage assessment rather than confirmed compromise.

## Incident Summary

- IDS label: `Bot`
- Binary classifier prediction: `ATTACK`
- Classifier confidence: `59.93%`
- Sample ID: `classifier-demo-020`

## Classifier And SHAP Evidence

- Init_Win_bytes_backward = 237.0, SHAP +3.1976, supports attack
- Bwd Packet Length Mean = 44.66666667, SHAP +1.7462, supports attack
- Bwd Packet Length Max = 128.0, SHAP +0.9155, supports attack
- Destination Port = 8080.0, SHAP +0.6262, supports attack
- Bwd IAT Min = 606.0, SHAP +0.5698, supports attack

## Graph Context

- Technique: `T1105` Ingress Tool Transfer
- Tactics: TA0011 Command and Control
- Mitigations: M1031, M1037

Graph context is contextual intelligence and does not prove compromise or attribution.

## LLM Secondary Assessment

- LLM output required fallback parsing.
- Graph interpretation: Retrieved graph context maps the subtype to Ingress Tool Transfer (T1105) under Command and Control (TA0011) as contextual intelligence, not proof of compromise.

### Recommended Actions

- None supplied

### LLM Limitations

- No CVE evidence is present in the supplied graph context.
- ATT&CK group, tool, and malware entries are usage context, not attribution.

## Classifier vs LLM Agreement

- Category: `agree_attack_low_confidence`
- Rationale: Classifier and LLM both support attack-oriented review for Bot, but classifier confidence is not high.

## Defensive Attack Chain Hypothesis

- Attack-chain mode: static fallback
- Seed technique: `T1105` Ingress Tool Transfer
- Confidence: `low`

### Likely Next Tactics/Techniques

- Command and Control: T1071 Application Layer Protocol
- Execution: T1059 Command and Scripting Interpreter
- Impact: T1499 Endpoint Denial of Service

### Chain Mitigations

- M1031 Network Intrusion Prevention
- M1037 Filter Network Traffic
- M1040 Behavior Prevention on Endpoint

### Vulnerability Context

- CAPEC: none reached
- CWE: none reached
- CVE: none reached

### Caveats

- This is a defensive hypothesis for prioritizing investigation, not an instruction sequence.
- Graph context and ATT&CK mappings provide contextual intelligence, not proof of attacker behavior.
- This output is not attribution and does not confirm compromise.
- Neo4j unavailable; used static ATT&CK seed mapping.
- No CVE evidence is present in the supplied context.

## Overall Limitations

- Live demo runs classifier inference, response parsing, agreement analysis, attack-chain logic, and report assembly.
- LoRA text generation is cached from HPC compact evaluation outputs and is not executed locally.
- Graph context in the report is contextual intelligence, not proof of compromise or attribution.
