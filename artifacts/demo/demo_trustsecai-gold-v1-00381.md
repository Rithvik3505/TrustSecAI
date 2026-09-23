# TrustSecAI Security Assessment Report

## Executive Summary

The classifier identified Bot with 100.00% confidence and prediction ATTACK. SHAP evidence is led by Init_Win_bytes_backward, Bwd Packet Length Mean, and graph context maps the behavior to T1105 Ingress Tool Transfer as contextual intelligence. No CVE or asset exposure evidence is present, so this is a triage assessment rather than confirmed compromise.

## Incident Summary

- IDS label: `Bot`
- Binary classifier prediction: `ATTACK`
- Classifier confidence: `100.00%`
- Sample ID: `534402`

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

- Category: `agree_attack_high_confidence`
- Rationale: Classifier and LLM both support an attack-oriented assessment for Bot with high classifier confidence.

## Defensive Attack Chain Hypothesis

- Attack-chain mode: graph-backed Neo4j traversal
- Seed technique: `T1105` Ingress Tool Transfer
- Confidence: `medium`

### Likely Next Tactics/Techniques

- Command and Control: T1001 Data Obfuscation
- Command and Control: T1001.001 Junk Data
- Command and Control: T1001.002 Steganography
- Command and Control: T1001.003 Protocol or Service Impersonation
- Command and Control: T1008 Fallback Channels

### Chain Mitigations

- M1031 Network Intrusion Prevention
- M1037 Filter Network Traffic

### Vulnerability Context

- CAPEC: none reached
- CWE: none reached
- CVE: none reached

### Caveats

- This is a defensive hypothesis for prioritizing investigation, not an instruction sequence.
- Graph traversal returns candidate investigation pivots; it does not prove compromise.
- Group, tool, and malware context must not be treated as attribution.
- No CVE evidence was reached from the graph traversal for this seed.

## Overall Limitations

- Offline demo uses frozen LoRA compact evaluation output; it does not run live inference.
- Agreement and attack-chain modules are deterministic scaffolding for the final demo.
- Unsafe-attribution evaluation flags are known to be overbroad and require human interpretation.
