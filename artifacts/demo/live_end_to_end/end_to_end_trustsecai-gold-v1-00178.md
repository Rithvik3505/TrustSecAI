# TrustSecAI Security Assessment Report

## Executive Summary

The classifier identified PortScan with 99.61% confidence and prediction ATTACK. SHAP evidence is led by Average Packet Size, Destination Port, and graph context maps the behavior to T1046 Network Service Discovery as contextual intelligence. CVE/CWE candidate enrichment is present, but asset exposure is not established.

## Incident Summary

- IDS label: `PortScan`
- Binary classifier prediction: `ATTACK`
- Classifier confidence: `99.61%`
- Sample ID: `classifier-demo-010`

## Classifier And SHAP Evidence

- Average Packet Size = 5.0, SHAP +2.7827, supports attack
- Destination Port = 801.0, SHAP -1.2856, supports benign
- Bwd Packets/s = 12987.01299, SHAP +0.9160, supports attack
- Max Packet Length = 6.0, SHAP +0.8469, supports attack
- Bwd Header Length = 20.0, SHAP +0.8439, supports attack

## Graph Context

- Technique: `T1046` Network Service Discovery
- Tactics: TA0007 Discovery
- Mitigations: M1030, M1031, M1042

Graph context is contextual intelligence and does not prove compromise or attribution.

## LLM Secondary Assessment

- LLM output parsed successfully.
- Graph interpretation: Retrieved graph context maps the subtype to Network Service Discovery (T1046) under Discovery (TA0007) as contextual intelligence, not proof of compromise.

### Recommended Actions

- Prioritize validation against the source capture
- Compare the SHAP-highlighted flow characteristics against packet and session telemetry
- Escalate if independent telemetry supports the mapped behavior

### LLM Limitations

- CVE and product entries are candidate enrichment only; asset exposure is not established.
- ATT&CK group, tool, and malware entries are usage context, not attribution.
- Some graph relationships are inferred and should be weighted below direct provenance.

## Classifier vs LLM Agreement

- Category: `agree_attack_high_confidence`
- Rationale: Classifier and LLM both support an attack-oriented assessment for PortScan with high classifier confidence.

## Defensive Attack Chain Hypothesis

- Attack-chain mode: static fallback
- Seed technique: `T1046` Network Service Discovery
- Confidence: `medium`

### Likely Next Tactics/Techniques

- Discovery: T1018 Remote System Discovery
- Credential Access: T1110 Brute Force
- Lateral Movement: T1021 Remote Services

### Chain Mitigations

- M1031 Network Intrusion Prevention
- M1030 Network Segmentation
- M1018 User Account Management

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
