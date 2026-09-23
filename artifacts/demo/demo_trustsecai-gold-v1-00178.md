# TrustSecAI Security Assessment Report

## Executive Summary

The classifier identified PortScan with 99.86% confidence and prediction ATTACK. SHAP evidence is led by Average Packet Size, Destination Port, and graph context maps the behavior to T1046 Network Service Discovery as contextual intelligence. CVE/CWE candidate enrichment is present, but asset exposure is not established.

## Incident Summary

- IDS label: `PortScan`
- Binary classifier prediction: `ATTACK`
- Classifier confidence: `99.86%`
- Sample ID: `308785`

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

- Attack-chain mode: graph-backed Neo4j traversal
- Seed technique: `T1046` Network Service Discovery
- Confidence: `medium`

### Likely Next Tactics/Techniques

- Discovery: T1007 System Service Discovery
- Discovery: T1010 Application Window Discovery
- Discovery: T1012 Query Registry
- Discovery: T1016 System Network Configuration Discovery
- Discovery: T1016.001 Internet Connection Discovery

### Chain Mitigations

- M1030 Network Segmentation
- M1031 Network Intrusion Prevention
- M1042 Disable or Remove Feature or Program

### Vulnerability Context

- CAPEC: CAPEC-300 Port Scanning
- CWE: CWE-200
- CVE: CVE-2026-44486, CVE-2026-44786, CVE-2026-45329, CVE-2026-42907, CVE-2026-44784

### Caveats

- This is a defensive hypothesis for prioritizing investigation, not an instruction sequence.
- Graph traversal returns candidate investigation pivots; it does not prove compromise.
- Group, tool, and malware context must not be treated as attribution.

## Overall Limitations

- Offline demo uses frozen LoRA compact evaluation output; it does not run live inference.
- Agreement and attack-chain modules are deterministic scaffolding for the final demo.
- Unsafe-attribution evaluation flags are known to be overbroad and require human interpretation.
