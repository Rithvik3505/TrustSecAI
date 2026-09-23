# TrustSecAI Security Assessment Report

## Executive Summary

The classifier identified DDoS with 100.00% confidence and prediction ATTACK. SHAP evidence is led by Bwd Packet Length Std, Init_Win_bytes_backward, and graph context maps the behavior to T1498 Network Denial of Service as contextual intelligence. No CVE or asset exposure evidence is present, so this is a triage assessment rather than confirmed compromise.

## Incident Summary

- IDS label: `DDoS`
- Binary classifier prediction: `ATTACK`
- Classifier confidence: `100.00%`
- Sample ID: `135033`

## Classifier And SHAP Evidence

- Bwd Packet Length Std = 2189.772933, SHAP +8.4191, supports attack
- Init_Win_bytes_backward = 229.0, SHAP +1.7810, supports attack
- Bwd Packet Length Mean = 1933.5, SHAP +1.3032, supports attack
- Packet Length Std = 1911.59573, SHAP +0.6300, supports attack
- Destination Port = 80.0, SHAP +0.5918, supports attack

## Graph Context

- Technique: `T1498` Network Denial of Service
- Tactics: TA0040 Impact
- Mitigations: M1037

Graph context is contextual intelligence and does not prove compromise or attribution.

## LLM Secondary Assessment

- LLM output parsed successfully.
- Graph interpretation: Retrieved graph context maps the subtype to Network Denial of Service (T1498) under Impact (TA0040) as contextual intelligence, not proof of compromise.

### Recommended Actions

- Filter Network Traffic (M1037)
- Behavioral Detection of T1498 – Network Denial of Service Across Platforms
- Preserve the sample_id and base_context_id during escalation for leakage-safe review

### LLM Limitations

- No CVE evidence is present in the supplied graph context.
- ATT&CK group, tool, and malware entries are usage context, not attribution.

## Classifier vs LLM Agreement

- Category: `agree_attack_high_confidence`
- Rationale: Classifier and LLM both support an attack-oriented assessment for DDoS with high classifier confidence.

## Defensive Attack Chain Hypothesis

- Attack-chain mode: graph-backed Neo4j traversal
- Seed technique: `T1498` Network Denial of Service
- Confidence: `medium`

### Likely Next Tactics/Techniques

- Impact: T1485 Data Destruction
- Impact: T1485.001 Lifecycle-Triggered Deletion
- Impact: T1486 Data Encrypted for Impact
- Impact: T1487 Disk Structure Wipe
- Impact: T1488 Disk Content Wipe

### Chain Mitigations

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
