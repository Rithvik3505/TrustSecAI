# TrustSecAI Security Assessment Report

## Executive Summary

The classifier identified Web Attack - Sql Injection with 98.32% confidence and prediction ATTACK. SHAP evidence is led by Destination Port, Init_Win_bytes_backward, and graph context maps the behavior to T1190 Exploit Public-Facing Application as contextual intelligence. No CVE or asset exposure evidence is present, so this is a triage assessment rather than confirmed compromise.

## Incident Summary

- IDS label: `Web Attack - Sql Injection`
- Binary classifier prediction: `ATTACK`
- Classifier confidence: `98.32%`
- Sample ID: `1448270`

## Classifier And SHAP Evidence

- Destination Port = 80.0, SHAP +2.7169, supports attack
- Init_Win_bytes_backward = 236.0, SHAP +2.3629, supports attack
- Bwd Packet Length Std = 0.0, SHAP -1.1524, supports benign
- Bwd Packets/s = 20833.33333, SHAP +0.7957, supports attack
- Bwd Header Length = 32.0, SHAP -0.5833, supports benign

## Graph Context

- Technique: `T1190` Exploit Public-Facing Application
- Tactics: TA0001 Initial Access
- Mitigations: M1016, M1026, M1030, M1035, M1037, M1048, M1050, M1051

Graph context is contextual intelligence and does not prove compromise or attribution.

## LLM Secondary Assessment

- LLM output parsed successfully.
- Graph interpretation: Retrieved graph context maps the subtype to Exploit Public-Facing Application (T1190) under Initial Access (TA0001) as contextual intelligence, not proof of compromise.

### Recommended Actions

- Validate the sample against packet capture and session telemetry
- Escalate if confirmed compromise; review post-exploit process/egress for additional detection
- Preserve the limitation notes when sharing the assistant's output

### LLM Limitations

- No CVE evidence is present in the supplied graph context.
- ATT&CK group, tool, and malware entries are usage context, not attribution.

## Classifier vs LLM Agreement

- Category: `agree_attack_high_confidence`
- Rationale: Classifier and LLM both support an attack-oriented assessment for Web Attack - Sql Injection with high classifier confidence.

## Defensive Attack Chain Hypothesis

- Seed technique: `T1190` Exploit Public-Facing Application
- Confidence: `medium`

### Likely Next Tactics/Techniques

- Execution: T1059 Command and Scripting Interpreter
- Credential Access: candidate credentials from web applications
- Exfiltration: T1567 Exfiltration Over Web Service

### Chain Mitigations

- M1016 Vulnerability Scanning
- M1030 Network Segmentation
- M1035 Limit Access to Resource Over Network

### Caveats

- This is a defensive hypothesis for prioritizing investigation, not an instruction sequence.
- Graph context and ATT&CK mappings provide contextual intelligence, not proof of attacker behavior.
- No CVE evidence is present in the supplied context.

## Overall Limitations

- Offline demo uses frozen LoRA compact evaluation output; it does not run live inference.
- Agreement and attack-chain modules are deterministic scaffolding for the final demo.
- Unsafe-attribution evaluation flags are known to be overbroad and require human interpretation.
