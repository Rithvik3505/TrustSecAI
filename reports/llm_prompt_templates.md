# TrustSecAI LLM Prompt Templates

## Template Principles

All prompt templates should require the model to:

- use only the supplied IDS, SHAP, and graph context
- preserve uncertainty
- cite available ATT&CK, CAPEC, CWE, and CVE IDs
- separate classifier evidence from threat-intelligence context
- avoid unsupported attribution
- produce deterministic, auditable outputs

These templates are designs for future corpus generation. They should not be used to generate the corpus in this phase.

## 1. Incident Report Generation

### Instruction

```text
Generate a SOC analyst incident assessment from the provided TrustSecAI context. Use only the supplied evidence. Include classifier result, key SHAP evidence, ATT&CK mapping, relevant attack patterns, candidate vulnerabilities, mitigations, recommended actions, and uncertainties.
```

### Input

```json
{
  "ids": {
    "prediction": "...",
    "confidence": 0.0
  },
  "shap": {
    "top_features": []
  },
  "graph_context": {}
}
```

### Expected Output

```json
{
  "title": "Security Incident Assessment",
  "primary_assessment": "...",
  "classifier_evidence": [],
  "attack_mapping": [],
  "threat_context": [],
  "candidate_vulnerabilities": [],
  "recommended_actions": [],
  "uncertainties": [],
  "severity": "low|medium|high|critical",
  "confidence": "low|medium|high"
}
```

## 2. Threat Assessment

### Instruction

```text
Assess the likely threat represented by the IDS prediction and graph context. Explain the likely attacker objective, mapped ATT&CK tactic/technique, relevant CAPEC behavior, and operational risk. Do not claim facts that are not present in the context.
```

### Expected Output

```json
{
  "threat_summary": "...",
  "likely_objective": "...",
  "mapped_technique": {
    "attack_id": "...",
    "name": "..."
  },
  "tactics": [],
  "risk_drivers": [],
  "evidence": [],
  "uncertainties": []
}
```

## 3. Mitigation Recommendation

### Instruction

```text
Recommend prioritized mitigations for the supplied incident context. Prefer mitigations from ATT&CK and CAPEC. Include detection or validation steps when available. Separate immediate containment from longer-term hardening.
```

### Expected Output

```json
{
  "immediate_actions": [],
  "hardening_actions": [],
  "detection_and_validation": [],
  "mapped_mitigations": [],
  "rationale": [],
  "limitations": []
}
```

## 4. Executive Summary

### Instruction

```text
Write a concise executive summary of the incident for a non-technical stakeholder. Keep the language clear and avoid unnecessary technical detail. Preserve severity, business impact, confidence, and recommended next steps.
```

### Expected Output

```json
{
  "summary": "...",
  "severity": "...",
  "business_impact": "...",
  "confidence": "...",
  "next_steps": []
}
```

## 5. ATT&CK Mapping

### Instruction

```text
Map the IDS prediction to ATT&CK context using the supplied graph data. Return the technique, tactic, related mitigations, detection guidance, and supporting provenance. If the mapping is broad or uncertain, say so explicitly.
```

### Expected Output

```json
{
  "ids_prediction": "...",
  "attack_mapping": {
    "technique_id": "...",
    "technique_name": "...",
    "tactics": []
  },
  "mitigations": [],
  "detection_guidance": [],
  "provenance": [],
  "mapping_confidence": "low|medium|high",
  "caveats": []
}
```

## 6. Security Analyst Reasoning

### Instruction

```text
Explain how the classifier evidence and graph context support or limit the incident assessment. Discuss top SHAP features, mapped technique behavior, and any retrieved vulnerability context. Use cautious language for inferred relationships.
```

### Expected Output

```json
{
  "reasoning": [
    {
      "step": 1,
      "claim": "...",
      "evidence": []
    }
  ],
  "classifier_interpretation": [],
  "graph_interpretation": [],
  "inferred_context": [],
  "uncertainties": []
}
```

## 7. Vulnerability Context Summary

### Instruction

```text
Summarize candidate vulnerability context for the incident. Use CVE/CWE/product context only when present in the supplied graph. Mark CVEs as candidate context unless the input contains asset evidence proving exposure.
```

### Expected Output

```json
{
  "weaknesses": [],
  "candidate_cves": [],
  "affected_products": [],
  "cvss_summary": "...",
  "asset_exposure_note": "...",
  "references": []
}
```

## 8. Uncertainty and Evidence Review

### Instruction

```text
Review the supplied TrustSecAI context for evidence strength and uncertainty. Identify which conclusions are directly supported, which are inferred, and what additional evidence a SOC analyst should collect.
```

### Expected Output

```json
{
  "directly_supported": [],
  "inferred": [],
  "unsupported_or_missing": [],
  "recommended_evidence_to_collect": [],
  "overall_confidence": "low|medium|high"
}
```

## Negative Instruction Patterns

Future corpus generation should include refusal/correction examples for unsafe analyst behavior:

- When no CVEs are present, the model should not invent CVEs.
- When only group usage context is present, the model should not attribute the incident to that group.
- When graph context is sparse, the model should state limitations.
- When classifier confidence is low, the model should recommend analyst review.

## Prompt Variable Names

Use stable variable names in future generation scripts:

- `{ids_prediction}`
- `{classifier_confidence}`
- `{binary_label}`
- `{source_file}`
- `{top_shap_features}`
- `{graph_context_json}`
- `{audience}`
- `{output_format}`
- `{max_words}`

