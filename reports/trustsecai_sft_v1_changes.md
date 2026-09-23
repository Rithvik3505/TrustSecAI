# TrustSecAI SFT v1 Changes

## Removed Boilerplate

- Removed target-output fields that mentioned future agreement-analysis preparation.
- Removed phrases such as `No agreement module is executed` from model-supervised outputs.
- Removed difficulty/curriculum commentary from target outputs.
- Kept implementation and generation details in reports/metadata only, not in model target text.

## Analyst Personas And Styles

- Added deterministic persona-style selection for analyst prose without exposing persona labels in outputs.
- Persona styles cover triage, investigation, technical assessment, hunting, incident response, engineering controls, executive briefing, and assurance/risk framing.
- Persona selection affects prose only and does not alter facts, graph context, schema, or metadata.

## Reasoning Pattern Expansion

- Expanded narrative patterns to include observation/evidence/action, signal/context/limitation, confidence/corroboration/caveat, risk/containment/validation, hypothesis/evidence-gap, detection/hardening, and escalation/follow-up flows.
- Improved SHAP language to reference 2-4 supplied features naturally rather than repeating all five mechanically.
- Added confidence-aware phrasing for high, medium, and low confidence cases.

## Output-Only Diversity Methodology

- Updated diversity analysis to report both full-record diversity and target-output diversity.
- Target-output diversity is the primary LoRA-readiness metric.
- Full-record diversity remains available for pipeline diagnostics.
- Target-output analysis excludes structured provenance, IDs, and graph payloads where appropriate.

## Validation Results

- Examples generated: 30000
- Accepted: 30000
- Rejected: 0
- Warnings: 0
- IDS label balance: 6000 examples per label
- Schema and metadata structure: unchanged

## Remaining Limitations

- The corpus is generated from five available retrieval contexts, so repeated ATT&CK techniques, mitigation names, SHAP feature families, and uncertainty caveats remain expected.
- The repeated exact sentence percentage is still high in target outputs because safety language and grounded source facts intentionally recur.
- Manual spot-checking is still required before PEFT/LoRA fine-tuning.

## Training Status

No LoRA training, fine-tuning, inference, retrieval changes, graph changes, IDS changes, or SHAP changes were performed.
