# Corpus Generation Quality Improvements

## Scope

This refinement updates only corpus generation quality. It does not change the JSON schema, metadata fields, provenance handling, validation logic, curriculum definitions, dataset balance, task distribution, or pilot size.

## Improvements Implemented

### Reasoning Diversity

- Added ten deterministic reasoning styles, including observation/evidence/assessment, evidence/risk/recommendation, confidence/limitations/next steps, classifier/graph/uncertainty, and operational risk/control review patterns.
- Rotated styles by example sequence index to avoid identical reasoning structures across examples.
- Preserved reproducibility through deterministic selection rather than non-repeatable randomness.

### Natural Analyst Language

- Reworked outputs to sound more like concise SOC analyst notes.
- Reduced repeated phrasing such as plain "The graph maps..." statements.
- Added clearer response language for triage, validation, mitigation, and evidence collection.

### Confidence-Aware Responses

- High confidence examples now use stronger but still bounded language.
- Medium confidence examples use balanced wording and request corroborating telemetry.
- Low confidence examples explicitly recommend analyst review and avoid firm conclusions.

### SHAP Formatting

- Rounded SHAP values to four decimal places.
- Added `contribution_strength` labels: `high`, `moderate`, or `low`.
- Updated classifier-evidence text to use contribution strength instead of exposing long floating-point values.

### Compact Retrieval Context

- Compacted verbose graph `description`, `x_mitre_detection`, and `execution_flow` text to concise summaries.
- Preserved IDs, names, properties, provenance, relationship metadata, confidence fields, and retrieval structure.
- Verified regenerated corpus graph descriptions are capped at 420 characters.

### Graph Interpretation

- Added explicit wording that GraphRAG provides contextual evidence and enrichment, not proof of compromise.
- Avoided wording that implies retrieved ATT&CK entities confirm attacker behavior or attribution.

## Regeneration Results

- Pilot examples regenerated: 240
- Accepted by validation: 240
- Rejected by validation: 0
- Validation warnings: 0
- Label distribution preserved: 48 examples per available IDS label
- Task distribution preserved
- Variant distribution preserved
- Curriculum distribution preserved

## Notes Before Scaling

- The regenerated pilot should be manually reviewed before scaling to the final 10k-25k corpus.
- The next quality-review focus should be whether the deterministic analyst phrasing is varied enough across full prompt families.
- No LoRA training, fine-tuning, inference, or LLM integration was performed.

