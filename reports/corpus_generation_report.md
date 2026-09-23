# TrustSecAI Corpus Generation Report

## Pipeline Overview

The corpus generation framework reads existing TrustSecAI evidence artifacts and creates supervised fine-tuning examples using deterministic templates. It does not train, fine-tune, or call any LLM.

Pipeline:

```text
IDS prediction + confidence
-> SHAP top features
-> Graph Retrieval JSON
-> Prompt template
-> Curriculum level
-> Deterministic target output
-> Quality validation
-> JSONL export
```

## Example Generation Flow

1. Load retrieval contexts from `artifacts/retrieval/*.json`.
2. Attach SHAP explanations from `artifacts/shap/sample_explanations.json` when available.
3. Apply one of the approved prompt templates.
4. Limit graph context according to easy, medium, hard, or expert curriculum settings.
5. Generate a structured target output that cites only supplied evidence.
6. Validate the example for unsupported IDs, missing provenance, duplicates, and attribution overclaiming.

## Validation Summary

- Accepted examples: 240
- Rejected examples: 0
- Validation warnings: 0

## Known Limitations

- The pilot uses only the currently exported retrieval contexts, so IDS label coverage is limited to available JSON artifacts.
- SHAP local examples are available for a subset of labels; other labels use deterministic fallback feature summaries.
- Target outputs are template-generated and should be manually reviewed before being used for training.
- CVEs are framed as candidate context unless separate asset exposure evidence is supplied.
- Actor, tool, and malware relationships are treated as ATT&CK usage context, not attribution.

## Recommended Scaling Strategy

- Export retrieval JSON for every mapped CICIDS2017 attack label.
- Generate a 200-500 example review set per major prompt family before full-scale generation.
- Add human review for a stratified sample of high, low, sparse, and inferred-context examples.
- Keep train/validation/test splits grouped by base incident and graph context to avoid leakage.
- Add a full official CWE dictionary if rich CWE explanation tasks are required.

## Estimated Final Corpus Size

A practical final corpus target is 10,000 to 25,000 examples after quality filtering, with synthetic IDS + SHAP + graph examples forming the largest component.
