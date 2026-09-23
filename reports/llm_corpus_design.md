# TrustSecAI LLM Fine-Tuning Corpus Design

## Objective

The TrustSecAI fine-tuning corpus should train an open-weight Llama 3.x model with PEFT/LoRA to produce cybersecurity analyst outputs from structured TrustSecAI evidence.

The model should learn:

- incident assessment structure
- evidence-grounded reasoning
- ATT&CK/CAPEC/CWE/CVE terminology
- mitigation recommendation style
- uncertainty handling
- provenance-aware reporting

The model should not learn to replace the graph retrieval layer. Retrieval remains the source of truth for current threat context.

## Corpus Categories

### 1. Knowledge Corpus

Purpose:

- Teach the model concise cybersecurity language grounded in ATT&CK, CAPEC, CWE, and CVE concepts.
- Improve terminology, mapping explanations, and mitigation phrasing.

Sources:

- ATT&CK techniques, tactics, mitigations, detection guidance
- CAPEC attack patterns, prerequisites, consequences, mitigations
- NVD CVE descriptions and CVSS summaries
- CWE IDs as bridge metadata

Expected size:

- 3,000 to 8,000 examples, depending on deduplication and template variety.

Contribution:

- Domain vocabulary
- Accurate mapping style
- Better security-language fluency

Risk:

- If over-weighted, the model may become a knowledge-base summarizer rather than an incident analyst.

### 2. Instruction Corpus

Purpose:

- Teach task-following behavior for analyst workflows.

Task families:

- incident report generation
- threat assessment
- mitigation recommendation
- executive summary
- ATT&CK mapping
- evidence review
- uncertainty analysis

Expected size:

- 2,000 to 5,000 examples.

Contribution:

- Stable outputs
- Better response formatting
- Audience-aware reporting

Risk:

- Too many near-identical templates can cause repetitive outputs.

### 3. Threat Intelligence Corpus

Purpose:

- Teach how to combine ATT&CK, CAPEC, CWE, CVE, products, references, tools, malware, groups, and detection guidance without overclaiming.

Sources:

- Neo4j graph retrieval output
- `artifacts/retrieval/*.json`
- future retrieval outputs for all IDS labels

Expected size:

- 1,500 to 4,000 examples.

Contribution:

- Multi-hop context synthesis
- Provenance-aware summarization
- Separation of direct and inferred relationships

Risk:

- Inferred CAPEC-CWE-CVE chains can overstate vulnerability relevance if asset evidence is absent.

### 4. Incident Report Corpus

Purpose:

- Teach the final user-facing TrustSecAI report style.

Sources:

- IDS labels from CICIDS2017
- classifier confidence
- SHAP local explanations
- graph retrieval context
- controlled report templates

Expected size:

- 2,000 to 6,000 examples.

Contribution:

- SOC-ready incident summaries
- SHAP and graph evidence integration
- Practical recommendations

Risk:

- CICIDS2017 has strong day/file distribution shift, so examples should avoid claiming the model has proven real-world generalization.

### 5. Synthetic SFT Corpus

Purpose:

- Create supervised instruction-response examples from TrustSecAI's own pipeline outputs.
- This should be the core corpus because it matches the production input shape.

Inputs:

```text
IDS prediction + confidence
SHAP top features
Graph Retrieval JSON
```

Outputs:

- structured incident assessment
- mitigation recommendation
- executive summary
- uncertainty analysis
- ATT&CK mapping

Expected size:

- 5,000 to 15,000 examples after quality filtering.

Contribution:

- Teaches the exact future LLM behavior.
- Aligns model outputs with TrustSecAI architecture.
- Preserves reproducibility because examples can be regenerated from structured artifacts.

Risk:

- Synthetic outputs can encode template bias. Human review or rule-based quality checks are needed before training.

## Recommended Corpus Balance

Initial target proportions:

| Component | Proportion | Rationale |
|---|---:|---|
| Synthetic IDS + SHAP + graph SFT | 45% | Closest to actual TrustSecAI runtime use |
| ATT&CK knowledge/instruction | 18% | Core behavior/tactic/mitigation grounding |
| CAPEC attack-pattern reasoning | 12% | Adds attack mechanics and consequences |
| NVD/CVE vulnerability summaries | 10% | Adds vulnerability and product context without dominating |
| SOC report and executive-summary style | 10% | Teaches usable reporting formats |
| Uncertainty/refusal/correction examples | 5% | Reduces hallucination and overclaiming |

This balance favors the production workflow while still grounding the model in cybersecurity knowledge.

## Synthetic Data Strategy

Synthetic instruction-response pairs should be generated only after this design phase.

Recommended methodology:

1. Select incident seeds from cleaned CICIDS2017.
2. Run the trained XGBoost model to obtain prediction and confidence.
3. Attach local SHAP explanations using top contributing features.
4. Resolve the IDS label through `artifacts/attack_label_mapping.json`.
5. Run the graph retrieval pipeline to produce structured context.
6. Select a prompt template from `reports/llm_prompt_templates.md`.
7. Generate a target response using deterministic template logic first.
8. Optionally use a stronger teacher model later, but only with strict validation against graph provenance.
9. Validate every output for unsupported entities, missing provenance, invented CVEs, and unsupported attribution.
10. Save accepted examples as JSONL using the schema in `reports/llm_training_schema.md`.

### Example Synthetic Input Assembly

```text
Prediction: PortScan
Classifier confidence: 0.98
SHAP: top 5 to 10 features
Graph context: T1046, Discovery tactic, mitigations, detection guidance, CAPEC/CWE/CVE candidates
Template: incident_report_generation
```

### Quality Checks

Every synthetic example should pass:

- valid JSON
- non-empty instruction, input, output, metadata
- all referenced ATT&CK/CAPEC/CWE/CVE IDs appear in input
- no invented products or references
- inferred relationships are described as inferred
- severity is justified by classifier confidence, technique context, CVSS, and available evidence
- no group/tool/malware context is framed as attribution unless explicitly supported

## Data Cleaning Recommendations

### CICIDS2017

- Use cleaned parquet, not raw CSVs.
- Preserve `source_file`.
- Summarize numeric features through SHAP instead of including all raw values.
- Balance examples across labels.
- Avoid duplicating many near-identical benign rows.

### ATT&CK

- Use active Enterprise ATT&CK objects.
- Exclude revoked and deprecated objects.
- Normalize external IDs.
- Strip citation markup when creating natural-language targets.
- Preserve source STIX ID and external references in metadata.

### CAPEC

- Use the comprehensive dictionary as the canonical source.
- Deduplicate alternate CAPEC views.
- Normalize CAPEC IDs and ATT&CK mappings.
- Parse semi-structured fields into lists where possible.
- Preserve blank-field awareness rather than filling missing values with guesses.

### CWE

- Use only referenced CWE IDs currently available in the graph.
- Do not invent CWE descriptions.
- Add a full official CWE dictionary later if richer CWE examples are required.

### NVD/CVE

- Deduplicate CVEs across year, modified, and recent feeds.
- Filter rejected/reserved records.
- Normalize CVSS v2/v3/v4 into a consistent summary.
- Preserve CVSS version and vector.
- Mark unscored CVEs as unscored.
- Treat CVEs reached through CWE as candidate context, not confirmed exposure.

### Graph Retrieval JSON

- Preserve deterministic ordering.
- Remove duplicate entities.
- Preserve provenance entries.
- Keep original vs inferred relationship flags.
- Limit extremely long CVE/product/reference lists using ranking.

## Training and Evaluation Notes

The fine-tuning stage should include:

- held-out IDS labels or incident families where possible
- exact-match checks for required IDs
- hallucination checks for unsupported CVEs/products/groups
- human review of a small validation set
- comparison between base model and LoRA-tuned model on the same graph contexts

Recommended Week 3 carry-forward:

- Build a corpus generator that reads retrieval JSON, SHAP explanations, and IDS predictions.
- Generate a small pilot dataset first, around 200 to 500 examples.
- Validate schema and output quality before scaling.

