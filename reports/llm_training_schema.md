# TrustSecAI LLM Training Schema

## Objective

The fine-tuning corpus should teach a Llama 3.x model to act as a cybersecurity analyst over TrustSecAI evidence. The model should learn response structure, reasoning style, uncertainty handling, and provenance-aware reporting. It should not memorize raw datasets or replace graph retrieval.

Recommended storage format:

```text
JSONL, one supervised example per line
```

## Unified JSONL Record

```json
{
  "instruction": "Generate a SOC analyst incident assessment from the provided IDS, SHAP, and graph context.",
  "input": {
    "ids": {
      "prediction": "PortScan",
      "confidence": 0.98,
      "binary_label": 1,
      "source_file": "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    },
    "shap": {
      "top_features": [
        {
          "feature": "Destination Port",
          "value": 80,
          "shap_value": 0.43
        }
      ]
    },
    "graph_context": {
      "attack": {},
      "capec": [],
      "cwes": [],
      "cves": [],
      "products": [],
      "references": [],
      "groups": [],
      "tools": [],
      "malware": [],
      "detection_guidance": [],
      "provenance": []
    }
  },
  "output": {
    "assessment": "The event is consistent with network service discovery...",
    "attack_mapping": [],
    "evidence": [],
    "recommended_actions": [],
    "uncertainties": [],
    "severity": "medium"
  },
  "metadata": {
    "example_id": "trustsecai-sft-000001",
    "category": "synthetic_sft",
    "task_type": "incident_report_generation",
    "source_datasets": ["CICIDS2017", "ATT&CK", "CAPEC", "NVD"],
    "generation_method": "template_plus_retrieval_context",
    "provenance_required": true,
    "created_at": "YYYY-MM-DD",
    "trustsecai_version": "week2-final",
    "split": "train"
  }
}
```

## Required Fields

### `instruction`

Purpose:

- Defines the user-facing task.
- Allows multiple task types while keeping one schema.
- Helps tune instruction-following behavior rather than raw completion behavior.

Requirements:

- Clear, explicit, and bounded.
- Must tell the model to use only supplied context.
- Should specify the target format when structured output is expected.

### `input`

Purpose:

- Contains all evidence available to the model.
- Keeps retrieval and model reasoning separate.
- Allows future evaluation of whether the model used or ignored evidence.

Recommended subfields:

- `ids`: prediction, confidence, source file, binary label when available.
- `shap`: top features and feature attributions.
- `graph_context`: exact output from the retrieval/context builder.
- `analyst_constraints`: optional tone, audience, length, and allowed output sections.

Requirements:

- Preserve original IDs such as ATT&CK IDs, CAPEC IDs, CWE IDs, CVE IDs.
- Preserve provenance entries.
- Preserve confidence and inferred flags.
- Do not include unsupported free-text facts.

### `output`

Purpose:

- Provides the target response the fine-tuned model should learn.
- Should be analyst-ready, not merely a restatement of the input.

Recommended output styles:

1. Structured JSON for machine-consumable results.
2. Markdown report for SOC analyst readability.
3. Short executive summary for management-level output.

For initial LoRA fine-tuning, prefer a structured JSON output because it improves evaluation and lowers ambiguity.

Recommended fields:

- `assessment`
- `attack_mapping`
- `evidence`
- `mitigations`
- `detection_notes`
- `affected_assets_or_products`
- `potential_consequences`
- `recommended_actions`
- `uncertainties`
- `severity`
- `confidence`

### `metadata`

Purpose:

- Enables reproducibility.
- Supports filtering, balancing, and auditing.
- Records which examples are synthetic versus source-derived.

Recommended metadata fields:

- `example_id`
- `category`
- `task_type`
- `source_datasets`
- `source_ids`
- `generation_method`
- `template_id`
- `quality_checks`
- `provenance_required`
- `created_at`
- `split`

## Output Contract

Every generated target output should obey these rules:

- Cite ATT&CK/CAPEC/CWE/CVE IDs when used.
- Distinguish classifier evidence from graph intelligence.
- Mark inferred CVEs as candidates unless asset evidence is present.
- Avoid attribution claims unless the input explicitly supports them.
- Include uncertainty when context is sparse or ambiguous.
- Do not invent mitigations, CVEs, products, or group names outside the input.

## Split Strategy

Recommended dataset splits:

- Train: 80%
- Validation: 10%
- Test: 10%

Split constraints:

- Keep incident variants from the same base graph context in the same split to avoid template leakage.
- Hold out at least one IDS label family for stress testing if enough examples exist.
- Maintain balanced representation of high-context and low-context labels.

## Example Task Types

| Task Type | Input Sources | Output Style |
|---|---|---|
| `incident_report_generation` | IDS + SHAP + graph context | structured report |
| `threat_assessment` | graph context | risk/severity assessment |
| `mitigation_recommendation` | ATT&CK + CAPEC + CVE context | prioritized actions |
| `executive_summary` | full context | concise non-technical summary |
| `attack_mapping` | IDS label + graph context | ATT&CK/CAPEC/CWE mapping |
| `security_analyst_reasoning` | IDS + SHAP + graph context | evidence-based explanation |
| `uncertainty_analysis` | sparse or inferred context | limitations and caveats |

## Rejected Schema Choices

Avoid a plain text-only schema with `prompt` and `completion` fields. It is harder to audit, harder to evaluate, and easier for provenance to be lost.

Avoid including raw CICIDS feature vectors in most examples. The LLM should reason over summarized SHAP evidence and graph context, not over 78 raw numeric flow columns.

