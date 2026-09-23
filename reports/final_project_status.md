# TrustSecAI Final Project Status

## 1. Project Title And Objective

**TrustSecAI: Context-Aware Security Incident Analysis using GraphRAG and Explainable AI**

TrustSecAI is a defensive cybersecurity research project that converts IDS alerts into contextual, explainable, and analyst-ready incident assessments. The project combines machine learning-based intrusion detection, SHAP explainability, a cybersecurity knowledge graph, deterministic graph retrieval, LoRA-adapted Llama 3.1 8B Instruct, classifier-vs-LLM agreement analysis, and bounded attack-chain prediction.

The objective is not only to detect attacks, but to help a SOC analyst understand:

- why the classifier produced the alert,
- which ATT&CK/CAPEC/CWE/CVE context is relevant,
- what the LLM secondary assessment says,
- whether classifier and LLM outputs agree,
- what defensive follow-up actions should be prioritized.

## 2. End-To-End Architecture

```text
Network Traffic / CICIDS2017
        ↓
CICIDS2017 Preprocessing
        ↓
Binary IDS Classifier / XGBoost
        ↓
SHAP Local Explainability
        ↓
Neo4j Security Knowledge Graph
ATT&CK + CAPEC + CWE + NVD/CVE + Products + IDS mappings
        ↓
Deterministic GraphRAG Retrieval / Context Builder
        ↓
Reviewed Gold SFT Corpus
        ↓
LoRA v1 Fine-Tuned Llama 3.1 8B Instruct
        ↓
Offline LLM Integration
        ↓
Classifier-vs-LLM Agreement Analysis
        ↓
Bounded Defensive Attack-Chain Prediction
        ↓
TrustSecAI Security Assessment Report / Multi-Case Demo
```

## 3. Completed Components

| Component | Status |
|---|---|
| CICIDS2017 preprocessing | Complete |
| XGBoost binary IDS classifier | Complete |
| SHAP explainability | Complete |
| Neo4j knowledge graph | Complete |
| Deterministic GraphRAG retrieval | Complete |
| Reviewed SFT corpus | Complete |
| LoRA v1 fine-tuning | Complete |
| Compact CUDA LoRA evaluation | Complete |
| Offline LLM integration | Complete |
| Agreement analysis | Complete |
| Attack-chain prediction | Complete |
| Multi-case demo | Complete |

## 4. Key Metrics

### XGBoost Random Split

Source: `artifacts/metrics/xgboost_metrics.json`

| Metric | Value |
|---|---:|
| Accuracy | 0.999170 |
| Precision | 0.995601 |
| Recall | 0.999499 |
| F1 score | 0.997546 |
| ROC-AUC | 0.999982 |
| Training time | 45.79 seconds |
| Features | 78 |

Interpretation: random split performance is extremely high, but this is not sufficient as a generalization claim because CICIDS rows from the same capture periods can leak distributional patterns across splits.

### XGBoost Day-Aware Split

Source: `artifacts/metrics/xgboost_day_split_metrics.json`

| Metric | Value |
|---|---:|
| Accuracy | 0.771359 |
| Precision | 0.999101 |
| Recall | 0.362623 |
| F1 score | 0.532115 |
| ROC-AUC | 0.788955 |
| Training time | 41.98 seconds |
| Features | 78 |

Interpretation: day-aware validation exposed a major distribution-shift/generalization gap. This became an important research finding and supports the project’s emphasis on explainability and contextual assessment rather than reporting only inflated random-split metrics.

### Knowledge Graph

Source: `reports/knowledge_graph_report.md`

| Item | Count |
|---|---:|
| Total nodes | 10,034 |
| Total relationships | 39,748 |

Validated IDS label mappings:

| IDS label | ATT&CK technique | Tactic | CAPEC | CWE | CVE |
|---|---|---|---:|---:|---:|
| PortScan | T1046 Network Service Discovery | Discovery | 1 | 1 | 37 |
| Web Attack - Sql Injection | T1190 Exploit Public-Facing Application | Initial Access | 0 | 0 | 0 |
| FTP-Patator | T1110 Brute Force | Credential Access | 1 | 2 | 3 |
| DDoS | T1498 Network Denial of Service | Impact | 0 | 0 | 0 |
| Bot | T1105 Ingress Tool Transfer | Command and Control | 0 | 0 | 0 |

### LoRA v1 Training

Source: `artifacts/training/logs/lora_training_metrics.json`

| Metric | Value |
|---|---:|
| Base model | `meta-llama/Llama-3.1-8B-Instruct` |
| LoRA mode | Adapter fine-tuning, not full fine-tuning |
| 4-bit loading | false |
| Epochs | 3 |
| Train runtime | 38,628.44 seconds, about 10.7 hours |
| Train loss | 0.173604 |
| Eval loss | 0.132792 |
| Eval mean token accuracy | 0.982005 |

Interpretation: training completed normally without CUDA OOM or traceback. Loss alone does not prove usefulness, so held-out compact inference/evaluation was performed.

### Compact CUDA LoRA Evaluation

Source: `artifacts/evaluation/lora_v1/evaluation_metrics.json`

| Metric | Value |
|---|---:|
| Held-out examples | 76 |
| Non-empty output rate | 1.0 |
| Error/traceback rate | 0.0 |
| Generated-token cap hit rate | 0.0 |
| JSON parse rate | 0.8289 |
| JSON parse OK | 63 / 76 |
| Metadata preservation coverage | 1.0 |
| Unsupported ID counts | `{"cwe": 4}` |
| Graph proof wording count | 0 |
| Mean generated tokens | 468.18 |
| Max generated tokens | 889 |

Interpretation: compact CUDA inference solved the earlier truncation problem. The remaining limitations are JSON parse failures for 13 examples, four unsupported CWE mentions, and overbroad unsafe-attribution phrase flags.

### Five Demo Cases

Source: `reports/demo_case_index.md`

| IDS label | example_id | task_type | Confidence | Demo report |
|---|---|---|---:|---|
| Web Attack - Sql Injection | `trustsecai-gold-v1-00575` | `mitigation_detection` | 0.983210 | `artifacts/demo/demo_trustsecai-gold-v1-00575.md` |
| PortScan | `trustsecai-gold-v1-00178` | `soc_incident_assessment` | 0.998606 | `artifacts/demo/demo_trustsecai-gold-v1-00178.md` |
| FTP-Patator | `trustsecai-gold-v1-00810` | `executive_summary` | 0.999981 | `artifacts/demo/demo_trustsecai-gold-v1-00810.md` |
| Bot | `trustsecai-gold-v1-00381` | `soc_incident_assessment` | 0.999968 | `artifacts/demo/demo_trustsecai-gold-v1-00381.md` |
| DDoS | `trustsecai-gold-v1-00128` | `mitigation_detection` | 0.999999 | `artifacts/demo/demo_trustsecai-gold-v1-00128.md` |

Attack-chain mode status:

- All five demo cases now demonstrate graph-backed Neo4j traversal when Neo4j is running.
- Static fallback remains implemented and keeps the demo usable without requiring a running Neo4j instance.

## 5. Main Artifact Paths

### Data And Model Artifacts

- Cleaned CICIDS dataset: `artifacts/processed/cleaned_cicids.parquet`
- XGBoost model: `models/xgboost/xgboost_model.joblib`
- XGBoost feature order: `models/xgboost/feature_order.json`
- XGBoost metadata: `models/xgboost/model_metadata.json`
- SHAP global importance: `artifacts/shap/global_feature_importance.csv`
- SHAP sample explanations: `artifacts/shap/sample_explanations.json`

### Graph And Retrieval

- Graph summary: `artifacts/graph/graph_summary.json`
- Knowledge graph report: `reports/knowledge_graph_report.md`
- Retrieval contexts: `artifacts/retrieval/`
- Retrieval API documentation: `docs/retrieval_api.md`

### Corpus And LoRA

- Strict reviewed corpus: `artifacts/gold_candidates/v1/reviewed/trustsecai_gold_v1_reviewed.jsonl`
- SFT train split: `artifacts/training/datasets/train_sft.jsonl`
- SFT validation split: `artifacts/training/datasets/validation_sft.jsonl`
- SFT test split: `artifacts/training/datasets/test_sft.jsonl`
- LoRA adapter: `models/lora/trustsecai_lora_v1/adapter_model.safetensors`
- LoRA config: `models/lora/trustsecai_lora_v1/adapter_config.json`
- Training metrics: `artifacts/training/logs/lora_training_metrics.json`

### Evaluation And Demo

- Compact LoRA generations: `artifacts/evaluation/lora_v1/lora_generations_compact.jsonl`
- Compact evaluation metrics: `artifacts/evaluation/lora_v1/evaluation_metrics.json`
- Compact inference log: `artifacts/evaluation/lora_v1/lora_compact_full_inference.log`
- Compact evaluation log: `artifacts/evaluation/lora_v1/evaluation_compact_full.log`
- Multi-case demo index: `reports/demo_case_index.md`
- Agreement report: `reports/agreement_analysis.md`
- Attack-chain report: `reports/attack_chain_agent.md`
- Final demo summary: `reports/final_demo_summary.md`

## 6. Limitations

- Random-split IDS metrics are inflated relative to day-aware evaluation.
- Day-aware XGBoost recall is low, showing distribution shift across capture days.
- The classifier is binary, so IDS subtype context is taken from real CICIDS labels in corpus/demo settings rather than predicted as multiclass probabilities.
- LoRA v1 compact outputs are not always valid JSON; parse rate is 0.8289.
- Four unsupported CWE mentions were detected in compact held-out evaluation.
- Unsafe-attribution phrase flags are overbroad and require human interpretation.
- Offline demo uses frozen compact LoRA outputs rather than live inference.
- Agreement analysis is deterministic and rule-based.
- Attack-chain prediction currently uses static ATT&CK seed mappings rather than Neo4j graph traversal.
- Graph-backed attack-chain traversal is implemented and validated for all five final demo cases when Neo4j is reachable.
- Graph-derived CVE relevance is candidate context unless asset exposure evidence exists.
- Graph context is contextual intelligence, not proof of compromise or attribution.

## 7. Future Work

- Improve day-aware IDS generalization using additional datasets, temporal validation, domain adaptation, or multiclass modeling.
- Add a production-safe live LoRA inference endpoint once GPU runtime is available.
- Improve LoRA output schema adherence with constrained decoding or structured output validation.
- Replace static attack-chain mappings with Neo4j traversal over ATT&CK, CAPEC, CWE, and CVE paths.
- Rank candidate next techniques using relationship confidence, provenance, graph distance, and alert history.
- Add temporal alert correlation for multi-stage incidents.
- Calibrate classifier-vs-LLM agreement scoring using analyst-reviewed incidents.
- Expand the human-reviewed gold corpus with more real evidence contexts.
- Add a lightweight UI or notebook for final presentation.

## 8. Suggested Demo Flow

1. Start with the architecture diagram and explain the goal: IDS alerts become explainable, contextual security assessments.
2. Show the XGBoost results, emphasizing both random-split performance and the day-aware generalization gap.
3. Show SHAP explanations to demonstrate why the classifier predicted attack.
4. Show the knowledge graph coverage and explain ATT&CK/CAPEC/CWE/CVE retrieval.
5. Open one demo Markdown report, preferably:
   - `artifacts/demo/demo_trustsecai-gold-v1-00575.md`
6. Walk through:
   - classifier prediction and confidence,
   - top SHAP features,
   - ATT&CK graph context,
   - LoRA secondary assessment,
   - agreement category,
   - bounded attack-chain hypothesis,
   - limitations and recommended actions.
7. Briefly show the multi-case index:
   - `reports/demo_case_index.md`
8. Close with research integrity:
   - random split inflated results,
   - compact LoRA inference works,
   - graph context is not proof,
   - analyst validation remains required.
