# TrustSecAI: Context-Aware Security Incident Analysis using GraphRAG and Explainable AI

**Internship Project Report**  
**Project Repository:** `C:\Users\LENOVO\WORK\Projects\TrustSecAI\TrustSecAI`

## Abstract

Security Operations Center (SOC) analysts often receive large volumes of intrusion detection alerts that identify suspicious traffic but provide limited context for triage, explanation, and response. TrustSecAI addresses this problem by combining machine learning-based intrusion detection, explainable AI, graph-based threat intelligence retrieval, and a LoRA-adapted large language model to generate contextual security incident assessments. The system uses CICIDS2017 for IDS preprocessing and binary attack detection, XGBoost as the primary classifier, SHAP for local model explanations, Neo4j for a cybersecurity knowledge graph built from MITRE ATT&CK, CAPEC, CWE, NVD/CVE, and CPE/product context, and deterministic GraphRAG retrieval to supply grounded context to a fine-tuned Llama 3.1 8B Instruct model. The LLM output is treated as a secondary assessment rather than ground truth. The final system also includes classifier-vs-LLM agreement analysis, graph-backed defensive attack-chain prediction with static fallback, and an offline Streamlit demo UI. XGBoost achieved strong random-split performance with F1 0.997546 and ROC-AUC 0.999982; however, day-aware validation dropped to F1 0.532115 and ROC-AUC 0.788955, exposing distribution shift. LoRA v1 training completed successfully with train loss 0.173604, eval loss 0.132792, and eval mean token accuracy 0.982005. Compact held-out LoRA evaluation produced a non-empty output rate of 1.0, error rate of 0.0, metadata coverage of 1.0, and JSON parse rate of 0.8289. These results show that TrustSecAI can transform IDS alerts into explainable and graph-grounded SOC reports while preserving important uncertainty and evidence limitations.

**Keywords** - Intrusion Detection, Explainable AI, SHAP, GraphRAG, Neo4j, MITRE ATT&CK, CAPEC, CWE, NVD, LoRA, Llama 3.1, SOC Automation, Cybersecurity Knowledge Graph

## I. Introduction

Modern network intrusion detection systems produce high-volume alerts that require rapid interpretation by SOC analysts. Traditional IDS alerts may indicate whether traffic is benign or malicious, but they often lack the contextual intelligence needed to explain why an alert was produced, how it maps to adversary behavior, what vulnerabilities may be relevant, and what defensive response should be prioritized.

TrustSecAI was developed as a defensive cybersecurity research framework to bridge this gap. The project integrates an XGBoost-based IDS classifier, SHAP explainability, a Neo4j threat intelligence graph, deterministic GraphRAG retrieval, and a LoRA-adapted Llama 3.1 8B Instruct model. The classifier remains the primary detector, while the LLM acts as a secondary analyst that summarizes supplied evidence. The system explicitly avoids treating graph context as proof of compromise or attribution.

The final TrustSecAI demo produces analyst-readable incident reports containing classifier evidence, SHAP feature explanations, ATT&CK/CAPEC/CWE/CVE graph context, LoRA secondary assessment, agreement category, defensive attack-chain hypothesis, recommended actions, and limitations.

## II. Literature Survey and Research Gap

Intrusion detection research has traditionally focused on improving classification performance using datasets such as CICIDS2017. Tree-based ensemble methods such as Random Forest and XGBoost are widely used because they handle tabular network-flow features effectively. However, high random-split accuracy can overstate real-world generalization when traffic from the same capture days appears across train and test partitions.

Explainable AI methods such as SHAP improve analyst trust by identifying which features contributed to a classifier prediction. Security knowledge bases such as MITRE ATT&CK, CAPEC, CWE, NVD/CVE, and CPE provide structured cyber threat and vulnerability intelligence, but they are often separate from IDS pipelines. Retrieval-augmented generation and GraphRAG approaches help connect structured knowledge to language models, but generated text must be grounded and constrained to avoid hallucinated CVEs, unsupported attribution, or overclaiming.

The research gap addressed by TrustSecAI is the integration of IDS detection, XAI explanations, graph-based cyber threat context, domain-adapted LLM assessment, classifier-vs-LLM agreement analysis, and defensive attack-chain prediction into a single reproducible SOC-assistance pipeline.

## III. Problem Statement

Given a network traffic alert, TrustSecAI aims to generate a contextual and explainable security assessment that answers:

- What did the IDS classifier predict?
- Which flow features influenced the prediction?
- Which ATT&CK technique and tactic are relevant?
- Are CAPEC, CWE, CVE, or product contexts available?
- What does the LoRA-adapted LLM conclude from the supplied evidence?
- Does the LLM assessment align with the classifier?
- What bounded defensive investigation pivots should be considered next?
- What limitations should the analyst preserve?

The system must avoid unsupported claims. LLM output is not ground truth. Graph context is contextual intelligence, not proof of compromise or attribution. Attack-chain output is defensive investigation prioritization, not offensive guidance.

## IV. Dataset and Preprocessing

The primary IDS dataset is CICIDS2017. The preprocessing pipeline loads and concatenates all CICIDS2017 CSV files, normalizes column names, resolves duplicate columns such as `Fwd Header Length`, normalizes labels, converts features to numeric values, replaces infinite values with nulls, removes invalid rows, preserves multiclass labels, and creates a binary target label where `BENIGN` is mapped to 0 and all attacks are mapped to 1.

The cybersecurity knowledge graph uses MITRE ATT&CK for tactics, techniques, mitigations, groups, malware, tools, campaigns, and detection guidance; CAPEC for attack patterns and attack relationships; CWE for weakness bridging; NVD/CVE for vulnerability intelligence; and CPE/product context for affected product relationships. IDS label mappings connect CICIDS labels to ATT&CK techniques.

## V. Proposed Methodology

TrustSecAI follows a layered methodology:

1. Train a binary IDS classifier on cleaned CICIDS2017 features.
2. Generate local SHAP explanations for classifier decisions.
3. Map the IDS label to ATT&CK technique context.
4. Retrieve deterministic graph context from Neo4j.
5. Package classifier, SHAP, and graph evidence into structured prompts.
6. Use a LoRA-adapted Llama 3.1 8B Instruct model for secondary assessment.
7. Parse the LLM output into normalized report fields.
8. Compare classifier and LLM outputs using deterministic agreement analysis.
9. Generate graph-backed defensive attack-chain hypotheses with static fallback.
10. Produce final JSON and Markdown reports, and display them in an offline Streamlit UI.

## VI. System Architecture

```text
Network Traffic / CICIDS2017
        ↓
CICIDS2017 Preprocessing
        ↓
XGBoost Binary IDS Classifier
        ↓
SHAP Explainability
        ↓
Neo4j Cybersecurity Knowledge Graph
ATT&CK + CAPEC + CWE + NVD/CVE + CPE/Product + IDS Mappings
        ↓
Deterministic GraphRAG Retrieval
        ↓
LoRA v1 Fine-Tuned Llama 3.1 8B Instruct
        ↓
Offline LLM Integration
        ↓
Classifier-vs-LLM Agreement Analysis
        ↓
Graph-Backed Defensive Attack-Chain Prediction
        ↓
TrustSecAI Security Assessment Report and Streamlit Demo
```

The architecture preserves separation of responsibilities. The classifier detects, SHAP explains, Neo4j retrieves, the LLM summarizes supplied context, agreement analysis checks consistency, and the attack-chain component proposes bounded defensive pivots.

## VII. Implementation

### A. IDS Classifier

XGBoost was selected as the primary IDS classifier after baseline comparison. The classifier uses 78 numeric CICIDS2017 features and excludes `label`, `binary_label`, and `source_file`. Class imbalance is handled with `scale_pos_weight`, and the model uses histogram-based tree construction for efficiency.

### B. Explainability

SHAP local explanations are generated for selected real classifier samples. These explanations preserve feature names, feature values, SHAP values, and contribution direction. SHAP evidence is included in both the LoRA corpus and final demo reports.

### C. Knowledge Graph and GraphRAG Retrieval

The Neo4j graph contains ATT&CK, CAPEC, CWE, NVD/CVE, product/reference, and IDS label mapping layers. ATT&CK acts as the behavioral spine. CAPEC and NVD are connected through CWE bridge nodes, and inferred edges are explicitly marked. Deterministic retrieval produces structured context without vector search.

### D. Gold Reviewed SFT Corpus

A reviewed gold SFT corpus was created from real evidence contexts instead of relying on large paraphrased synthetic corpora. The reviewed strict corpus contains examples grounded in classifier output, real SHAP evidence, graph retrieval context, provenance, and reviewer approval metadata.

### E. LoRA Fine-Tuning

The base model is `meta-llama/Llama-3.1-8B-Instruct`. LoRA adapter fine-tuning was used instead of full model fine-tuning. Training was performed for 3 epochs on the HPC environment without 4-bit loading because bitsandbytes was not used.

### F. Integration and Demo

The integration layer supports offline mode by reading frozen compact LoRA outputs from `artifacts/evaluation/lora_v1/lora_generations_compact.jsonl`. The final demo composes existing LoRA outputs with classifier evidence, SHAP evidence, graph context, agreement analysis, and attack-chain prediction. A Streamlit UI provides a reviewer-friendly offline dashboard.

## VIII. Results and Evaluation

### A. XGBoost Evaluation

| Evaluation strategy | Accuracy | Precision | Recall | F1 score | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| Random split | 0.999170 | 0.995601 | 0.999499 | 0.997546 | 0.999982 |
| Day-aware split | 0.771359 | 0.999101 | 0.362623 | 0.532115 | 0.788955 |

The random split shows very high classification performance. The day-aware split reveals a major generalization gap, especially in recall. This indicates distribution shift across capture days and supports the need for explainability, careful validation, and contextual analyst review.

### B. Knowledge Graph Metrics

| Graph metric | Value |
|---|---:|
| Total nodes | 10,034 |
| Total relationships | 39,748 |

Validated IDS labels include SQL Injection, PortScan, FTP-Patator, Bot, and DDoS. The graph resolves each to a seed ATT&CK technique and associated tactic.

### C. LoRA Training Metrics

| Metric | Value |
|---|---:|
| Base model | meta-llama/Llama-3.1-8B-Instruct |
| Epochs | 3 |
| Train runtime | about 10.7 hours |
| Train loss | 0.173604 |
| Eval loss | 0.132792 |
| Eval mean token accuracy | 0.982005 |

Training completed successfully without observed CUDA OOM or traceback.

### D. Compact LoRA Evaluation

| Metric | Value |
|---|---:|
| Held-out examples | 76 |
| Non-empty output rate | 1.0 |
| Error/traceback rate | 0.0 |
| Generated-token cap hit rate | 0.0 |
| JSON parse rate | 0.8289 |
| Metadata preservation coverage | 1.0 |
| Unsupported ID counts | `{"cwe": 4}` |
| Graph proof wording count | 0 |

The compact prompt strategy solved the earlier truncation issue caused by long provenance arrays. Remaining limitations include non-parseable JSON in 13 examples and four unsupported CWE mentions.

## IX. Demo and Case Studies

The final offline demo covers five IDS labels. Each case reads a frozen LoRA output and generates JSON and Markdown reports. With Neo4j running, all five demo cases use graph-backed attack-chain traversal.

| IDS label | Example ID | Task type | Confidence | Attack-chain mode |
|---|---|---|---:|---|
| Web Attack - Sql Injection | `trustsecai-gold-v1-00575` | mitigation_detection | 0.983210 | graph |
| PortScan | `trustsecai-gold-v1-00178` | soc_incident_assessment | 0.998606 | graph |
| FTP-Patator | `trustsecai-gold-v1-00810` | executive_summary | 0.999981 | graph |
| Bot | `trustsecai-gold-v1-00381` | soc_incident_assessment | 0.999968 | graph |
| DDoS | `trustsecai-gold-v1-00128` | mitigation_detection | 0.999999 | graph |

The recommended first demo report is `artifacts/demo/demo_trustsecai-gold-v1-00575.md`. The offline Streamlit UI can be launched using:

```bash
streamlit run src/ui/streamlit_demo.py
```

## X. Limitations

TrustSecAI is a research prototype and has several limitations:

- Random-split IDS metrics are inflated relative to day-aware validation.
- The IDS classifier is binary, while IDS subtype context is taken from real CICIDS labels in the reviewed corpus and demo.
- LoRA v1 compact outputs are not always valid JSON.
- Four unsupported CWE mentions were detected during compact evaluation.
- Unsafe attribution detection is currently overbroad and requires human interpretation.
- Offline demo mode reads frozen LoRA outputs rather than performing live inference.
- Graph-backed attack-chain prediction produces defensive candidate pivots, not confirmed attack paths.
- CVE/CWE/CAPEC enrichment is candidate context unless asset exposure evidence is explicitly present.
- Graph context is not proof of compromise or attribution.

## XI. Conclusion and Future Work

TrustSecAI demonstrates an end-to-end defensive SOC-assistance pipeline that integrates IDS classification, SHAP explainability, graph-based threat intelligence, LoRA-based secondary assessment, agreement analysis, and graph-backed defensive attack-chain prediction. The system produces explainable reports while preserving uncertainty and avoiding unsupported attribution.

Future work includes improving day-aware IDS generalization, adding live GPU-backed LoRA inference, enforcing structured LLM output with constrained decoding, expanding the reviewed SFT corpus, adding temporal alert correlation, improving graph-based candidate ranking, calibrating agreement scores with analyst feedback, and extending the Streamlit UI for interactive investigation.

## References

[1] I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization," ICISSP, 2018.  
[2] T. Chen and C. Guestrin, "XGBoost: A Scalable Tree Boosting System," KDD, 2016.  
[3] S. M. Lundberg and S.-I. Lee, "A Unified Approach to Interpreting Model Predictions," NeurIPS, 2017.  
[4] MITRE, "MITRE ATT&CK Enterprise Matrix."  
[5] MITRE, "Common Attack Pattern Enumeration and Classification (CAPEC)."  
[6] MITRE, "Common Weakness Enumeration (CWE)."  
[7] National Institute of Standards and Technology, "National Vulnerability Database (NVD)."  
[8] NIST, "Common Platform Enumeration (CPE)."  
[9] Neo4j, "Neo4j Graph Database."  
[10] P. Lewis et al., "Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks," NeurIPS, 2020.  
[11] E. Hu et al., "LoRA: Low-Rank Adaptation of Large Language Models," ICLR, 2022.  
[12] Hugging Face, "PEFT: Parameter-Efficient Fine-Tuning."  
[13] Meta AI, "Llama 3.1 Model Family."  
[14] TrustSecAI Project Artifacts, `reports/`, `artifacts/`, and `src/` directories, 2026.
