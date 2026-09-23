# TrustSecAI Final Demo Summary

## Completed Milestones

TrustSecAI has progressed from IDS preprocessing through LoRA-backed secondary assessment and offline demo integration.

Completed components include:

- CICIDS2017 preprocessing
- Binary XGBoost IDS classifier
- SHAP explainability
- Neo4j cybersecurity knowledge graph using ATT&CK, CAPEC, CWE, NVD/CVE, CPE/product context, and IDS label mappings
- Deterministic graph retrieval and context construction
- Reviewed gold SFT corpus
- LoRA fine-tuning of Llama 3.1 8B Instruct
- Compact CUDA held-out LoRA inference/evaluation
- Offline integration layer
- Multi-case demo generation
- Classifier-vs-LLM agreement analysis
- Bounded defensive attack-chain prediction with graph-backed Neo4j traversal and static fallback

## LoRA v1 Status

LoRA v1 training completed successfully on the HPC/DGX Spark environment. The final compact CUDA evaluation is the best current evaluation artifact.

Key compact evaluation results:

- Total held-out examples: 76
- Non-empty output rate: 1.0
- Generated-token cap hit rate: 0.0
- Metadata preservation coverage: 1.0
- Error/traceback rate: 0.0
- JSON parse rate: 0.8289
- Unsupported ID counts: `{"cwe": 4}`
- Graph proof wording count: 0

LoRA v1 is frozen for the current project timeline. No retraining is planned before the final demo.

## Offline Integration

The offline integration pipeline consumes frozen compact LoRA outputs from:

`artifacts/evaluation/lora_v1/lora_generations_compact.jsonl`

It then composes:

- Classifier evidence
- SHAP evidence
- Graph context summary
- Parsed LoRA secondary assessment
- Classifier-vs-LLM agreement result
- Bounded attack-chain prediction
- Final Markdown security report

The offline design avoids costly inference during demos while preserving realistic TrustSecAI output.

## Multi-Case Demo

The final demo set covers five IDS labels:

| IDS label | example_id | Demo report |
|---|---|---|
| Web Attack - Sql Injection | `trustsecai-gold-v1-00575` | `artifacts/demo/demo_trustsecai-gold-v1-00575.md` |
| PortScan | `trustsecai-gold-v1-00178` | `artifacts/demo/demo_trustsecai-gold-v1-00178.md` |
| FTP-Patator | `trustsecai-gold-v1-00810` | `artifacts/demo/demo_trustsecai-gold-v1-00810.md` |
| Bot | `trustsecai-gold-v1-00381` | `artifacts/demo/demo_trustsecai-gold-v1-00381.md` |
| DDoS | `trustsecai-gold-v1-00128` | `artifacts/demo/demo_trustsecai-gold-v1-00128.md` |

The case index is available at:

`reports/demo_case_index.md`

All five demo cases now use graph-backed Neo4j traversal for attack-chain prediction when Neo4j is running. Static fallback remains available and keeps the UI/demo runnable without a database.

## Remaining Limitations

- LoRA v1 still has some JSON parse failures on held-out compact evaluation.
- Four unsupported CWE mentions were detected by automatic evaluation.
- Unsafe attribution phrase detection is overbroad and should be interpreted manually.
- Agreement analysis is deterministic and rule-based.
- Attack-chain prediction supports graph-backed Neo4j traversal, with static ATT&CK seed fallback when Neo4j is unavailable.
- The current demo uses frozen LoRA outputs rather than live inference.

## Future Work

- Integrate live LoRA inference into the demo pipeline when runtime allows.
- Replace static attack-chain mappings with Neo4j traversal.
- Rank graph-derived candidate next techniques using relationship confidence and provenance.
- Add temporal alert correlation.
- Calibrate agreement scoring against analyst-reviewed incidents.
- Expand human-reviewed SFT data if additional real evidence contexts become available.
