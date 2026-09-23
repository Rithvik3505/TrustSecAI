# TrustSecAI Agreement Analysis

## Purpose

Agreement analysis compares the primary IDS classifier output with the LoRA-based secondary assessment. Its purpose is to help SOC analysts understand whether the model pipeline is internally aligned, where uncertainty exists, and when analyst review should be prioritized.

The classifier remains the primary detector. The LoRA/LLM output is a secondary contextual assessment, not ground truth. Agreement analysis should therefore be interpreted as an evidence-consistency signal, not as an automated final verdict.

## Inputs

The current implementation uses:

- Classifier prediction, such as `ATTACK`
- Classifier confidence
- CICIDS/IDS label, such as `PortScan` or `DDoS`
- SHAP evidence availability
- Parsed LoRA/LLM output
- Evidence flags, such as whether CVE evidence is available for vulnerability-context tasks

The agreement layer does not invent evidence and does not override the classifier. It summarizes consistency between existing evidence streams.

## Agreement Categories

| Category | Meaning |
|---|---|
| `agree_attack_high_confidence` | The classifier predicts attack with high confidence, and the LLM output is attack-relevant without clearly claiming benign/false-positive/uncertain status. |
| `agree_attack_low_confidence` | The classifier predicts attack and the LLM output is attack-relevant, but classifier confidence is below the high-confidence threshold. |
| `llm_uncertain_classifier_attack` | The classifier predicts attack, but the LLM emphasizes uncertainty, insufficient corroboration, or missing evidence. |
| `classifier_attack_llm_benign_or_uncertain` | The classifier predicts attack, but the LLM output appears benign-leaning, false-positive oriented, or strongly contradictory. |
| `evidence_gap` | Required supporting evidence is missing or sparse, so analyst review should be prioritized. |

## Current Demo Behavior

The five-case offline demo set uses frozen compact LoRA outputs from `artifacts/evaluation/lora_v1/lora_generations_compact.jsonl`.

| IDS label | example_id | Classifier confidence | Agreement result |
|---|---|---:|---|
| Web Attack - Sql Injection | `trustsecai-gold-v1-00575` | 0.983210 | `agree_attack_high_confidence` |
| PortScan | `trustsecai-gold-v1-00178` | 0.998606 | `agree_attack_high_confidence` |
| FTP-Patator | `trustsecai-gold-v1-00810` | 0.999981 | `agree_attack_high_confidence` |
| Bot | `trustsecai-gold-v1-00381` | 0.999968 | `agree_attack_high_confidence` |
| DDoS | `trustsecai-gold-v1-00128` | 0.999999 | `agree_attack_high_confidence` |

These results are expected for the demo set because each selected example has a high-confidence binary XGBoost `ATTACK` prediction and a LoRA assessment that remains attack-relevant while preserving caveats such as "not proof of compromise" and "not attribution."

## Interpretation

Agreement does not mean the incident is confirmed. It means the classifier signal, SHAP evidence, graph context, and secondary LLM assessment are directionally consistent. SOC analysts should still validate the alert with packet capture, endpoint logs, service logs, asset exposure data, and incident timelines.

## Limitations

- The current logic is deterministic and rule-based.
- It depends on parsed LoRA text, so malformed or partially structured outputs can reduce reliability.
- It is not a replacement for analyst validation.
- It does not perform independent ground-truth verification.
- LoRA v1 compact evaluation had a JSON parse rate of 0.8289, so fallback parsing remains necessary.
- The agreement layer intentionally treats graph context as contextual intelligence rather than proof of compromise or attribution.

