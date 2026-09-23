# TrustSecAI Demo README

## Canonical Project Root

Use this folder as the canonical TrustSecAI project root:

```text
C:\Users\LENOVO\WORK\Projects\TrustSecAI\TrustSecAI
```

## Project Summary

TrustSecAI is a defensive cybersecurity research pipeline that turns IDS alerts into explainable, graph-contextualized, LoRA-assisted SOC incident assessments.

## Reports To Open First

Start with these reports:

1. `reports/final_project_status.md`
2. `reports/final_demo_summary.md`
3. `reports/demo_case_index.md`
4. `reports/agreement_analysis.md`
5. `reports/attack_chain_agent.md`

## Recommended Demo Report

Open this demo report first:

```text
artifacts/demo/demo_trustsecai-gold-v1-00575.md
```

This case demonstrates a Web Attack - Sql Injection alert with classifier confidence, SHAP evidence, ATT&CK context, LoRA secondary assessment, agreement analysis, attack-chain hypothesis, and limitations.

## Offline Demo Command

From the canonical project root, run:

```bash
python -m src.pipeline.trustsecai_demo --example-id trustsecai-gold-v1-00575 --offline-lora
```

This writes:

```text
artifacts/demo/demo_trustsecai-gold-v1-00575.json
artifacts/demo/demo_trustsecai-gold-v1-00575.md
```

## Offline Mode

The demo uses frozen compact LoRA outputs from:

```text
artifacts/evaluation/lora_v1/lora_generations_compact.jsonl
```

No GPU is required for offline demo mode. The command does not run LoRA inference; it only reads an existing generation and builds the final TrustSecAI report.

## Important Safety Note

Do not rerun training or LoRA inference unless explicitly required. The final demo is designed around frozen LoRA v1 outputs and already-generated compact CUDA evaluation artifacts.

## Five Demo Cases

| IDS label | example_id | Demo Markdown |
|---|---|---|
| Web Attack - Sql Injection | `trustsecai-gold-v1-00575` | `artifacts/demo/demo_trustsecai-gold-v1-00575.md` |
| PortScan | `trustsecai-gold-v1-00178` | `artifacts/demo/demo_trustsecai-gold-v1-00178.md` |
| FTP-Patator | `trustsecai-gold-v1-00810` | `artifacts/demo/demo_trustsecai-gold-v1-00810.md` |
| Bot | `trustsecai-gold-v1-00381` | `artifacts/demo/demo_trustsecai-gold-v1-00381.md` |
| DDoS | `trustsecai-gold-v1-00128` | `artifacts/demo/demo_trustsecai-gold-v1-00128.md` |

## Suggested Speaking Flow

1. Start with the classifier prediction and confidence.
2. Explain the top SHAP features that influenced the classifier.
3. Show the graph context, especially ATT&CK technique, tactic, and mitigations.
4. Present the LoRA secondary assessment as analyst-supporting context, not ground truth.
5. Highlight the classifier-vs-LLM agreement category.
6. Walk through the bounded attack-chain hypothesis.
7. Close with limitations: graph context is not proof of compromise, group/tool/malware context is not attribution, and analyst validation remains required.

