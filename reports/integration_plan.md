# TrustSecAI Integration Plan

## Current Status

LoRA v1 is frozen after successful HPC training and compact CUDA evaluation. The best current secondary-assessment artifact is:

`artifacts/evaluation/lora_v1/lora_generations_compact.jsonl`

This integration phase does not retrain, does not run inference, and does not modify the LoRA adapter, checkpoints, datasets, or evaluation artifacts.

## Implemented In Phase 1

- `src/llm/integration/lora_client.py`
  - Offline-first wrapper for frozen LoRA generations.
  - Retrieves a LoRA output by `example_id` or one-based `row_number`.
  - Includes a command-mode placeholder documenting the HPC inference command without executing it.

- `src/llm/integration/prompt_builder.py`
  - Builds compact TrustSecAI prompts for future live inference.
  - Reinforces evidence-only behavior, no invented IDs, no attribution, and secondary-assessment framing.
  - Extracts supplied TrustSecAI context from the stored SFT prompt.

- `src/llm/integration/response_parser.py`
  - Parses compact JSON LoRA outputs.
  - Falls back to normalized text output when JSON parsing fails.

- `src/analysis/agreement.py`
  - Provides classifier-vs-LLM agreement categories and rationale strings.

- `src/analysis/attack_chain.py`
  - Provides bounded defensive attack-chain hypotheses using static ATT&CK seed mappings.
  - Avoids offensive procedural guidance.

- `src/reporting/security_report_builder.py`
  - Builds final Markdown security assessment reports from classifier evidence, SHAP evidence, graph context, LoRA output, agreement results, and attack-chain predictions.

- `src/pipeline/trustsecai_demo.py`
  - Offline demo runner that composes frozen LoRA output into JSON and Markdown reports.

## Offline vs Live

Offline mode is the default and should be used for the current project deadline. It consumes existing compact LoRA generations and is safe to run locally.

Live command mode is intentionally not executed from the integration client. If fresh LoRA output is required, run the documented HPC command manually:

```bash
python -m src.llm.evaluation.run_lora_inference --model-mode lora --max-new-tokens 1200 --compact-output-instruction --output-suffix compact --device-placement cuda
```

## Remaining Work

1. Add live end-to-end inference once the demo is stable.
2. Replace static attack-chain seeds with graph traversal from Neo4j.
3. Calibrate agreement thresholds with additional reviewed examples.
4. Add a final report-generation CLI that starts from a new IDS event rather than frozen test examples.
5. Add a short demo notebook or script for presentation.

## Known Limitations

- Agreement analysis is deterministic scaffolding and should be treated as a research prototype.
- Attack-chain prediction is bounded and defensive but currently static.
- LoRA output JSON parsing was 82.89% on compact held-out evaluation, so fallback parsing remains necessary.
- Unsafe-attribution automatic flags are overbroad and should be documented rather than treated as definitive failures.
