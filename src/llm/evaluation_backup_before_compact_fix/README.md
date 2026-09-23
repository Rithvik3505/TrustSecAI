# TrustSecAI LoRA v1 Evaluation

This package evaluates the trained TrustSecAI LoRA adapter on the held-out SFT test split. It does not train or modify the adapter.

## Inputs

- Primary test file: `artifacts/training/datasets/test_sft.jsonl`
- Optional compact test file: `artifacts/training/datasets/test_sft_compact.jsonl`
- LoRA adapter: `models/lora/trustsecai_lora_v1`
- Base model: `meta-llama/Llama-3.1-8B-Instruct`

Use `test_sft.jsonl` for the main evaluation because training used `max_seq_length: 8192` and the full test examples fit under that limit according to the token audit.

## Phase 1: LoRA Smoke Test On 3 Examples

Run the trained LoRA adapter only on three held-out examples:

```bash
python -m src.llm.evaluation.run_lora_inference --model-mode lora --limit 3 --max-new-tokens 700
```

Expected output:

- `artifacts/evaluation/lora_v1/lora_generations.jsonl`

## Phase 2: Base+LoRA Smoke Test On 3 Examples

Run both the base model and the LoRA adapter on the same three examples:

```bash
python -m src.llm.evaluation.run_lora_inference --model-mode both --limit 3 --max-new-tokens 700
```

Expected outputs:

- `artifacts/evaluation/lora_v1/base_generations.jsonl`
- `artifacts/evaluation/lora_v1/lora_generations.jsonl`

## Phase 3: Full LoRA Test Inference On All Held-Out Test Examples

Run LoRA inference over the full held-out test split:

```bash
python -m src.llm.evaluation.run_lora_inference --model-mode lora --max-new-tokens 900
```

Expected output:

- `artifacts/evaluation/lora_v1/lora_generations.jsonl`

## Phase 4: Full Base Model Inference Only If Time Allows

Base model inference is useful for comparison but may be slower and more expensive. Run it after LoRA inference if HPC time allows:

```bash
python -m src.llm.evaluation.run_lora_inference --model-mode base --max-new-tokens 900
```

Expected output:

- `artifacts/evaluation/lora_v1/base_generations.jsonl`

## Phase 5: Run evaluate_generations.py After Generation Files Exist

Run evaluation after one or both generation files exist:

```bash
python -m src.llm.evaluation.evaluate_generations
```

Expected outputs:

- `artifacts/evaluation/lora_v1/evaluation_metrics.json`
- `reports/evaluation/lora_v1_test_evaluation.md`

If both `base_generations.jsonl` and `lora_generations.jsonl` exist, the evaluator also writes base-vs-LoRA comparison metrics.

## Optional Compact Test Evaluation

The compact test set is useful for an ablation or faster check:

```bash
python -m src.llm.evaluation.run_lora_inference --test-file artifacts/training/datasets/test_sft_compact.jsonl --model-mode both --limit 3
```

## Safety Checks

`evaluate_generations.py` checks:

- non-empty output rate
- output length statistics
- obvious traceback/error text
- JSON parse rate when the target is JSON-like
- unsupported CVE, ATT&CK, CWE, and CAPEC IDs
- unsafe attribution phrases
- graph/GraphRAG proof wording

These are automatic guardrails, not a replacement for human SOC-quality review.

## Runtime Warning

Full inference may be slow or impractical on CPU. Run on the HPC/GPU environment with Hugging Face access to `meta-llama/Llama-3.1-8B-Instruct`.
