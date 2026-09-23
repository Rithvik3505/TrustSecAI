# TrustSecAI LoRA Setup Report

Created: 2026-07-13

## Files Created

- `src/llm/training/__init__.py`
- `src/llm/training/check_environment.py`
- `src/llm/training/prepare_sft_dataset.py`
- `src/llm/training/train_lora.py`
- `src/llm/training/training_config.yaml`
- `src/llm/training/README.md`

## Dataset Paths

- Train: `artifacts/gold_candidates/v1/reviewed/train_reviewed.jsonl`
- Validation: `artifacts/gold_candidates/v1/reviewed/validation_reviewed.jsonl`
- Test: `artifacts/gold_candidates/v1/reviewed/test_reviewed.jsonl`

Prepared SFT outputs:

- `artifacts/training/datasets/train_sft.jsonl`
- `artifacts/training/datasets/validation_sft.jsonl`
- `artifacts/training/datasets/test_sft.jsonl`
- `artifacts/training/datasets/train_sft_tiny.jsonl`
- `artifacts/training/datasets/validation_sft_tiny.jsonl`
- `artifacts/training/datasets/train_sft_compact.jsonl`
- `artifacts/training/datasets/validation_sft_compact.jsonl`
- `artifacts/training/datasets/test_sft_compact.jsonl`

## Base Model

- `meta-llama/Llama-3.1-8B-Instruct`

## LoRA Configuration

- r: 16
- alpha: 32
- dropout: 0.05
- target modules: `q_proj`, `k_proj`, `v_proj`, `o_proj`, `gate_proj`, `up_proj`, `down_proj`
- 4-bit loading enabled by default

## Expected Output Paths

- Full run: `models/lora/trustsecai_lora_v1/`
- Dry-run: `models/lora/trustsecai_lora_v1_dry_run/`
- Metrics: `artifacts/training/logs/lora_training_metrics.json`

## Commands

Dry-run:

```bash
python -m src.llm.training.train_lora --dry-run
```

Full training:

```bash
python -m src.llm.training.train_lora --config src/llm/training/training_config.yaml
```

Token-length audit:

```bash
python -m src.llm.training.audit_token_lengths
```

Compact dataset generation:

```bash
python -m src.llm.training.prepare_sft_dataset --compact-context
```

## Known Risks

- Llama 3.1 model access requires Hugging Face authorization.
- CUDA GPU is required for practical training.
- `bitsandbytes` may need an HPC-compatible CUDA/PyTorch stack.
- If VRAM is limited, reduce `max_seq_length` or use a smaller model for smoke testing.

## HPC Notes

Run `python -m src.llm.training.check_environment` on the HPC before training. Install PyTorch using the build matching the HPC CUDA version reported by `nvidia-smi`.

No LoRA training, model download, or inference was run automatically during this setup task.

## Token-Length Audit Note

`src/llm/training/audit_token_lengths.py` has been added. On the local Windows environment, the audit did not run to completion because `transformers` is not installed. On HPC, install the training dependencies and authenticate to Hugging Face before running the audit.
