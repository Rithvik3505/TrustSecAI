# TrustSecAI LoRA Training Setup

This directory contains the reproducible setup for the first clean LoRA experiment using the strict reviewed Gold v1 corpus only.

Do not use the old 30k synthetic corpus for this run.

## Data

- Train: `artifacts/gold_candidates/v1/reviewed/train_reviewed.jsonl`
- Validation: `artifacts/gold_candidates/v1/reviewed/validation_reviewed.jsonl`
- Test: `artifacts/gold_candidates/v1/reviewed/test_reviewed.jsonl`

Prepared SFT files are written to:

- `artifacts/training/datasets/train_sft.jsonl`
- `artifacts/training/datasets/validation_sft.jsonl`
- `artifacts/training/datasets/test_sft.jsonl`
- `artifacts/training/datasets/train_sft_tiny.jsonl`
- `artifacts/training/datasets/validation_sft_tiny.jsonl`

## Fresh HPC Setup

Check the HPC CUDA version first:

```bash
nvidia-smi
```

Install the PyTorch build that matches the HPC CUDA version from the official PyTorch selector. Do not assume a CUDA wheel until the HPC environment is known.

### Option A: Conda

```bash
conda create -n trustsecai-lora python=3.11 -y
conda activate trustsecai-lora
python -m pip install --upgrade pip

# Install torch/torchvision/torchaudio using the command recommended for the HPC CUDA version.
# Then install the training stack:
python -m pip install transformers datasets accelerate peft trl bitsandbytes sentencepiece protobuf pandas scikit-learn pyyaml tqdm
```

### Option B: pip virtual environment

```bash
python -m venv .venv-trustsecai-lora
source .venv-trustsecai-lora/bin/activate
python -m pip install --upgrade pip

# Install torch/torchvision/torchaudio using the command recommended for the HPC CUDA version.
# Then install the training stack:
python -m pip install transformers datasets accelerate peft trl bitsandbytes sentencepiece protobuf pandas scikit-learn pyyaml tqdm
```

Flash Attention is optional. Missing `flash-attn` should not block training.

## Hugging Face Access

Llama 3.1 requires Hugging Face access approval and login:

```bash
huggingface-cli login
```

Do not store tokens in source files or print them in logs. Environment variables such as `HF_TOKEN` are acceptable if managed securely by the HPC.

## Commands

1. Check environment:

```bash
python -m src.llm.training.check_environment
```

2. Prepare dataset:

```bash
python -m src.llm.training.prepare_sft_dataset
```

3. Run dry-run:

```bash
python -m src.llm.training.train_lora --dry-run
```

4. Audit token lengths before training:

```bash
python -m src.llm.training.audit_token_lengths
```

5. Optional compact dataset generation if the audit shows heavy truncation:

```bash
python -m src.llm.training.prepare_sft_dataset --compact-context
```

6. Run full LoRA training:

```bash
python -m src.llm.training.train_lora --config src/llm/training/training_config.yaml
```

7. Optional no-4bit run:

```bash
python -m src.llm.training.train_lora --no-4bit
```

## Outputs

- Full adapter: `models/lora/trustsecai_lora_v1/`
- Dry-run adapter: `models/lora/trustsecai_lora_v1_dry_run/`
- Logs: `artifacts/training/logs/`
- Reports: `reports/training/`

## OOM Guidance

If out-of-memory occurs:

- keep `load_in_4bit=true`
- reduce `max_seq_length`
- reduce per-device batch size
- increase gradient accumulation
- use a smaller base model for a smoke test
