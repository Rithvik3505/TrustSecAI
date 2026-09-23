# TrustSecAI LoRA Dry-Run Report

- Created: 2026-07-14
- Output dir: `models/lora/trustsecai_lora_v1_dry_run`
- Base model: `meta-llama/Llama-3.1-8B-Instruct`
- 4-bit loading: `False`

```json
{
  "dry_run": true,
  "base_model": "meta-llama/Llama-3.1-8B-Instruct",
  "load_in_4bit": false,
  "train": {
    "train_runtime": 1401.6658,
    "train_samples_per_second": 0.029,
    "train_steps_per_second": 0.004,
    "total_flos": 9154682596835328.0,
    "train_loss": 0.8573984146118164,
    "epoch": 2.5
  },
  "eval": {
    "eval_loss": 0.7521198987960815,
    "eval_runtime": 86.5107,
    "eval_samples_per_second": 0.092,
    "eval_steps_per_second": 0.092,
    "eval_entropy": 0.7817412465810776,
    "eval_num_tokens": 202174.0,
    "eval_mean_token_accuracy": 0.8527142181992531,
    "epoch": 2.5
  }
}
```
