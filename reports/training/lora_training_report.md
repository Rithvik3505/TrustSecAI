# TrustSecAI LoRA Training Report

- Created: 2026-07-15
- Output dir: `models/lora/trustsecai_lora_v1`
- Base model: `meta-llama/Llama-3.1-8B-Instruct`
- 4-bit loading: `False`

```json
{
  "dry_run": false,
  "base_model": "meta-llama/Llama-3.1-8B-Instruct",
  "load_in_4bit": false,
  "train": {
    "train_runtime": 38628.4373,
    "train_samples_per_second": 0.026,
    "train_steps_per_second": 0.003,
    "total_flos": 2.2233063223310746e+17,
    "train_loss": 0.17360446908215219,
    "epoch": 3.0
  },
  "eval": {
    "eval_loss": 0.1327916830778122,
    "eval_runtime": 840.7551,
    "eval_samples_per_second": 0.093,
    "eval_steps_per_second": 0.093,
    "eval_entropy": 0.0654584993250095,
    "eval_num_tokens": 4909998.0,
    "eval_mean_token_accuracy": 0.9820054158186301,
    "epoch": 3.0
  }
}
```
