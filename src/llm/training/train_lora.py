"""LoRA fine-tuning entrypoint for TrustSecAI reviewed SFT data."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import date
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CONFIG = ROOT / "src" / "llm" / "training" / "training_config.yaml"
METRICS_PATH = ROOT / "artifacts" / "training" / "logs" / "lora_training_metrics.json"
REPORT_PATH = ROOT / "reports" / "training" / "lora_training_report.md"
DRY_REPORT_PATH = ROOT / "reports" / "training" / "lora_dry_run_report.md"


def load_config(path: Path) -> dict[str, Any]:
    """Load YAML training config."""

    return yaml.safe_load(path.read_text(encoding="utf-8"))


def require_cuda() -> None:
    """Stop if CUDA is unavailable."""

    import torch

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA GPU is unavailable. Do not start LoRA training on this environment.")


def load_jsonl_dataset(path: str, text_field: str):
    """Load a local JSONL dataset through datasets."""

    from datasets import load_dataset

    dataset = load_dataset("json", data_files=str(ROOT / path), split="train")
    if text_field not in dataset.column_names:
        raise ValueError(f"Dataset {path} does not contain text field {text_field!r}")
    return dataset


def build_model_and_tokenizer(config: dict[str, Any], no_4bit: bool, base_model_override: str | None):
    """Load tokenizer/model and apply memory-conscious options."""

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    model_cfg = config["model"]
    base_model = base_model_override or model_cfg["base_model_name"]
    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=bool(model_cfg.get("trust_remote_code", False)))
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    dtype_name = model_cfg.get("torch_dtype", "bfloat16")
    torch_dtype = getattr(torch, dtype_name)
    quantization_config = None
    load_in_4bit = bool(model_cfg.get("load_in_4bit", True)) and not no_4bit
    if load_in_4bit:
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch_dtype,
            bnb_4bit_use_double_quant=True,
        )
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        trust_remote_code=bool(model_cfg.get("trust_remote_code", False)),
        torch_dtype=torch_dtype,
        device_map="auto",
        quantization_config=quantization_config,
    )
    if model_cfg.get("use_gradient_checkpointing", True):
        model.gradient_checkpointing_enable()
        model.config.use_cache = False
    return model, tokenizer, base_model, load_in_4bit


def train(config_path: Path, dry_run: bool, no_4bit: bool, base_model_override: str | None, output_dir_override: str | None) -> None:
    """Run LoRA training or tiny dry-run."""

    require_cuda()
    from peft import LoraConfig
    from transformers import TrainingArguments
    from trl import SFTTrainer, SFTConfig

    config = load_config(config_path)
    data_cfg = config["data"].copy()
    train_file = data_cfg["train_file"]
    validation_file = data_cfg["validation_file"]
    output_dir = config["training"]["output_dir"]
    max_steps = -1
    if dry_run:
        train_file = config["dry_run"]["train_file"]
        validation_file = config["dry_run"]["validation_file"]
        output_dir = config["dry_run"]["output_dir"]
        max_steps = int(config["dry_run"]["max_steps"])
    if output_dir_override:
        output_dir = output_dir_override
    train_dataset = load_jsonl_dataset(train_file, data_cfg["text_field"])
    eval_dataset = load_jsonl_dataset(validation_file, data_cfg["text_field"])
    model, tokenizer, base_model, load_in_4bit = build_model_and_tokenizer(config, no_4bit, base_model_override)
    lora_cfg = config["lora"]
    peft_config = LoraConfig(
        r=int(lora_cfg["r"]),
        lora_alpha=int(lora_cfg["alpha"]),
        lora_dropout=float(lora_cfg["dropout"]),
        target_modules=list(lora_cfg["target_modules"]),
        bias="none",
        task_type="CAUSAL_LM",
    )
    train_cfg = config["training"]
    args = SFTConfig(
        output_dir=str(ROOT / output_dir),
        num_train_epochs=float(train_cfg["num_train_epochs"]),
        per_device_train_batch_size=int(train_cfg["per_device_train_batch_size"]),
        per_device_eval_batch_size=int(train_cfg["per_device_eval_batch_size"]),
        gradient_accumulation_steps=int(train_cfg["gradient_accumulation_steps"]),
        learning_rate=float(train_cfg["learning_rate"]),
        warmup_ratio=float(train_cfg["warmup_ratio"]),
        weight_decay=float(train_cfg["weight_decay"]),
        logging_steps=int(train_cfg["logging_steps"]),
        eval_steps=int(train_cfg["eval_steps"]),
        save_steps=int(train_cfg["save_steps"]),
        save_total_limit=int(train_cfg["save_total_limit"]),
        eval_strategy=train_cfg["evaluation_strategy"],
        save_strategy=train_cfg["save_strategy"],
        report_to=train_cfg.get("report_to", "none"),
        seed=int(train_cfg["seed"]),
        max_steps=max_steps,
        bf16=config["model"].get("torch_dtype") == "bfloat16",
        dataset_text_field=data_cfg["text_field"],
        max_length=int(data_cfg["max_seq_length"]),
        packing=False,
    )
    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        peft_config=peft_config,
        args=args,
    )
    metrics: dict[str, Any] = {"dry_run": dry_run, "base_model": base_model, "load_in_4bit": load_in_4bit}
    try:
        result = trainer.train()
        metrics["train"] = result.metrics
        metrics["eval"] = trainer.evaluate()
        trainer.save_model(str(ROOT / output_dir))
        tokenizer.save_pretrained(str(ROOT / output_dir))
        (ROOT / output_dir / "training_config.yaml").write_text(config_path.read_text(encoding="utf-8"), encoding="utf-8")
    except RuntimeError as exc:
        message = str(exc)
        if "out of memory" in message.lower():
            message += "\nSuggested fixes: reduce max_seq_length, keep load_in_4bit=true, reduce batch size, increase gradient accumulation, or use a smaller base model."
        raise RuntimeError(message) from exc
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    write_report(metrics, output_dir, dry_run)


def write_report(metrics: dict[str, Any], output_dir: str, dry_run: bool) -> None:
    """Write training/dry-run report."""

    path = DRY_REPORT_PATH if dry_run else REPORT_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# TrustSecAI LoRA Dry-Run Report" if dry_run else "# TrustSecAI LoRA Training Report",
        "",
        f"- Created: {date.today().isoformat()}",
        f"- Output dir: `{output_dir}`",
        f"- Base model: `{metrics['base_model']}`",
        f"- 4-bit loading: `{metrics['load_in_4bit']}`",
        "",
        "```json",
        json.dumps(metrics, indent=2),
        "```",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Train TrustSecAI LoRA adapter.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-4bit", action="store_true")
    parser.add_argument("--base-model", default=None)
    parser.add_argument("--output-dir", default=None)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    try:
        train(args.config, args.dry_run, args.no_4bit, args.base_model, args.output_dir)
    except Exception as exc:
        print(f"LoRA training did not start or failed safely: {exc}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
