"""Run deterministic base/LoRA inference on the held-out TrustSecAI test set."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Literal

import torch


ROOT = Path(__file__).resolve().parents[3]
DEFAULT_TEST_FILE = ROOT / "artifacts" / "training" / "datasets" / "test_sft.jsonl"
DEFAULT_OUTPUT_DIR = ROOT / "artifacts" / "evaluation" / "lora_v1"
DEFAULT_ADAPTER_DIR = ROOT / "models" / "lora" / "trustsecai_lora_v1"
DEFAULT_BASE_MODEL = "meta-llama/Llama-3.1-8B-Instruct"
COMPACT_OUTPUT_INSTRUCTION = (
    "Return a compact JSON object. Do not include the full provenance array. "
    "Summarize provenance in at most 3 short strings. Keep the output under 700 words. "
    "Include only these keys: ids_label, sample_id, classifier_evidence, shap_evidence, "
    "graph_interpretation, limitations, provenance_summary, recommended_actions."
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load JSONL records from disk."""

    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    """Write JSONL rows."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def extract_prompt(row: dict[str, Any], compact_output_instruction: bool = False) -> str:
    """Extract the prompt without the supervised assistant target."""

    messages = row.get("messages")
    if isinstance(messages, list) and len(messages) >= 2:
        system = messages[0].get("content", "")
        user = messages[1].get("content", "")
        if compact_output_instruction:
            user = f"{user}\n\nAdditional output constraint:\n{COMPACT_OUTPUT_INSTRUCTION}"
        return (
            "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
            f"{system}<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n"
            f"{user}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
        )
    text = row.get("text", "")
    marker = "<|start_header_id|>assistant<|end_header_id|>"
    if marker not in text:
        raise ValueError(f"Could not split prompt/assistant target for {row.get('metadata', {}).get('example_id')}")
    prompt = text.split(marker, 1)[0]
    if compact_output_instruction:
        user_marker = "<|start_header_id|>user<|end_header_id|>"
        eot_marker = "<|eot_id|>"
        last_user = prompt.rfind(user_marker)
        if last_user >= 0:
            insert_at = prompt.find(eot_marker, last_user)
            if insert_at >= 0:
                prompt = (
                    prompt[:insert_at]
                    + f"\n\nAdditional output constraint:\n{COMPACT_OUTPUT_INSTRUCTION}"
                    + prompt[insert_at:]
                )
            else:
                prompt += f"\n\nAdditional output constraint:\n{COMPACT_OUTPUT_INSTRUCTION}"
        else:
            prompt += f"\n\nAdditional output constraint:\n{COMPACT_OUTPUT_INSTRUCTION}"
    return prompt + marker + "\n\n"


def target_text(row: dict[str, Any]) -> str:
    """Extract reviewed target output text from the SFT row."""

    messages = row.get("messages")
    if isinstance(messages, list) and len(messages) >= 3:
        return str(messages[2].get("content", ""))
    text = row.get("text", "")
    marker = "<|start_header_id|>assistant<|end_header_id|>"
    if marker not in text:
        return ""
    return text.split(marker, 1)[1].replace("<|eot_id|>", "").strip()


def preserve_metadata(row: dict[str, Any]) -> dict[str, Any]:
    """Keep the full row metadata for traceability."""

    metadata = row.get("metadata", {})
    return metadata if isinstance(metadata, dict) else {}


def flatten_metadata(row: dict[str, Any]) -> dict[str, Any]:
    """Extract commonly used metadata fields onto the generation record."""

    metadata = preserve_metadata(row)
    keys = [
        "example_id",
        "task_type",
        "ids_label",
        "base_context_id",
        "sample_id",
        "model_prediction",
        "model_confidence",
        "task_variant",
        "provenance_type",
        "has_cve",
    ]
    return {key: metadata.get(key) for key in keys if key in metadata}


def load_tokenizer(base_model: str):
    """Load tokenizer."""

    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(base_model, trust_remote_code=False)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    return tokenizer


def first_parameter_device(model: Any) -> str:
    """Return the device of the first model parameter for diagnostics."""

    try:
        return str(next(model.parameters()).device)
    except StopIteration:
        return "no_parameters"


def select_torch_dtype(device_placement: Literal["auto", "cuda"]) -> torch.dtype:
    """Select an inference dtype."""

    if device_placement == "cuda" and torch.cuda.is_available() and not torch.cuda.is_bf16_supported():
        print("bfloat16 is not reported as supported; using float16 for CUDA placement.", flush=True)
        return torch.float16
    return torch.bfloat16


def load_model(
    base_model: str,
    adapter_dir: Path | None,
    torch_dtype: torch.dtype,
    device_placement: Literal["auto", "cuda"],
):
    """Load base model, optionally with PEFT adapter."""

    from transformers import AutoModelForCausalLM

    print(f"Selected device placement: {device_placement}", flush=True)
    print(f"torch.cuda.is_available(): {torch.cuda.is_available()}", flush=True)
    print(f"Adapter directory: {adapter_dir if adapter_dir is not None else 'none'}", flush=True)

    if device_placement == "auto":
        model = AutoModelForCausalLM.from_pretrained(
            base_model,
            torch_dtype=torch_dtype,
            device_map="auto",
            trust_remote_code=False,
        )
    else:
        if not torch.cuda.is_available():
            raise RuntimeError("CUDA placement was requested, but CUDA is unavailable.")
        model = AutoModelForCausalLM.from_pretrained(
            base_model,
            torch_dtype=torch_dtype,
            trust_remote_code=False,
        )
        model.to("cuda")
    print(f"First parameter device after base load: {first_parameter_device(model)}", flush=True)

    if adapter_dir is not None:
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, str(adapter_dir))
        if device_placement == "cuda":
            model.to("cuda")
        print(f"First parameter device after adapter load: {first_parameter_device(model)}", flush=True)
    else:
        print(f"First parameter device after adapter load: {first_parameter_device(model)}", flush=True)

    model.eval()
    return model


def generate_for_rows(
    rows: list[dict[str, Any]],
    mode: Literal["base", "lora"],
    base_model: str,
    adapter_dir: Path,
    output_dir: Path,
    max_new_tokens: int,
    compact_output_instruction: bool,
    output_suffix: str | None,
    device_placement: Literal["auto", "cuda"],
) -> Path:
    """Generate deterministic outputs for rows and write JSONL."""

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is unavailable. Run inference on the HPC/GPU environment.")
    tokenizer = load_tokenizer(base_model)
    torch_dtype = select_torch_dtype(device_placement)
    model = load_model(
        base_model=base_model,
        adapter_dir=adapter_dir if mode == "lora" else None,
        torch_dtype=torch_dtype,
        device_placement=device_placement,
    )
    outputs: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        prompt = extract_prompt(row, compact_output_instruction=compact_output_instruction)
        encoded = tokenizer(prompt, return_tensors="pt").to(model.device)
        with torch.no_grad():
            generated = model.generate(
                **encoded,
                do_sample=False,
                max_new_tokens=max_new_tokens,
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )
        new_tokens = generated[0][encoded["input_ids"].shape[-1] :]
        generation = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
        output_row = {
            "model_mode": mode,
            "metadata": preserve_metadata(row),
            "prompt": prompt,
            "target": target_text(row),
            "generation": generation,
            "prompt_tokens": int(encoded["input_ids"].shape[-1]),
            "generated_tokens": int(new_tokens.shape[-1]),
            "max_new_tokens": max_new_tokens,
            "row_number": index,
        }
        output_row.update(flatten_metadata(row))
        outputs.append(output_row)
    suffix = f"_{output_suffix}" if output_suffix else ""
    output_path = output_dir / f"{mode}_generations{suffix}.jsonl"
    write_jsonl(output_path, outputs)
    return output_path


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Run TrustSecAI base/LoRA inference on held-out SFT test set.")
    parser.add_argument("--test-file", type=Path, default=DEFAULT_TEST_FILE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--adapter-dir", type=Path, default=DEFAULT_ADAPTER_DIR)
    parser.add_argument("--base-model", default=DEFAULT_BASE_MODEL)
    parser.add_argument("--model-mode", choices=["base", "lora", "both"], default="both")
    parser.add_argument("--device-placement", choices=["auto", "cuda"], default="auto")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--max-new-tokens", type=int, default=900)
    parser.add_argument(
        "--compact-output-instruction",
        action="store_true",
        help="Append a compact JSON output instruction to reduce long provenance copying.",
    )
    parser.add_argument(
        "--output-suffix",
        default=None,
        help="Optional filename suffix, e.g. compact -> lora_generations_compact.jsonl.",
    )
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    rows = load_jsonl(args.test_file)
    if args.limit is not None:
        rows = rows[: max(0, args.limit)]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    modes = ["base", "lora"] if args.model_mode == "both" else [args.model_mode]
    generated = []
    try:
        for mode in modes:
            generated.append(
                str(
                    generate_for_rows(
                        rows=rows,
                        mode=mode,
                        base_model=args.base_model,
                        adapter_dir=args.adapter_dir,
                        output_dir=args.output_dir,
                        max_new_tokens=args.max_new_tokens,
                        compact_output_instruction=args.compact_output_instruction,
                        output_suffix=args.output_suffix,
                        device_placement=args.device_placement,
                    )
                )
            )
    except Exception as exc:
        print(f"Inference stopped safely: {exc}", file=sys.stderr)
        raise SystemExit(1)
    print(json.dumps({"generated_files": generated, "rows": len(rows)}, indent=2))


if __name__ == "__main__":
    main()
