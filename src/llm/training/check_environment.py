"""Check HPC readiness for TrustSecAI LoRA training."""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import sys
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
REPORT_PATH = ROOT / "reports" / "training" / "hpc_environment_report.md"
JSON_PATH = ROOT / "artifacts" / "training" / "logs" / "hpc_environment_report.json"
CORPUS_PATHS = [
    ROOT / "artifacts" / "gold_candidates" / "v1" / "reviewed" / "trustsecai_gold_v1_reviewed.jsonl",
    ROOT / "artifacts" / "gold_candidates" / "v1" / "reviewed" / "train_reviewed.jsonl",
    ROOT / "artifacts" / "gold_candidates" / "v1" / "reviewed" / "validation_reviewed.jsonl",
    ROOT / "artifacts" / "gold_candidates" / "v1" / "reviewed" / "test_reviewed.jsonl",
]


def package_version(name: str) -> str | None:
    """Return package version without importing heavy modules when possible."""

    try:
        from importlib.metadata import version

        return version(name)
    except Exception:
        return None


def package_available(name: str) -> bool:
    """Return whether a package appears importable."""

    return importlib.util.find_spec(name) is not None


def torch_info() -> dict[str, Any]:
    """Collect PyTorch/CUDA information."""

    info: dict[str, Any] = {
        "torch_available": package_available("torch"),
        "torch_version": package_version("torch"),
        "cuda_available": False,
        "cuda_version": None,
        "gpu_count": 0,
        "gpus": [],
    }
    if not info["torch_available"]:
        return info
    try:
        import torch

        info["cuda_available"] = bool(torch.cuda.is_available())
        info["cuda_version"] = torch.version.cuda
        info["gpu_count"] = int(torch.cuda.device_count()) if info["cuda_available"] else 0
        for index in range(info["gpu_count"]):
            props = torch.cuda.get_device_properties(index)
            info["gpus"].append(
                {
                    "index": index,
                    "name": props.name,
                    "vram_gb": round(props.total_memory / (1024**3), 2),
                }
            )
    except Exception as exc:
        info["torch_error"] = str(exc)
    return info


def collect_environment() -> dict[str, Any]:
    """Collect environment diagnostics."""

    hf_token_available = any(os.environ.get(name) for name in ["HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_TOKEN"])
    hf_home = os.environ.get("HF_HOME") or os.environ.get("HUGGINGFACE_HUB_CACHE") or os.environ.get("TRANSFORMERS_CACHE")
    report = {
        "created_at": date.today().isoformat(),
        "python_version": sys.version,
        "platform": platform.platform(),
        "os": os.name,
        "cwd": str(Path.cwd()),
        "packages": {
            "transformers": package_version("transformers"),
            "datasets": package_version("datasets"),
            "peft": package_version("peft"),
            "accelerate": package_version("accelerate"),
            "trl": package_version("trl"),
            "bitsandbytes_available": package_available("bitsandbytes"),
            "flash_attn_available": package_available("flash_attn"),
        },
        "torch": torch_info(),
        "reviewed_corpus_paths": {str(path.relative_to(ROOT)): path.exists() for path in CORPUS_PATHS},
        "hugging_face": {
            "cache_path_set": hf_home is not None,
            "cache_path": hf_home,
            "token_or_login_appears_available": bool(hf_token_available),
            "token_value_printed": False,
        },
    }
    return report


def write_reports(report: dict[str, Any]) -> None:
    """Write JSON and Markdown environment reports."""

    JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    JSON_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    torch = report["torch"]
    packages = report["packages"]
    lines = [
        "# TrustSecAI HPC Environment Report",
        "",
        f"- Python: `{report['python_version'].split()[0]}`",
        f"- Platform: `{report['platform']}`",
        f"- Working directory: `{report['cwd']}`",
        f"- Torch: `{torch.get('torch_version')}`",
        f"- CUDA available: `{torch.get('cuda_available')}`",
        f"- CUDA version visible to PyTorch: `{torch.get('cuda_version')}`",
        f"- GPU count: `{torch.get('gpu_count')}`",
        f"- GPUs: `{torch.get('gpus')}`",
        f"- transformers: `{packages.get('transformers')}`",
        f"- datasets: `{packages.get('datasets')}`",
        f"- peft: `{packages.get('peft')}`",
        f"- accelerate: `{packages.get('accelerate')}`",
        f"- trl: `{packages.get('trl')}`",
        f"- bitsandbytes available: `{packages.get('bitsandbytes_available')}`",
        f"- flash-attn available: `{packages.get('flash_attn_available')}`",
        f"- Hugging Face cache path set: `{report['hugging_face']['cache_path_set']}`",
        f"- HF token/login appears available: `{report['hugging_face']['token_or_login_appears_available']}`",
        "",
        "## Reviewed Corpus Paths",
        "",
    ]
    for path, exists in report["reviewed_corpus_paths"].items():
        lines.append(f"- `{path}`: `{exists}`")
    if not torch.get("cuda_available"):
        lines.extend(["", "## Training Status", "", "CUDA GPU is not available. Do not attempt LoRA training on this environment."])
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    """CLI entrypoint."""

    report = collect_environment()
    write_reports(report)
    print(json.dumps(report, indent=2))
    if not report["torch"].get("cuda_available"):
        print("CUDA GPU is not available. Environment check completed; training should not be started here.")


if __name__ == "__main__":
    main()
