"""Lightweight LoRA v1 integration client.

The default client mode is offline: it reads frozen LoRA generations from the
held-out compact evaluation artifact. Live/HPC command mode is intentionally a
placeholder so this module never triggers expensive inference by accident.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_GENERATIONS_FILE = Path("artifacts/evaluation/lora_v1/lora_generations_compact.jsonl")
DEFAULT_HPC_COMMAND = (
    "python -m src.llm.evaluation.run_lora_inference "
    "--model-mode lora --max-new-tokens 1200 --compact-output-instruction "
    "--output-suffix compact --device-placement cuda"
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load JSONL records from disk."""

    if not path.exists():
        raise FileNotFoundError(f"LoRA generation file not found: {path}")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@dataclass
class LoraClient:
    """Read frozen LoRA outputs or describe the live inference command."""

    generations_file: Path = DEFAULT_GENERATIONS_FILE
    mode: str = "offline"

    def __post_init__(self) -> None:
        """Validate mode and lazily index offline generations."""

        if self.mode not in {"offline", "command"}:
            raise ValueError("mode must be 'offline' or 'command'")
        self._rows: list[dict[str, Any]] | None = None
        self._by_example_id: dict[str, dict[str, Any]] | None = None

    def _ensure_loaded(self) -> None:
        """Load offline generation rows once."""

        if self._rows is not None:
            return
        rows = load_jsonl(self.generations_file)
        self._rows = rows
        self._by_example_id = {
            str(row.get("example_id") or row.get("metadata", {}).get("example_id")): row
            for row in rows
            if row.get("example_id") or row.get("metadata", {}).get("example_id")
        }

    def get_generation(self, example_id: str | None = None, row_number: int | None = None) -> dict[str, Any]:
        """Return a frozen LoRA generation by example_id or one-based row number."""

        if self.mode != "offline":
            raise RuntimeError("Command mode is documentation-only; run HPC inference explicitly outside this client.")
        self._ensure_loaded()
        assert self._rows is not None
        assert self._by_example_id is not None
        if example_id:
            if example_id not in self._by_example_id:
                raise KeyError(f"example_id not found in offline LoRA generations: {example_id}")
            return self._by_example_id[example_id]
        if row_number is not None:
            if row_number < 1 or row_number > len(self._rows):
                raise IndexError(f"row_number must be between 1 and {len(self._rows)}")
            return self._rows[row_number - 1]
        raise ValueError("Provide either example_id or row_number")

    def command_placeholder(self) -> dict[str, str]:
        """Describe, but do not execute, the HPC inference command."""

        return {
            "mode": "command",
            "status": "not_executed",
            "command": DEFAULT_HPC_COMMAND,
            "note": "Run this manually on the HPC/GPU only when a new LoRA generation artifact is required.",
        }

