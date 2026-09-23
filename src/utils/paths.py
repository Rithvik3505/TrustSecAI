"""Project path helpers.

The scripts in this repository should be runnable from the project root or from
within subdirectories. This module centralizes path resolution so data scripts do
not rely on absolute machine-specific paths.
"""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASETS_DIR = PROJECT_ROOT / "Datasets"
CICIDS_DIR = DATASETS_DIR / "CICIDS-2017"
REPORTS_DIR = PROJECT_ROOT / "reports"
ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
PROCESSED_DIR = ARTIFACTS_DIR / "processed"
METRICS_DIR = ARTIFACTS_DIR / "metrics"
SHAP_DIR = ARTIFACTS_DIR / "shap"
GRAPH_ARTIFACTS_DIR = ARTIFACTS_DIR / "graph"
MODELS_DIR = PROJECT_ROOT / "models"
RF_MODEL_DIR = MODELS_DIR / "random_forest"


def ensure_project_dirs() -> None:
    """Create expected output directories if they are missing."""

    for path in (
        REPORTS_DIR,
        ARTIFACTS_DIR,
        PROCESSED_DIR,
        METRICS_DIR,
        SHAP_DIR,
        GRAPH_ARTIFACTS_DIR,
        MODELS_DIR,
        RF_MODEL_DIR,
    ):
        path.mkdir(parents=True, exist_ok=True)
