"""Live classifier-only inference helper for TrustSecAI demos.

This module intentionally uses only the saved XGBoost IDS model and processed
CICIDS samples. It does not call Neo4j, LoRA, SHAP global generation, or any
training code.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

from src.utils.paths import ARTIFACTS_DIR, MODELS_DIR, PROCESSED_DIR, PROJECT_ROOT, REPORTS_DIR


TARGET_DEMO_LABELS = [
    "BENIGN",
    "Web Attack - Sql Injection",
    "PortScan",
    "FTP-Patator",
    "Bot",
    "DDoS",
]
EXCLUDED_FEATURE_COLUMNS = {
    "label",
    "Label",
    "binary_label",
    "source_file",
    "sample_id",
    "row_number",
    "row_index",
    "id",
    "metadata",
}
SAMPLE_PATH = ARTIFACTS_DIR / "demo" / "classifier_live_samples.csv"


@dataclass(frozen=True)
class ClassifierArtifacts:
    """Resolved classifier artifact paths and feature order."""

    model_path: Path
    feature_order_path: Path | None
    metadata_path: Path | None
    feature_columns: list[str]


def _relative(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def discover_model_path() -> tuple[Path | None, list[Path]]:
    """Find the preferred saved XGBoost binary classifier."""

    candidates = [
        MODELS_DIR / "xgboost" / "xgboost_model.joblib",
        MODELS_DIR / "xgboost" / "xgboost_model.pkl",
        MODELS_DIR / "xgboost_model.joblib",
        MODELS_DIR / "xgboost_model.pkl",
        ARTIFACTS_DIR / "models" / "xgboost_model.joblib",
        ARTIFACTS_DIR / "models" / "xgboost" / "xgboost_model.joblib",
    ]
    existing = [path for path in candidates if path.exists()]
    if existing:
        return existing[0], candidates

    search_roots = [MODELS_DIR, ARTIFACTS_DIR / "models", ARTIFACTS_DIR / "metrics"]
    discovered: list[Path] = []
    for root in search_roots:
        if root.exists():
            for pattern in ("*.joblib", "*.pkl", "*.pickle", "*.ubj", "*.model", "*.json"):
                discovered.extend(root.rglob(pattern))
    xgb_like = [path for path in discovered if "xgboost" in path.name.lower() or "xgboost" in str(path.parent).lower()]
    return (xgb_like[0] if xgb_like else None), candidates + xgb_like


def load_feature_columns(model_dir: Path, sample_frame: pd.DataFrame | None = None) -> tuple[list[str], Path | None, Path | None]:
    """Load saved feature order, falling back to dataframe feature inference."""

    feature_order_path = model_dir / "feature_order.json"
    metadata_path = model_dir / "model_metadata.json"

    if feature_order_path.exists():
        return json.loads(feature_order_path.read_text(encoding="utf-8")), feature_order_path, metadata_path if metadata_path.exists() else None

    if metadata_path.exists():
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        feature_columns = metadata.get("feature_columns")
        if isinstance(feature_columns, list) and feature_columns:
            return [str(column) for column in feature_columns], None, metadata_path

    if sample_frame is None:
        raise FileNotFoundError(
            "No saved feature_order.json or model_metadata.json was found, and no sample dataframe was provided for feature inference."
        )
    inferred = [column for column in sample_frame.columns if column not in EXCLUDED_FEATURE_COLUMNS]
    return inferred, None, metadata_path if metadata_path.exists() else None


def load_classifier_artifacts() -> ClassifierArtifacts:
    """Resolve classifier model and feature order."""

    model_path, searched = discover_model_path()
    if model_path is None:
        searched_text = "\n".join(f"- {_relative(path)}" for path in searched)
        raise FileNotFoundError(
            "Could not find a saved XGBoost model artifact. Searched:\n"
            f"{searched_text}\n"
            "Expected preferred path: models/xgboost/xgboost_model.joblib"
        )
    feature_columns, feature_order_path, metadata_path = load_feature_columns(model_path.parent)
    return ClassifierArtifacts(model_path, feature_order_path, metadata_path, feature_columns)


def load_model(model_path: Path) -> Any:
    """Load the saved classifier with clear dependency errors."""

    try:
        import joblib
    except ImportError as exc:
        raise RuntimeError("Missing dependency: install joblib with `pip install joblib`.") from exc

    try:
        loaded = joblib.load(model_path)
    except ModuleNotFoundError as exc:
        if exc.name and "xgboost" in exc.name.lower():
            raise RuntimeError("Missing dependency: install XGBoost with `pip install xgboost`.") from exc
        raise

    if isinstance(loaded, dict):
        model = loaded.get("model")
        if model is None:
            raise RuntimeError(
                f"Model artifact `{model_path}` is a dictionary but does not contain a `model` key."
            )
        return model
    return loaded


def _read_source_dataset_for_samples() -> pd.DataFrame:
    """Load the smallest available processed dataset that contains demo labels."""

    sample_csv = PROCESSED_DIR / "cleaned_cicids_sample.csv"
    if sample_csv.exists():
        sample_frame = pd.read_csv(sample_csv)
        labels = set(sample_frame.get("label", pd.Series(dtype=str)).astype(str))
        if set(TARGET_DEMO_LABELS).issubset(labels):
            return sample_frame

    parquet_path = PROCESSED_DIR / "cleaned_cicids.parquet"
    if not parquet_path.exists():
        if sample_csv.exists():
            return pd.read_csv(sample_csv)
        raise FileNotFoundError("No processed CICIDS dataset found under artifacts/processed/.")
    return pd.read_parquet(parquet_path)


def ensure_demo_samples(sample_path: Path = SAMPLE_PATH, rows_per_label: int = 5, random_state: int = 42) -> Path:
    """Create a small balanced classifier demo sample CSV if it does not exist."""

    if sample_path.exists():
        return sample_path

    sample_path.parent.mkdir(parents=True, exist_ok=True)
    dataframe = _read_source_dataset_for_samples()
    if "label" not in dataframe.columns:
        raise ValueError("Processed dataset does not contain a `label` column for demo sampling.")

    selected_parts: list[pd.DataFrame] = []
    for label in TARGET_DEMO_LABELS:
        subset = dataframe[dataframe["label"].astype(str) == label]
        if subset.empty:
            continue
        take = min(rows_per_label, len(subset))
        selected_parts.append(subset.sample(n=take, random_state=random_state))

    if not selected_parts:
        raise ValueError("No rows were available for the classifier live demo sample.")

    demo = pd.concat(selected_parts, ignore_index=True)
    demo.insert(0, "sample_id", [f"classifier-demo-{index:03d}" for index in range(len(demo))])
    demo.to_csv(sample_path, index=False)
    return sample_path


def load_demo_samples(sample_path: Path = SAMPLE_PATH) -> pd.DataFrame:
    """Load or create the small classifier demo sample set."""

    path = ensure_demo_samples(sample_path)
    return pd.read_csv(path)


def prepare_feature_frame(row: pd.Series, feature_columns: list[str]) -> tuple[pd.DataFrame, list[str], list[str]]:
    """Build a single-row feature dataframe in the model's expected order."""

    missing = [column for column in feature_columns if column not in row.index]
    extra = [column for column in row.index if column not in set(feature_columns) | EXCLUDED_FEATURE_COLUMNS]
    if missing:
        return pd.DataFrame(), missing, extra

    features = pd.DataFrame([{column: row[column] for column in feature_columns}])
    features = features.apply(pd.to_numeric, errors="coerce").fillna(0)
    return features, missing, extra


def select_sample(dataframe: pd.DataFrame, row_number: int | None, label: str | None, random_sample: bool) -> pd.Series:
    """Select one sample row for inference."""

    if row_number is not None:
        if row_number < 1 or row_number > len(dataframe):
            raise IndexError(f"row-number must be between 1 and {len(dataframe)}.")
        return dataframe.iloc[row_number - 1]

    if label:
        subset = dataframe[dataframe["label"].astype(str).str.lower() == label.lower()]
        if subset.empty:
            available = ", ".join(sorted(dataframe["label"].astype(str).unique()))
            raise ValueError(f"No demo sample found for label `{label}`. Available labels: {available}")
        return subset.iloc[0]

    if random_sample:
        return dataframe.iloc[random.Random(42).randrange(len(dataframe))]

    return dataframe.iloc[0]


def predict_sample(model: Any, feature_frame: pd.DataFrame) -> dict[str, Any]:
    """Run binary classifier prediction and probability extraction."""

    prediction_value = int(model.predict(feature_frame)[0])
    prediction_label = "ATTACK" if prediction_value == 1 else "BENIGN"
    benign_probability: float | None = None
    attack_probability: float | None = None

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(feature_frame)[0]
        if len(probabilities) >= 2:
            benign_probability = float(probabilities[0])
            attack_probability = float(probabilities[1])
    if attack_probability is None:
        attack_probability = float(prediction_value)
        benign_probability = 1.0 - attack_probability

    return {
        "prediction": prediction_label,
        "prediction_value": prediction_value,
        "attack_probability": attack_probability,
        "benign_probability": benign_probability,
        "confidence": attack_probability if prediction_label == "ATTACK" else benign_probability,
    }


def binary_ground_truth(label: str | None, binary_label: Any | None = None) -> int | None:
    """Convert available ground truth into BENIGN=0 / ATTACK=1."""

    if binary_label is not None and str(binary_label) != "nan":
        try:
            return int(binary_label)
        except (TypeError, ValueError):
            pass
    if label is None:
        return None
    return 0 if str(label).upper() == "BENIGN" else 1


def prediction_for_cli(row_number: int | None = None, label: str | None = None, random_sample: bool = False) -> dict[str, Any]:
    """Run one classifier-only live prediction and return a serializable result."""

    artifacts = load_classifier_artifacts()
    samples = load_demo_samples()
    row = select_sample(samples, row_number=row_number, label=label, random_sample=random_sample)
    feature_frame, missing, extra = prepare_feature_frame(row, artifacts.feature_columns)
    if missing:
        raise ValueError(f"Feature mismatch. Missing columns: {missing}. Extra columns: {extra[:20]}")

    model = load_model(artifacts.model_path)
    model_feature_count = getattr(model, "n_features_in_", None)
    if model_feature_count is not None and int(model_feature_count) != len(artifacts.feature_columns):
        raise ValueError(
            f"Model expects {model_feature_count} features, but feature_order contains {len(artifacts.feature_columns)}."
        )

    prediction = predict_sample(model, feature_frame)
    true_binary = binary_ground_truth(row.get("label"), row.get("binary_label"))
    binary_correct = None if true_binary is None else prediction["prediction_value"] == true_binary

    metadata = {
        "sample_id": row.get("sample_id", f"row-{int(row.name) + 1}"),
        "row_number": int(row.name) + 1,
        "true_label": row.get("label"),
        "source_file": row.get("source_file"),
        "binary_ground_truth": true_binary,
        "binary_correct": binary_correct,
    }

    feature_preview = {column: row[column] for column in artifacts.feature_columns[:10]}
    return {
        "model_path": _relative(artifacts.model_path),
        "feature_order_path": _relative(artifacts.feature_order_path) if artifacts.feature_order_path else None,
        "sample_data_path": _relative(SAMPLE_PATH),
        "feature_count": len(artifacts.feature_columns),
        "model_feature_count": int(model_feature_count) if model_feature_count is not None else None,
        "metadata": metadata,
        "prediction": prediction,
        "feature_preview": feature_preview,
    }


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Run live classifier-only TrustSecAI prediction.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--row-number", type=int, help="1-based row number in the demo sample file.")
    group.add_argument("--random", action="store_true", help="Select a deterministic random sample.")
    group.add_argument("--label", type=str, help="Select the first sample with this IDS label.")
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    try:
        result = prediction_for_cli(row_number=args.row_number, label=args.label, random_sample=args.random)
    except Exception as exc:  # noqa: BLE001 - CLI should show concise demo-safe errors.
        print(f"Classifier live prediction failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    metadata = result["metadata"]
    prediction = result["prediction"]
    print("TrustSecAI Live Classifier Prediction")
    print(f"Model path: {result['model_path']}")
    print(f"Sample data path: {result['sample_data_path']}")
    print(f"Feature count: {result['feature_count']}")
    print(f"Sample ID: {metadata.get('sample_id')}")
    print(f"Row number: {metadata.get('row_number')}")
    print(f"True IDS label: {metadata.get('true_label')}")
    print(f"Source file: {metadata.get('source_file')}")
    print(f"Prediction: {prediction['prediction']}")
    print(f"Attack probability: {prediction['attack_probability']:.6f}")
    print(f"Benign probability: {prediction['benign_probability']:.6f}")
    print(f"Classifier confidence: {prediction['confidence']:.6f}")
    if metadata.get("binary_correct") is not None:
        print(f"Binary correctness: {metadata['binary_correct']}")
    print("Top 10 feature preview:")
    for feature, value in result["feature_preview"].items():
        print(f"  - {feature}: {value}")


if __name__ == "__main__":
    main()
