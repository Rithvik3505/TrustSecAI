"""Streamlit UI for live TrustSecAI classifier-only inference."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pandas as pd

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

try:
    import streamlit as st
except ImportError as exc:  # pragma: no cover - used only when launched as an app.
    raise SystemExit("Streamlit is not installed. Install it with `pip install streamlit`.") from exc

from src.pipeline.classifier_live_predict import (
    SAMPLE_PATH,
    binary_ground_truth,
    load_classifier_artifacts,
    load_demo_samples,
    load_model,
    predict_sample,
    prepare_feature_frame,
)


def _format_probability(value: float | None) -> str:
    if value is None:
        return "Not available"
    return f"{value:.2%}"


@st.cache_resource(show_spinner=False)
def cached_artifacts() -> Any:
    """Load model artifact metadata once."""

    return load_classifier_artifacts()


@st.cache_resource(show_spinner=False)
def cached_model(model_path: str) -> Any:
    """Load the saved XGBoost model once."""

    return load_model(Path(model_path))


@st.cache_data(show_spinner=False)
def cached_samples() -> pd.DataFrame:
    """Load the small live-demo sample dataset."""

    return load_demo_samples()


def _row_label(row: pd.Series) -> str:
    sample_id = row.get("sample_id", f"row-{int(row.name) + 1}")
    label = row.get("label", "unknown")
    source = row.get("source_file", "unknown source")
    return f"{int(row.name) + 1}: {sample_id} | {label} | {source}"


def _try_live_shap(model: Any, feature_frame: pd.DataFrame, max_features: int = 5) -> tuple[pd.DataFrame | None, str | None]:
    """Best-effort lightweight local SHAP explanation."""

    try:
        import shap
    except ImportError:
        return None, "Live SHAP unavailable in this lightweight demo; install `shap` or use the generated SHAP reports."

    try:
        explainer = shap.TreeExplainer(model)
        values = explainer.shap_values(feature_frame)
        if isinstance(values, list):
            shap_values = values[1] if len(values) > 1 else values[0]
        else:
            shap_values = values
        row_values = shap_values[0]
        rows = []
        for feature, shap_value, raw_value in zip(feature_frame.columns, row_values, feature_frame.iloc[0], strict=False):
            rows.append(
                {
                    "feature": feature,
                    "value": raw_value,
                    "shap_value": float(shap_value),
                    "direction": "supports attack" if float(shap_value) > 0 else "supports benign",
                }
            )
        table = pd.DataFrame(rows)
        table["abs_shap"] = table["shap_value"].abs()
        table = table.sort_values("abs_shap", ascending=False).drop(columns=["abs_shap"]).head(max_features)
        table["shap_value"] = table["shap_value"].map(lambda value: round(float(value), 4))
        return table, None
    except Exception as exc:  # noqa: BLE001 - optional SHAP should never break classifier demo.
        return None, f"Live SHAP unavailable in this lightweight demo: {exc}. SHAP explanations are available in generated reports."


def main() -> None:
    """Render Streamlit classifier-only demo."""

    st.set_page_config(page_title="TrustSecAI Live Classifier Demo", layout="wide")
    st.title("TrustSecAI Live Classifier Demo")
    st.caption(
        "This demo runs the binary XGBoost IDS classifier live. "
        "It does not run LoRA, Neo4j, or attack-chain inference."
    )
    st.info("The classifier uses only numeric CICIDS flow features. Labels and source_file are excluded from prediction.")

    try:
        artifacts = cached_artifacts()
        samples = cached_samples()
        model = cached_model(str(artifacts.model_path))
    except Exception as exc:  # noqa: BLE001 - app should show friendly setup guidance.
        st.error(f"Unable to initialize classifier demo: {exc}")
        st.markdown(
            """
            Useful checks:
            - Confirm `models/xgboost/xgboost_model.joblib` exists.
            - Confirm `models/xgboost/feature_order.json` exists.
            - Install missing packages with `pip install xgboost joblib pandas streamlit`.
            """
        )
        return

    st.sidebar.header("Sample Selection")
    st.sidebar.write(f"Model: `{artifacts.model_path}`")
    st.sidebar.write(f"Sample file: `{SAMPLE_PATH}`")
    st.sidebar.write(f"Feature count: `{len(artifacts.feature_columns)}`")

    labels = ["All"] + sorted(samples["label"].astype(str).unique().tolist()) if "label" in samples else ["All"]
    selected_label = st.sidebar.selectbox("Filter by IDS label", labels)
    filtered = samples if selected_label == "All" else samples[samples["label"].astype(str) == selected_label]
    if filtered.empty:
        st.warning("No rows available for the selected label.")
        return

    if st.sidebar.button("Random sample"):
        st.session_state["selected_row_pos"] = int(filtered.sample(n=1, random_state=None).index[0])

    options = {int(index): _row_label(row) for index, row in filtered.iterrows()}
    default_index = st.session_state.get("selected_row_pos")
    option_keys = list(options.keys())
    if default_index not in option_keys:
        default_index = option_keys[0]
    selected_index = st.sidebar.selectbox(
        "Select sample row",
        option_keys,
        index=option_keys.index(default_index),
        format_func=lambda key: options[key],
    )
    row = samples.loc[selected_index]

    feature_frame, missing, extra = prepare_feature_frame(row, artifacts.feature_columns)
    left, right = st.columns([1, 1])
    with left:
        st.subheader("Selected Sample")
        st.write(
            {
                "sample_id": row.get("sample_id", f"row-{selected_index + 1}"),
                "true_ids_label": row.get("label", "Not available"),
                "source_file": row.get("source_file", "Not available"),
                "binary_ground_truth": binary_ground_truth(row.get("label"), row.get("binary_label")),
            }
        )
    with right:
        st.subheader("Artifact Status")
        st.write(
            {
                "model_path": str(artifacts.model_path),
                "feature_order_path": str(artifacts.feature_order_path) if artifacts.feature_order_path else "Inferred",
                "features_loaded": len(artifacts.feature_columns),
                "expected_features": 78,
            }
        )

    if missing:
        st.error("Feature mismatch. The selected sample is missing model features.")
        st.write({"missing": missing, "extra": extra[:20]})
        return

    if st.button("Run Classifier", type="primary"):
        try:
            prediction = predict_sample(model, feature_frame)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Classifier prediction failed: {exc}")
            return

        true_binary = binary_ground_truth(row.get("label"), row.get("binary_label"))
        binary_correct = None if true_binary is None else prediction["prediction_value"] == true_binary

        st.subheader("Live Prediction")
        metric_cols = st.columns(4)
        metric_cols[0].metric("Prediction", prediction["prediction"])
        metric_cols[1].metric("Attack probability", _format_probability(prediction["attack_probability"]))
        metric_cols[2].metric("Benign probability", _format_probability(prediction["benign_probability"]))
        metric_cols[3].metric("Binary correct", "N/A" if binary_correct is None else str(binary_correct))

        st.subheader("Top 10 Raw Feature Values")
        preview = pd.DataFrame(
            [{"feature": feature, "value": row[feature]} for feature in artifacts.feature_columns[:10]]
        )
        st.dataframe(preview, use_container_width=True, hide_index=True)

        st.subheader("Optional Live SHAP")
        shap_table, shap_message = _try_live_shap(model, feature_frame)
        if shap_table is not None:
            st.dataframe(shap_table, use_container_width=True, hide_index=True)
        else:
            st.warning(shap_message)


if __name__ == "__main__":
    main()
