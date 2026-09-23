"""Streamlit end-to-end TrustSecAI local demo.

Live components are lightweight: classifier inference, parsing, agreement,
attack-chain logic, and report assembly. LoRA generation is loaded from frozen
HPC evaluation artifacts.
"""

from __future__ import annotations

import sys
import os
import random
from pathlib import Path
from typing import Any

import pandas as pd

if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[2]))

try:
    import streamlit as st
except ImportError as exc:  # pragma: no cover - app-only dependency.
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
from src.pipeline.end_to_end_live_demo import DEMO_EXAMPLE_BY_LABEL, build_end_to_end_payload, save_payload


OUTPUT_DIR = Path("artifacts/demo/live_end_to_end")
LABEL_OPTIONS = [
    "Web Attack - Sql Injection",
    "PortScan",
    "FTP-Patator",
    "Bot",
    "DDoS",
    "BENIGN",
]
KEY_SANDBOX_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Packet Length Mean",
    "Packet Length Std",
    "Average Packet Size",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Bwd Packets/s",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Bwd Header Length",
    "Bwd IAT Total",
    "Bwd IAT Min",
]


def _value(value: Any) -> str:
    if value is None or value == "":
        return "Not available"
    if isinstance(value, float):
        return f"{value:.2%}" if 0 <= value <= 1 else f"{value:.4f}"
    return str(value)


def _as_list(value: Any) -> list[Any]:
    if not value:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _metric_row(payload: dict[str, Any]) -> None:
    classifier = payload.get("classifier_evidence", {})
    agreement = payload.get("agreement_result", {})
    chain = payload.get("attack_chain_prediction", {})
    cols = st.columns(5)
    cols[0].metric("IDS label", _value(classifier.get("ids_label")))
    cols[1].metric("Classifier", _value(classifier.get("model_prediction")))
    cols[2].metric("Confidence", _value(classifier.get("model_confidence")))
    cols[3].metric("Agreement", _value(agreement.get("category")))
    cols[4].metric("Attack-chain mode", _value(chain.get("mode")))


def _show_shap(shap_evidence: dict[str, Any]) -> None:
    features = _as_list(shap_evidence.get("top_features") or shap_evidence.get("shap_evidence"))
    if not features:
        st.warning(shap_evidence.get("fallback_note") or "SHAP evidence is not available for this case.")
        return
    rows = []
    for item in features[:5]:
        if isinstance(item, dict):
            rows.append(
                {
                    "feature": item.get("feature"),
                    "value": item.get("value"),
                    "shap_value": item.get("shap_value"),
                    "direction": str(item.get("direction", "")).replace("_", " "),
                }
            )
        else:
            rows.append({"feature": str(item), "value": "", "shap_value": "", "direction": ""})
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
    if shap_evidence.get("fallback_note"):
        st.caption(shap_evidence["fallback_note"])


def _show_graph(graph: dict[str, Any]) -> None:
    technique = graph.get("technique") or {}
    tactics = graph.get("tactics") or []
    st.write(
        {
            "context_mode": graph.get("context_mode", "Not available"),
            "technique": f"{technique.get('id', 'unknown')} {technique.get('name', '')}".strip(),
            "tactics": tactics or "Not available",
            "mitigation_count": len(graph.get("mitigation_ids") or []),
            "capec_count": len(graph.get("capec_ids") or []),
            "cwe_count": len(graph.get("cwe_ids") or []),
            "cve_count": len(graph.get("cve_ids") or []),
            "provenance_type": graph.get("provenance_type", "Not available"),
        }
    )


def _show_llm(parsed: dict[str, Any]) -> None:
    if not parsed:
        st.warning("No frozen LoRA output available for this selected sample.")
        return
    st.write("LLM output parsed successfully." if parsed.get("parse_ok") else "LLM output required fallback parsing.")
    st.markdown("**Graph interpretation**")
    st.write(parsed.get("graph_interpretation") or "Not available")
    st.markdown("**Recommended actions**")
    actions = _as_list(parsed.get("recommended_actions"))
    if actions:
        for item in actions:
            st.write(f"- {item}")
    else:
        st.write("Not available")
    st.markdown("**Limitations**")
    limitations = _as_list(parsed.get("limitations"))
    if limitations:
        for item in limitations:
            st.write(f"- {item}")
    else:
        st.write("Not available")


def _show_attack_chain(chain: dict[str, Any]) -> None:
    seed = chain.get("seed") or chain.get("seed_technique") or {}
    st.write(
        {
            "mode": chain.get("mode", "Not available"),
            "graph_available": chain.get("graph_available", "Not available"),
            "seed": f"{seed.get('technique_id') or seed.get('id', 'unknown')} {seed.get('technique_name') or seed.get('name', '')}".strip(),
            "confidence": chain.get("confidence", "Not available"),
            "fallback_reason": chain.get("fallback_reason") or "Not applicable",
        }
    )
    st.markdown("**Candidate next tactics/techniques**")
    steps = chain.get("candidate_next_steps") or chain.get("likely_next_tactics_techniques") or []
    if steps:
        for item in steps:
            if isinstance(item, dict):
                st.write(f"- {_value(item.get('tactic'))}: {_value(item.get('technique_id') or item.get('id'))} {_value(item.get('technique_name') or item.get('technique'))}")
            else:
                st.write(f"- {item}")
    else:
        st.write("Not available")
    st.markdown("**Caveats**")
    for item in _as_list(chain.get("caveats")):
        st.write(f"- {item}")


@st.cache_resource(show_spinner=False)
def _cached_classifier_artifacts() -> Any:
    """Load classifier artifact metadata once for the sandbox."""

    return load_classifier_artifacts()


@st.cache_resource(show_spinner=False)
def _cached_classifier_model(model_path: str) -> Any:
    """Load XGBoost classifier once for the sandbox."""

    return load_model(Path(model_path))


@st.cache_data(show_spinner=False)
def _cached_demo_samples() -> pd.DataFrame:
    """Load small demo samples for manual classifier sandbox."""

    return load_demo_samples()


def _sample_display(row: pd.Series) -> str:
    sample_id = row.get("sample_id", f"row-{int(row.name) + 1}")
    label = row.get("label", "unknown label")
    source = row.get("source_file", "unknown source")
    return f"{int(row.name) + 1}: {sample_id} | {label} | {source}"


def _feature_default(row: pd.Series, feature: str) -> float:
    """Return a numeric widget default for one feature."""

    value = pd.to_numeric(row.get(feature, 0.0), errors="coerce")
    if pd.isna(value):
        return 0.0
    return float(value)


def _reset_sandbox_values(row: pd.Series, feature_columns: list[str]) -> None:
    """Reset sandbox feature values to the selected base sample."""

    st.session_state["sandbox_values"] = {feature: _feature_default(row, feature) for feature in feature_columns}
    st.session_state["sandbox_base_index"] = int(row.name)
    st.session_state["sandbox_revision"] = st.session_state.get("sandbox_revision", 0) + 1


def _ensure_sandbox_values(row: pd.Series, feature_columns: list[str]) -> None:
    """Initialize or refresh sandbox values when the base sample changes."""

    if st.session_state.get("sandbox_base_index") != int(row.name) or "sandbox_values" not in st.session_state:
        _reset_sandbox_values(row, feature_columns)


def _perturb_sandbox_values(features: list[str]) -> None:
    """Apply a small deterministic perturbation to selected editable features."""

    rng = random.Random(42)
    values = dict(st.session_state.get("sandbox_values", {}))
    for feature in features:
        current = float(values.get(feature, 0.0))
        if current == 0:
            values[feature] = 1.0
            continue
        factor = 1.0 + rng.uniform(-0.15, 0.15)
        values[feature] = max(0.0, current * factor)
    st.session_state["sandbox_values"] = values
    st.session_state["sandbox_revision"] = st.session_state.get("sandbox_revision", 0) + 1
    st.session_state["sandbox_message"] = (
        "Selected features were perturbed for demonstration. Unrealistic values may produce unrealistic predictions."
    )


def _run_classifier_from_values(model: Any, feature_columns: list[str], values: dict[str, float]) -> dict[str, Any]:
    """Run classifier on edited sandbox values."""

    frame = pd.DataFrame([{feature: float(values.get(feature, 0.0)) for feature in feature_columns}])
    prediction = predict_sample(model, frame)
    return {"prediction": prediction, "feature_frame": frame}


def _render_end_to_end_tab() -> None:
    """Render the existing end-to-end demo view."""

    selected_label = st.sidebar.selectbox("Demo case", LABEL_OPTIONS)
    mapped_example = DEMO_EXAMPLE_BY_LABEL.get(selected_label)
    st.sidebar.write(f"Frozen LoRA example: `{mapped_example or 'not available'}`")
    use_graph = st.sidebar.checkbox("Use graph-backed attack-chain if Neo4j is available", value=True)
    prefer_live_shap = st.sidebar.checkbox("Try live SHAP first", value=True)

    if st.button("Run End-to-End Demo", type="primary"):
        try:
            payload = build_end_to_end_payload(
                example_id=mapped_example,
                label=selected_label,
                use_graph_attack_chain=use_graph,
                prefer_live_shap=prefer_live_shap,
            )
            key = mapped_example or selected_label
            paths = save_payload(payload, OUTPUT_DIR, key)
        except Exception as exc:  # noqa: BLE001 - reviewer-safe UI.
            st.error(f"End-to-end demo failed: {exc}")
            return

        _metric_row(payload)
        st.success(f"Saved JSON: {paths['json']} | Markdown: {paths['markdown']}")

        st.header("Stage 1: Live Classifier Inference")
        classifier = payload.get("classifier_evidence", {})
        st.write(
            {
                "true_ids_label": classifier.get("true_ids_label"),
                "binary_prediction": classifier.get("model_prediction"),
                "attack_probability": classifier.get("attack_probability"),
                "benign_probability": classifier.get("benign_probability"),
                "binary_correct": classifier.get("binary_correct"),
                "model_path": classifier.get("model_path"),
                "feature_count": classifier.get("feature_count"),
            }
        )

        st.header("Stage 2: SHAP Explanation")
        _show_shap(payload.get("shap_evidence", {}))

        st.header("Stage 3: GraphRAG Context")
        _show_graph(payload.get("graph_context_summary", {}))

        st.header("Stage 4: Frozen LoRA Secondary Assessment")
        if payload.get("lora_generation_available"):
            _show_llm(payload.get("llm_secondary_assessment", {}))
        else:
            st.warning("No frozen LoRA output available for this selected sample.")

        st.header("Stage 5: Agreement Analysis")
        st.write(payload.get("agreement_result", {}))

        st.header("Stage 6: Attack-Chain Hypothesis")
        _show_attack_chain(payload.get("attack_chain_prediction", {}))

        st.header("Stage 7: Final Report")
        st.markdown(payload.get("markdown_report", "Not available"))


def _render_classifier_sandbox_tab() -> None:
    """Render manual XGBoost classifier sandbox."""

    st.subheader("Live Classifier Sandbox")
    st.info(
        "Manual editing demonstrates that the trained XGBoost classifier is being executed live. "
        "Security interpretation is meaningful only for realistic CICIDS-style flow values. "
        "Labels, source_file, and metadata are never passed into the model."
    )
    try:
        artifacts = _cached_classifier_artifacts()
        samples = _cached_demo_samples()
        model = _cached_classifier_model(str(artifacts.model_path))
    except Exception as exc:  # noqa: BLE001
        st.error(f"Unable to initialize classifier sandbox: {exc}")
        st.markdown("Install expected dependencies with `.venv\\Scripts\\python.exe -m pip install xgboost joblib pandas streamlit`.")
        return

    labels = ["All"] + sorted(samples["label"].astype(str).unique().tolist()) if "label" in samples else ["All"]
    col_filter, col_select = st.columns([1, 2])
    selected_label = col_filter.selectbox("Filter sandbox samples", labels, key="sandbox_filter_label")
    filtered = samples if selected_label == "All" else samples[samples["label"].astype(str) == selected_label]
    if filtered.empty:
        st.warning("No samples available for this filter.")
        return

    options = {int(index): _sample_display(row) for index, row in filtered.iterrows()}
    selected_index = col_select.selectbox(
        "Choose a base sample",
        list(options.keys()),
        format_func=lambda key: options[key],
        key="sandbox_sample_index",
    )
    row = samples.loc[selected_index]
    _ensure_sandbox_values(row, artifacts.feature_columns)
    values = st.session_state["sandbox_values"]
    revision = st.session_state.get("sandbox_revision", 0)
    if st.session_state.get("sandbox_message"):
        st.warning(st.session_state.pop("sandbox_message"))

    st.markdown("**Base sample metadata**")
    example_id = DEMO_EXAMPLE_BY_LABEL.get(str(row.get("label")))
    st.write(
        {
            "example_id": example_id or "Not available",
            "sample_id": row.get("sample_id", f"row-{selected_index + 1}"),
            "ids_label": row.get("label", "Not available"),
            "binary_ground_truth": binary_ground_truth(row.get("label"), row.get("binary_label")),
            "source_file": row.get("source_file", "Not available"),
            "model_path": str(artifacts.model_path),
            "feature_count": len(artifacts.feature_columns),
            "sample_data_path": str(SAMPLE_PATH),
        }
    )

    base_frame, missing, extra = prepare_feature_frame(row, artifacts.feature_columns)
    if missing:
        st.error(f"Base sample is missing required model features: {missing}")
        if extra:
            st.write({"extra_columns": extra[:20]})
        return
    base_prediction = predict_sample(model, base_frame)

    st.markdown("**Key editable features**")
    st.caption("These commonly visible CICIDS features are shown first for fast review. All metadata columns are excluded.")
    key_features = [feature for feature in KEY_SANDBOX_FEATURES if feature in artifacts.feature_columns]
    for index in range(0, len(key_features), 3):
        cols = st.columns(3)
        for col, feature in zip(cols, key_features[index : index + 3], strict=False):
            with col:
                values[feature] = st.number_input(
                    feature,
                    value=float(values.get(feature, 0.0)),
                    step=1.0,
                    format="%.6f",
                    key=f"sandbox_key_{revision}_{selected_index}_{feature}",
                )

    with st.expander("Edit all 78 model features"):
        st.caption("Feature order is preserved. Key features already edited above are shown read-only here.")
        all_features = artifacts.feature_columns
        for index in range(0, len(all_features), 3):
            cols = st.columns(3)
            for col, feature in zip(cols, all_features[index : index + 3], strict=False):
                with col:
                    disabled = feature in key_features
                    current_value = float(values.get(feature, 0.0))
                    widget_value = st.number_input(
                        feature,
                        value=current_value,
                        step=1.0,
                        format="%.6f",
                        key=(
                            f"sandbox_all_readonly_{revision}_{selected_index}_{feature}"
                            if disabled
                            else f"sandbox_all_{revision}_{selected_index}_{feature}"
                        ),
                        disabled=disabled,
                        help="Edit this feature in the key-feature section above." if disabled else None,
                    )
                    if not disabled:
                        values[feature] = widget_value

    st.session_state["sandbox_values"] = values
    with st.container(horizontal=True):
        run_clicked = st.button("Run classifier on edited values", type="primary")
        if st.button("Reset to original sample values"):
            _reset_sandbox_values(row, artifacts.feature_columns)
            st.rerun()
        if st.button("Perturb selected features"):
            _perturb_sandbox_values(key_features)
            st.rerun()

    if run_clicked:
        try:
            edited_result = _run_classifier_from_values(model, artifacts.feature_columns, values)
        except Exception as exc:  # noqa: BLE001
            st.error(f"Classifier prediction failed: {exc}")
            return
        edited_prediction = edited_result["prediction"]
        prediction_changed = edited_prediction["prediction"] != base_prediction["prediction"]
        prob_delta = edited_prediction["attack_probability"] - base_prediction["attack_probability"]

        st.subheader("Live edited-input prediction")
        metric_cols = st.columns(5)
        metric_cols[0].metric("Base prediction", base_prediction["prediction"], _value(base_prediction["attack_probability"]))
        metric_cols[1].metric("Edited prediction", edited_prediction["prediction"], _value(edited_prediction["attack_probability"]))
        metric_cols[2].metric("Attack probability delta", f"{prob_delta:+.2%}")
        metric_cols[3].metric("Benign probability", _value(edited_prediction["benign_probability"]))
        metric_cols[4].metric("Prediction changed", "Yes" if prediction_changed else "No")
        if prediction_changed:
            st.success("The classifier output changed after feature edits.")
        else:
            st.info("The classifier recomputed live; this edit did not cross the decision boundary.")
        st.write(
            {
                "prediction": edited_prediction["prediction"],
                "attack_probability": edited_prediction["attack_probability"],
                "benign_probability": edited_prediction["benign_probability"],
                "feature_count": len(artifacts.feature_columns),
                "model_path": str(artifacts.model_path),
                "excluded_from_prediction": ["label", "binary_label", "source_file", "sample_id"],
            }
        )


def main() -> None:
    """Render Streamlit end-to-end demo."""

    st.set_page_config(page_title="TrustSecAI End-to-End Demo", layout="wide")
    st.title("TrustSecAI End-to-End Local Demo")
    st.caption("Offline review-safe demo using frozen LoRA v1 compact outputs.")
    st.info(
        "Live components: classifier, report assembly, agreement analysis, attack-chain logic. "
        "Cached component: LoRA text generation from HPC evaluation artifacts."
    )
    st.caption(f"Neo4j URI used by this Streamlit process: `{os.getenv('NEO4J_URI', 'bolt://127.0.0.1:7687')}`")

    end_to_end_tab, sandbox_tab = st.tabs(["End-to-End Demo", "Live Classifier Sandbox"])
    with end_to_end_tab:
        _render_end_to_end_tab()
    with sandbox_tab:
        _render_classifier_sandbox_tab()


if __name__ == "__main__":
    main()
