"""Offline Streamlit UI for TrustSecAI demo reports.

The UI reads generated demo JSON files from artifacts/demo. It does not run
training, LoRA inference, Neo4j traversal, or modify model artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEMO_DIR = PROJECT_ROOT / "artifacts" / "demo"

DEMO_CASES = {
    "Web Attack - Sql Injection: trustsecai-gold-v1-00575": "trustsecai-gold-v1-00575",
    "PortScan: trustsecai-gold-v1-00178": "trustsecai-gold-v1-00178",
    "FTP-Patator: trustsecai-gold-v1-00810": "trustsecai-gold-v1-00810",
    "Bot: trustsecai-gold-v1-00381": "trustsecai-gold-v1-00381",
    "DDoS: trustsecai-gold-v1-00128": "trustsecai-gold-v1-00128",
}


def value_or_na(value: Any) -> Any:
    """Return a display-safe value."""

    return "Not available" if value in (None, "", [], {}) else value


def load_demo(example_id: str) -> dict[str, Any]:
    """Load one demo JSON file."""

    path = DEMO_DIR / f"demo_{example_id}.json"
    if not path.exists():
        st.error(f"Demo JSON not found: {path}")
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        st.error(f"Demo JSON is malformed: {exc}")
        return {}


def percent(value: Any) -> str:
    """Format confidence-like values."""

    if isinstance(value, (int, float)):
        return f"{value:.2%}"
    return "Not available"


def shap_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return top SHAP rows for a table."""

    rows = []
    features = data.get("shap_evidence", {}).get("top_features") or data.get("llm_secondary_assessment", {}).get("shap_evidence") or []
    for item in features[:5]:
        if not isinstance(item, dict):
            continue
        shap_value = item.get("shap_value")
        rows.append(
            {
                "feature": value_or_na(item.get("feature")),
                "value": value_or_na(item.get("value")),
                "shap_value": round(shap_value, 4) if isinstance(shap_value, (int, float)) else value_or_na(shap_value),
                "direction": value_or_na(str(item.get("direction", "")).replace("_", " ")),
            }
        )
    return rows


def attack_chain_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return candidate attack-chain steps for a table."""

    chain = data.get("attack_chain_prediction", {})
    steps = chain.get("candidate_next_steps") or chain.get("likely_next_tactics_techniques") or []
    rows = []
    for item in steps:
        if not isinstance(item, dict):
            rows.append({"tactic": "Not available", "technique_id": "candidate", "technique": str(item), "confidence": "Not available"})
            continue
        rows.append(
            {
                "tactic": value_or_na(item.get("tactic")),
                "technique_id": value_or_na(item.get("technique_id") or item.get("id")),
                "technique": value_or_na(item.get("technique_name") or item.get("technique") or item.get("description")),
                "confidence": value_or_na(item.get("confidence")),
            }
        )
    return rows


def render_list(title: str, items: Any) -> None:
    """Render a list-like section safely."""

    st.markdown(f"#### {title}")
    if not items:
        st.write("Not available")
        return
    if isinstance(items, str):
        st.write(items)
        return
    if isinstance(items, dict):
        st.json(items)
        return
    for item in items:
        if isinstance(item, dict):
            label = item.get("id") or item.get("name") or item.get("technique_id") or item.get("feature") or "item"
            detail = item.get("name") or item.get("technique_name") or item.get("technique") or item.get("rationale") or ""
            st.markdown(f"- `{label}` {detail}")
        else:
            st.markdown(f"- {item}")


def graph_counts(data: dict[str, Any]) -> dict[str, int]:
    """Compute graph context counts."""

    graph = data.get("graph_context_summary", {})
    return {
        "CAPEC": len(graph.get("capec_ids") or []),
        "CWE": len(graph.get("cwe_ids") or []),
        "CVE": len(graph.get("cve_ids") or []),
    }


def render_dashboard(data: dict[str, Any]) -> None:
    """Render the TrustSecAI demo dashboard."""

    metadata = data.get("metadata", {})
    classifier = data.get("classifier_evidence", {})
    graph = data.get("graph_context_summary", {})
    llm = data.get("llm_secondary_assessment", {})
    agreement = data.get("agreement_result", {})
    chain = data.get("attack_chain_prediction", {})

    st.title("TrustSecAI Security Incident Analysis Demo")
    st.caption("Offline demo using frozen LoRA v1 compact outputs")

    cols = st.columns(5)
    cols[0].metric("IDS Label", value_or_na(metadata.get("ids_label") or classifier.get("ids_label")))
    cols[1].metric("Classifier", value_or_na(classifier.get("model_prediction")))
    cols[2].metric("Confidence", percent(classifier.get("model_confidence")))
    cols[3].metric("Agreement", value_or_na(agreement.get("category")))
    cols[4].metric("Attack-Chain Mode", value_or_na(chain.get("mode")))

    st.markdown("## Executive Summary")
    report = data.get("markdown_report", "")
    executive = "Not available"
    if "## Executive Summary" in report:
        executive = report.split("## Executive Summary", 1)[1].split("##", 1)[0].strip()
    st.write(executive)

    st.markdown("## Classifier And SHAP Evidence")
    st.write(
        {
            "sample_id": value_or_na(classifier.get("sample_id")),
            "source_file": value_or_na(classifier.get("source_file")),
            "confidence_band": value_or_na(classifier.get("confidence_band")),
        }
    )
    rows = shap_rows(data)
    st.dataframe(rows if rows else [{"feature": "Not available"}], use_container_width=True)

    st.markdown("## Graph Context")
    technique = graph.get("technique") or {}
    st.write(
        {
            "ATT&CK technique": f"{value_or_na(technique.get('id'))} {value_or_na(technique.get('name'))}",
            "tactics": graph.get("tactics") or "Not available",
            "mitigations": graph.get("mitigation_ids") or "Not available",
            "counts": graph_counts(data),
            "provenance_type": value_or_na(graph.get("provenance_type")),
        }
    )

    st.markdown("## LLM Secondary Assessment")
    st.write(value_or_na(llm.get("graph_interpretation")))
    render_list("Recommended Actions", llm.get("recommended_actions"))
    render_list("Limitations", llm.get("limitations"))

    st.markdown("## Agreement Analysis")
    st.write({"category": value_or_na(agreement.get("category")), "rationale": value_or_na(agreement.get("rationale"))})

    st.markdown("## Defensive Attack-Chain Hypothesis")
    seed = chain.get("seed") or chain.get("seed_technique") or {}
    st.write(
        {
            "mode": value_or_na(chain.get("mode")),
            "graph_available": value_or_na(chain.get("graph_available")),
            "seed": seed,
            "confidence": value_or_na(chain.get("confidence")),
        }
    )
    st.dataframe(attack_chain_rows(data) or [{"tactic": "Not available"}], use_container_width=True)
    render_list("Mitigations", chain.get("mitigations"))
    render_list("Vulnerability Context", chain.get("vulnerability_context"))
    render_list("Caveats", chain.get("caveats"))

    st.markdown("## Raw Markdown Report")
    with st.expander("Open full Markdown report", expanded=False):
        st.markdown(report or "Not available")


def main() -> None:
    """Run the Streamlit app."""

    selected = st.sidebar.selectbox("Demo case", list(DEMO_CASES))
    example_id = DEMO_CASES[selected]
    st.sidebar.write(f"Example ID: `{example_id}`")
    data = load_demo(example_id)
    if data:
        render_dashboard(data)


if __name__ == "__main__":
    main()
