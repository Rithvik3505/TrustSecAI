# TrustSecAI Streamlit Demo Guide

## Purpose

The Streamlit UI provides a lightweight reviewer dashboard for the final TrustSecAI demo. It is offline-first and reads existing demo JSON files from `artifacts/demo/`.

It does not run:

- model training
- LoRA inference
- Neo4j traversal
- classifier inference

It does not modify model, checkpoint, dataset, or evaluation artifacts.

## Run Command

From the canonical project root:

```bash
streamlit run src/ui/streamlit_demo.py
```

If Streamlit is not installed:

```bash
pip install streamlit
```

## Demo Cases

The sidebar lets the reviewer select:

- Web Attack - Sql Injection: `trustsecai-gold-v1-00575`
- PortScan: `trustsecai-gold-v1-00178`
- FTP-Patator: `trustsecai-gold-v1-00810`
- Bot: `trustsecai-gold-v1-00381`
- DDoS: `trustsecai-gold-v1-00128`

Each case loads:

```text
artifacts/demo/demo_<example_id>.json
```

## Dashboard Sections

The UI shows:

- IDS label
- classifier prediction
- classifier confidence
- agreement category
- attack-chain mode
- executive summary
- top 5 SHAP features
- ATT&CK technique, tactic, mitigations, and CAPEC/CWE/CVE counts
- LoRA secondary assessment
- agreement rationale
- defensive attack-chain hypothesis
- raw Markdown report viewer

## Notes For Reviewers

- The UI is designed for presentation and inspection, not experimentation.
- Graph context is contextual intelligence, not proof of compromise.
- Group, tool, and malware context must not be interpreted as attribution.
- Candidate attack-chain steps are defensive investigation pivots, not attacker instructions.
- Missing fields are displayed as `Not available` rather than crashing the UI.
