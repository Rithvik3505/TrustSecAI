# TrustSecAI End-to-End Live Demo Guide

## Purpose

This demo gives reviewers a practical local view of the TrustSecAI pipeline without requiring GPU access or live Llama inference.

It runs the lightweight components live and combines them with frozen LoRA v1 outputs generated during the completed HPC evaluation.

## What Runs Live

- CICIDS sample selection
- Numeric feature extraction
- XGBoost binary IDS classifier inference
- Classifier confidence calculation
- Binary correctness check when ground truth is available
- Optional local SHAP calculation when the environment supports it
- Response parsing
- Classifier-vs-LLM agreement analysis
- Defensive attack-chain prediction logic
- Markdown report assembly

## What Is Cached

- LoRA/Llama text generation is cached from:

```text
artifacts/evaluation/lora_v1/lora_generations_compact.jsonl
```

- Graph context used by the frozen LoRA prompt is cached from that evaluation context.
- Attack-chain traversal can use live Neo4j if available; otherwise the module safely falls back to static ATT&CK seed mappings.

## Why LoRA Is Cached

The LoRA v1 adapter was trained and evaluated on the HPC/DGX Spark environment. Live Llama inference is expensive, requires GPU memory, and is not necessary for a reviewer-facing local demonstration. The cached compact output lets reviewers inspect the complete TrustSecAI reasoning flow while avoiding accidental retraining or expensive inference.

## Streamlit Command

Run from the canonical project root:

```powershell
cd "C:\Users\LENOVO\WORK\Projects\TrustSecAI\TrustSecAI"
$env:NEO4J_URI="bolt://127.0.0.1:7687"
.venv\Scripts\python.exe -m streamlit run src/ui/end_to_end_live_demo.py
```

If Streamlit is missing:

```powershell
.venv\Scripts\python.exe -m pip install streamlit neo4j
```

Use the repo virtual environment for the UI so Streamlit and the Neo4j Python driver are available in the same interpreter.

## Reviewer Classifier Sandbox

The Streamlit app now has two tabs:

1. `End-to-End Demo`
2. `Live Classifier Sandbox`

Open `Live Classifier Sandbox` to manually edit CICIDS flow feature values and rerun the trained XGBoost classifier live.

Reviewer flow:

1. Select a base sample, optionally filtering by IDS label.
2. Review the base metadata: sample ID, IDS label, binary ground truth, and source file.
3. Edit the key numeric features shown first, such as `Destination Port`, `Flow Duration`, packet counts, packet sizes, and window/header fields.
4. Open `Edit all 78 model features` only if deeper inspection is needed.
5. Click `Run classifier on edited values`.
6. Compare the base sample prediction with the edited-input prediction.

What this proves:

- The saved XGBoost classifier is loaded and executed live.
- The prediction changes according to numeric CICIDS feature values.
- Labels, `source_file`, and metadata are excluded from the model input.
- The model uses the saved 78-feature order from `models/xgboost/feature_order.json`.

What this does not prove:

- It does not retrain the model.
- It does not run LoRA/Llama inference.
- It does not require Neo4j for sandbox use.
- It does not make security claims for unrealistic manually edited values.

Use the perturb button only to demonstrate live recomputation. The UI warns that unrealistic values may produce unrealistic predictions.

## CLI Commands

Run the SQL Injection demo case:

```powershell
$env:NEO4J_URI="bolt://127.0.0.1:7687"
.venv\Scripts\python.exe -m src.pipeline.end_to_end_live_demo --example-id trustsecai-gold-v1-00575
```

Run by IDS label:

```powershell
python -m src.pipeline.end_to_end_live_demo --label PortScan
```

Run with manual classifier feature overrides:

```powershell
python -m src.pipeline.end_to_end_live_demo --example-id trustsecai-gold-v1-00575 --override-feature "Destination Port=443" --override-feature "Average Packet Size=60"
```

Disable Neo4j traversal and force static fallback:

```powershell
python -m src.pipeline.end_to_end_live_demo --label PortScan --no-graph-attack-chain
```

## Output Paths

Generated outputs are saved under:

```text
artifacts/demo/live_end_to_end/
```

Each run creates:

- `end_to_end_<case>.json`
- `end_to_end_<case>.md`

## Reviewer Speaking Flow

1. Select one of the five attack demo cases, such as SQL Injection or PortScan.
2. Run the end-to-end demo.
3. Show Stage 1 to prove the XGBoost classifier is running live.
4. Show Stage 2 to explain the most influential CICIDS flow features.
5. Show Stage 3 to explain that graph context is contextual intelligence, not proof of compromise.
6. Show Stage 4 to present the frozen LoRA secondary assessment.
7. Show Stage 5 to explain classifier-vs-LLM agreement.
8. Show Stage 6 to show bounded defensive attack-chain pivots.
9. Show Stage 7 as the final SOC-style report.

## Important Safety Notes

- Do not rerun LoRA training during review.
- Do not run live LoRA inference locally.
- Do not modify the trained LoRA adapter or XGBoost model.
- The classifier is the primary detector.
- LoRA output is a secondary assessment, not ground truth.
- Graph context does not prove compromise or attribution.
- Attack-chain output is defensive investigation prioritization, not offensive guidance.
