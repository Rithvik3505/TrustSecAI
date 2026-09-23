# TrustSecAI Classifier Live Demo Guide

## Purpose

This lightweight demo shows the already-trained binary XGBoost IDS classifier running live on selected CICIDS2017 flow samples.

It proves that the saved classifier artifact can be loaded locally, receives numeric CICIDS flow features in the expected order, and produces a live `BENIGN` or `ATTACK` prediction with probability/confidence.

## What It Does Not Prove

- It does not retrain the IDS model.
- It does not run LoRA or Llama inference.
- It does not require Neo4j or GraphRAG.
- It does not run attack-chain prediction.
- It does not prove compromise, attribution, or asset exposure.

The classifier is binary. The live prediction is only `BENIGN` or `ATTACK`; CICIDS subtype labels such as `PortScan` are shown as ground-truth sample metadata for demonstration and retrieval context.

## Artifacts Used

| Artifact | Purpose |
|---|---|
| `models/xgboost/xgboost_model.joblib` | Saved binary XGBoost IDS classifier |
| `models/xgboost/feature_order.json` | Exact model feature order |
| `models/xgboost/model_metadata.json` | Model metadata and metric summary |
| `artifacts/processed/cleaned_cicids_sample.csv` | Preferred compact source for demo rows |
| `artifacts/processed/cleaned_cicids.parquet` | Fallback source if a label is missing from compact sample |
| `artifacts/demo/classifier_live_samples.csv` | Small derived demo sample file |

The derived demo CSV is allowed because it is a demo artifact. It does not modify the model, processed dataset, or evaluation outputs.

## Streamlit Demo

Run from the canonical project root:

```powershell
cd "C:\Users\LENOVO\WORK\Projects\TrustSecAI\TrustSecAI"
python -m streamlit run src/ui/classifier_live_demo.py
```

If Streamlit is missing:

```powershell
pip install streamlit
```

The app displays:

- model path
- feature count
- selected sample metadata
- true IDS label if present
- source file if present
- live binary prediction
- attack and benign probabilities
- binary correctness if ground truth is available
- top 10 raw feature values
- optional live SHAP if the local environment supports it

## CLI Fallback

Run a specific label:

```powershell
python -m src.pipeline.classifier_live_predict --label PortScan
```

Run a deterministic random example:

```powershell
python -m src.pipeline.classifier_live_predict --random
```

Run by 1-based row number from `artifacts/demo/classifier_live_samples.csv`:

```powershell
python -m src.pipeline.classifier_live_predict --row-number 1
```

## Reviewer Explanation

For review, first show the Streamlit classifier-only demo to demonstrate live IDS inference. Then open the existing TrustSecAI incident demo to show how the broader system adds SHAP evidence, graph context, LoRA secondary assessment, agreement analysis, and defensive attack-chain pivots.

Suggested speaking line:

> This screen is deliberately classifier-only. It proves the saved XGBoost IDS model is being loaded and executed live on CICIDS flow features. The downstream TrustSecAI demo then turns this kind of classifier signal into contextual SOC-style analysis using SHAP, GraphRAG, the fine-tuned Llama adapter, agreement analysis, and defensive attack-chain prioritization.

## Safety Note

The classifier uses only numeric CICIDS flow features. `label`, `binary_label`, `source_file`, and demo metadata fields are excluded from prediction.
