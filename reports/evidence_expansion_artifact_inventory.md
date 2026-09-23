# Evidence Expansion Artifact Inventory

Created: 2026-07-10

## Found Artifacts

- Cleaned CICIDS dataset: found `artifacts/processed/cleaned_cicids.parquet`
- XGBoost model candidates: models/xgboost/xgboost_model.joblib, models/xgboost/xgboost_model.joblib
- Feature metadata candidates: artifacts/metrics/xgboost_metrics.json, models/xgboost/feature_order.json
- SHAP artifacts: artifacts/shap/global_feature_importance.csv, artifacts/shap/sample_explanations.json
- Retrieval contexts: 5 of 5 target labels
- Attack label mapping: found `artifacts/attack_label_mapping.json`

## Missing Artifacts


## Safety Assessment

- Feature ordering recoverable: True
- Model inference can be run safely: True
- SHAP can be computed for selected model: True
- Blocking issue: none

## Assumptions

- The Week 1 XGBoost script trained a binary classifier and did not persist a model artifact in the current repository state.
- Feature order can be reconstructed from cleaned_cicids.parquet by excluding label, binary_label, and source_file, but exact model compatibility cannot be verified without the saved XGBoost artifact.
- For a binary IDS model, model_prediction is BENIGN/ATTACK; IDS sub-label retrieval must be linked using the real CICIDS ground-truth label, not invented multiclass probabilities.
