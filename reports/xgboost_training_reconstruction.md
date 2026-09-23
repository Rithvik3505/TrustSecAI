# XGBoost Training Reconstruction

## Reconstructed Configuration

- Model task: binary IDS classification
- Label column: `binary_label`
- Class mapping: `0 = BENIGN`, `1 = ATTACK`
- Excluded columns: `label`, `binary_label`, `source_file`
- Feature count: 78
- Split logic: stratified random 70/15/15 using random seed 42
- Save path: `models/xgboost/xgboost_model.joblib`

## Hyperparameters

```json
{
  "colsample_bytree": 0.8,
  "eval_metric": "logloss",
  "learning_rate": 0.1,
  "max_depth": 8,
  "n_estimators": 300,
  "n_jobs": -1,
  "objective": "binary:logistic",
  "random_state": 42,
  "scale_pos_weight": 4.920958059721024,
  "subsample": 0.8,
  "tree_method": "hist"
}
```
