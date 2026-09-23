# XGBoost Baseline IDS Report

## Scope

Binary IDS baseline using `artifacts/processed/cleaned_cicids.parquet`. Excluded columns: `label`, `binary_label`, `source_file`.

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

## Training Summary

| Metric | Value |
|---|---:|
| Feature count | 78 |
| Training rows | 1,764,558 |
| Validation rows | 378,120 |
| Test rows | 378,120 |
| Training time seconds | 45.794 |

## Metrics

| split | accuracy | precision | recall | f1_score | roc_auc |
| --- | --- | --- | --- | --- | --- |
| validation | 0.999130 | 0.995137 | 0.999734 | 0.997430 | 0.999981 |
| test | 0.999170 | 0.995601 | 0.999499 | 0.997546 | 0.999982 |

## Test Confusion Matrix

|  | Predicted 0 | Predicted 1 |
|---|---:|---:|
| Actual 0 | 313977 | 282 |
| Actual 1 | 32 | 63829 |

## Observations

- Uses the same stratified 70/15/15 split as the Random Forest baseline.
- Uses `tree_method="hist"` for memory-conscious training.
- Uses `scale_pos_weight` from the training split class ratio.
- This is binary classification only; no SHAP or Week 2 components are run here.
