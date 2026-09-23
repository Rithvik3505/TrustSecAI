# Random Forest Baseline IDS Report

## Scope

This report covers the Week 1 binary IDS baseline only. It uses `artifacts/processed/cleaned_cicids.parquet` and excludes `label`, `binary_label`, and `source_file` from model features.

## Hyperparameters

```json
{
  "class_weight": "balanced_subsample",
  "criterion": "gini",
  "max_depth": null,
  "n_estimators": 100,
  "n_jobs": -1,
  "random_state": 42
}
```

## Training Summary

| Metric | Value |
|---|---:|
| Feature count | 78 |
| Training rows | 1,764,558 |
| Validation rows | 378,120 |
| Test rows | 378,120 |
| Training time seconds | 71.368 |

## Metrics

| split | accuracy | precision | recall | f1_score | roc_auc |
| --- | --- | --- | --- | --- | --- |
| validation | 0.998619 | 0.996504 | 0.995318 | 0.995911 | 0.999818 |
| test | 0.998527 | 0.996627 | 0.994645 | 0.995635 | 0.999771 |

## Test Confusion Matrix

Labels are ordered `[0, 1]`, where `0=BENIGN` and `1=ATTACK`.

|  | Predicted 0 | Predicted 1 |
|---|---:|---:|
| Actual 0 | 314044 | 215 |
| Actual 1 | 342 | 63519 |

## Validation Confusion Matrix

|  | Predicted 0 | Predicted 1 |
|---|---:|---:|
| Actual 0 | 314036 | 223 |
| Actual 1 | 299 | 63562 |

## Class Distribution

| split | binary_label | meaning | count | percentage |
| --- | --- | --- | --- | --- |
| full | 0 | BENIGN | 2095057 | 83.110864 |
| full | 1 | ATTACK | 425741 | 16.889136 |
| train | 0 | BENIGN | 1466539 | 83.110841 |
| train | 1 | ATTACK | 298019 | 16.889159 |
| validation | 0 | BENIGN | 314259 | 83.110917 |
| validation | 1 | ATTACK | 63861 | 16.889083 |
| test | 0 | BENIGN | 314259 | 83.110917 |
| test | 1 | ATTACK | 63861 | 16.889083 |

## Observations

- The first baseline uses a stratified 70/15/15 train/validation/test split.
- Class labels are binary only: `BENIGN -> 0`, all attacks -> `1`.
- The model excludes `source_file`, preventing direct file/day leakage through that audit column.
- Accuracy should not be the only decision metric because the cleaned dataset remains imbalanced.
- SHAP and explainability were intentionally not run in this phase.
