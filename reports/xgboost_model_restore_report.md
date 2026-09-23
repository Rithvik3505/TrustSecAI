# XGBoost Model Restore Report

- Restore action: retrained and persisted Week 1 random-split XGBoost model
- Model path: `models/xgboost/xgboost_model.joblib`
- Feature order: `models/xgboost/feature_order.json`
- Metadata: `models/xgboost/model_metadata.json`
- Feature count: 78
- Training rows: 1764558
- Validation rows: 378120
- Test rows: 378120
- Training time seconds: 33.481

## Test Metrics

```json
{
  "accuracy": 0.9991695757960436,
  "confusion_matrix": {
    "fn": 32,
    "fp": 282,
    "labels": [
      0,
      1
    ],
    "matrix": [
      [
        313977,
        282
      ],
      [
        32,
        63829
      ]
    ],
    "tn": 313977,
    "tp": 63829
  },
  "f1_score": 0.9975463382614947,
  "precision": 0.9956013788585422,
  "recall": 0.999498911698846,
  "roc_auc": 0.9999816954785841
}
```
