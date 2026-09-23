# XGBoost Day-Aware Split Report

## Scope

Train on Monday, Tuesday, Wednesday, and Thursday. Test on Friday. Binary labels only.

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
  "scale_pos_weight": 8.290611209986103,
  "subsample": 0.8,
  "tree_method": "hist"
}
```

## Training Summary

| Metric | Value |
|---|---:|
| Feature count | 78 |
| Training rows | 1,905,365 |
| Test rows | 615,433 |
| Training time seconds | 41.975 |

## Metrics

| accuracy | precision | recall | f1_score | roc_auc |
| --- | --- | --- | --- | --- |
| 0.771359 | 0.999101 | 0.362623 | 0.532115 | 0.788955 |

## Confusion Matrix

|  | Predicted 0 | Predicted 1 |
|---|---:|---:|
| Actual 0 | 394705 | 72 |
| Actual 1 | 140641 | 80015 |

## Observations

- Uses the same day-aware methodology as the Random Forest validation study.
- Uses `tree_method="hist"` for memory-conscious training.
- Uses training-split `scale_pos_weight`.
