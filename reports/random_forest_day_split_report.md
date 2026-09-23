# Random Forest Day-Aware Split Report

## Scope

This experiment trains on Monday, Tuesday, Wednesday, and Thursday CICIDS2017 records and tests only on Friday records. It uses the same Random Forest hyperparameters as the stratified baseline.

## Split

- Train files: `Monday-WorkingHours.pcap_ISCX.csv, Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv, Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv, Tuesday-WorkingHours.pcap_ISCX.csv, Wednesday-workingHours.pcap_ISCX.csv`
- Test files: `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv, Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv, Friday-WorkingHours-Morning.pcap_ISCX.csv`

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
| Training rows | 1,905,365 |
| Test rows | 615,433 |
| Training time seconds | 63.633 |

## Metrics

| accuracy | precision | recall | f1_score | roc_auc |
| --- | --- | --- | --- | --- |
| 0.677088 | 0.995435 | 0.099821 | 0.181446 | 0.781619 |

## Confusion Matrix

Labels are ordered `[0, 1]`, where `0=BENIGN` and `1=ATTACK`.

|  | Predicted 0 | Predicted 1 |
|---|---:|---:|
| Actual 0 | 394676 | 101 |
| Actual 1 | 198630 | 22026 |

## Class Distribution

| split | binary_label | meaning | count | percentage |
| --- | --- | --- | --- | --- |
| train | 0 | BENIGN | 1700280 | 89.236446 |
| train | 1 | ATTACK | 205085 | 10.763554 |
| test | 0 | BENIGN | 394777 | 64.146219 |
| test | 1 | ATTACK | 220656 | 35.853781 |

## Observations

- This split is stricter than random row splitting because Friday attack scenarios are held out entirely from training.
- A performance drop relative to the random split is expected if row-level random splitting was benefiting from file/day-specific traffic similarity.
- This result is a better research-integrity check for generalization than the random split alone.
