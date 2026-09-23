# Model Comparison

## Metrics

| model | accuracy | precision | recall | f1_score | roc_auc |
| --- | --- | --- | --- | --- | --- |
| Random Forest - Random Split | 0.998527 | 0.996627 | 0.994645 | 0.995635 | 0.999771 |
| Random Forest - Day-Aware Split | 0.677088 | 0.995435 | 0.099821 | 0.181446 | 0.781619 |
| XGBoost - Random Split | 0.999170 | 0.995601 | 0.999499 | 0.997546 | 0.999982 |
| XGBoost - Day-Aware Split | 0.771359 | 0.999101 | 0.362623 | 0.532115 | 0.788955 |

## Notes

- Random split results measure row-level stratified test performance.
- Day-aware results test generalization to held-out Friday traffic.
- The day-aware split is the stronger research-integrity signal for deployment-like generalization.
