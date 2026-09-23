# Generalization Analysis

## Does XGBoost Improve Day-Aware Performance?

Yes, XGBoost improves day-aware F1 compared with Random Forest.

## Day-Aware Metric Deltas

Positive values mean XGBoost is higher than Random Forest.

| Metric | Delta |
|---|---:|
| Accuracy | 0.094272 |
| Precision | 0.003666 |
| Recall | 0.262803 |
| F1 | 0.350669 |
| ROC-AUC | 0.007337 |

Improved metrics: `accuracy, precision, recall, f1_score, roc_auc`.

## Primary Limitation

The primary limitation is dataset distribution shift and attack distribution mismatch, not simply Random Forest. Friday contains DDoS, PortScan, and Bot-heavy traffic, while the Monday-Thursday training set has a different attack mix. A stronger learner can help only if the training distribution contains transferable evidence for the held-out attack behavior.

## Recommendation for Week 2

Carry both Random Forest and XGBoost forward for a short final checkpoint, but use the better day-aware performer as the primary IDS candidate. The final report should present random-split results as a baseline and day-aware results as the core generalization finding.

## Comparison Table

| model | accuracy | precision | recall | f1_score | roc_auc |
| --- | --- | --- | --- | --- | --- |
| Random Forest - Random Split | 0.998527 | 0.996627 | 0.994645 | 0.995635 | 0.999771 |
| Random Forest - Day-Aware Split | 0.677088 | 0.995435 | 0.099821 | 0.181446 | 0.781619 |
| XGBoost - Random Split | 0.999170 | 0.995601 | 0.999499 | 0.997546 | 0.999982 |
| XGBoost - Day-Aware Split | 0.771359 | 0.999101 | 0.362623 | 0.532115 | 0.788955 |

## Impact of Evaluation Strategy on IDS Performance

The Week 1 experiments show that evaluation strategy has a decisive impact on reported IDS performance. Under a stratified random split, both tree-based models can see highly similar traffic patterns across training and test partitions. This produces very high scores and is useful as a pipeline sanity check, but it is not a sufficient estimate of real-world generalization.

The day-aware split is stricter because Friday traffic is held out entirely while the model trains on Monday through Thursday. This exposes a major generalization challenge: attack families and traffic patterns are not evenly distributed across capture days. A model can perform well on random rows yet fail to recall attacks from a held-out day if those attack behaviors were weakly represented or absent during training.

For TrustSecAI, this result is important rather than discouraging. The framework should not only detect attacks; it should communicate uncertainty and contextual limits. Week 2 should therefore carry forward the model that best balances random-split strength with day-aware recall, while reporting day-aware validation as the more honest security evaluation. Random split metrics can remain as a baseline, but final claims should emphasize generalization under distribution shift.
