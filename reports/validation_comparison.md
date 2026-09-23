# Validation Comparison

## Metrics

| evaluation | accuracy | precision | recall | f1_score | roc_auc |
| --- | --- | --- | --- | --- | --- |
| Random Stratified Split | 0.998527 | 0.996627 | 0.994645 | 0.995635 | 0.999771 |
| Day-Aware Split | 0.677088 | 0.995435 | 0.099821 | 0.181446 | 0.781619 |

## Performance Difference

- F1 delta, day-aware minus random: `-0.814189`
- Recall delta, day-aware minus random: `-0.894824`

## Interpretation

The day-aware split shows a substantial performance drop. This suggests the random split likely overestimated generalization because records from the same capture days and attack scenarios were distributed across train and test.

## Potential Leakage Discussion

The random stratified split is useful for a first sanity-check baseline, but it can place near-duplicate or same-capture traffic patterns into both training and test data. Because CICIDS2017 is organized by day and attack scenario, this can inflate reported performance.

The day-aware split is stricter because all Friday records are held out for testing. It better reflects the question: can the IDS trained on earlier days generalize to a later capture day with different attack mixes?

## Recommendation

For the final project, report both metrics:

- Use the random stratified split as the baseline comparability result.
- Use the day-aware split as the primary research-integrity generalization result.

If only one headline metric is allowed, prefer the day-aware split because it is less likely to benefit from row-level leakage.
