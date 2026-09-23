# TrustSecAI Week 1 Implementation Plan

## Week 1 Boundary

Week 1 should deliver the first IDS and explainability foundation only:

1. Dataset analysis
2. Dataset preprocessing
3. IDS training pipeline
4. Baseline model evaluation
5. SHAP integration

Do not start Neo4j, GraphRAG, LLM fine-tuning, classifier-LLM agreement analysis, or attack-chain prediction in Week 1. ATT&CK, CAPEC, and NVD should remain documented future context sources.

## Recommended IDS Strategy

### Primary Dataset

Use `Datasets/CICIDS-2017/` as the only Week 1 model-training dataset.

CICIDS2017 contains 2,830,743 rows, 78 flow features, and one label column. It has strong class imbalance and a few quality issues that must be handled before modeling.

### Target Definitions

Build two targets:

- Binary IDS target: `BENIGN` vs `ATTACK`
- Multiclass IDS target: original attack class labels after normalization

Recommended order:

1. Implement and validate binary classification first.
2. Add multiclass classification once the preprocessing pipeline and evaluation harness are stable.

Reasoning:

- Binary classification gives a fast, defensible first IDS baseline.
- Rare multiclass labels such as `Heartbleed`, `Infiltration`, and `Web Attack - Sql Injection` are too small for stable early conclusions.
- The final architecture needs attack type, confidence, and SHAP features; binary output is useful, but multiclass output will be needed later for richer incident context.

## Train/Validation/Test Strategy

### Baseline Split

Use a stratified split over the cleaned combined CICIDS dataset:

- Train: 70%
- Validation: 15%
- Test: 15%

Requirements:

- Stratify by label for binary and multiclass experiments.
- Use a fixed random seed.
- Save split metadata.
- Ensure preprocessing is fit only on the training split.

### Robustness Split

After the first baseline, add a day/file-aware holdout experiment:

- Train on a subset of days/files.
- Test on held-out attack days/files.

Reasoning:

- CICIDS traffic is organized by day and attack scenario.
- Random splits can leak collection-specific patterns and overestimate real-world generalization.
- A file-aware holdout gives a better SOC-style estimate of whether the model generalizes beyond memorized traffic sessions.

### Rare-Class Handling

For multiclass evaluation:

- Keep rare labels in the test set if possible.
- Report rare classes separately.
- Do not oversample the validation or test set.
- Consider grouping ultra-rare classes into `Other Attack` only as an experimental comparison, not as the canonical label set.

## Preprocessing Pipeline

Recommended steps:

1. Load all CICIDS CSV files.
2. Strip whitespace from column names.
3. Make duplicate columns unique, especially `Fwd Header Length`.
4. Normalize labels:
   - `BENIGN`
   - `DDoS`
   - `PortScan`
   - `Bot`
   - `Infiltration`
   - `FTP-Patator`
   - `SSH-Patator`
   - `DoS GoldenEye`
   - `DoS Hulk`
   - `DoS Slowhttptest`
   - `DoS slowloris`
   - `Heartbleed`
   - `Web Attack - Brute Force`
   - `Web Attack - XSS`
   - `Web Attack - Sql Injection`
5. Convert all feature columns to numeric.
6. Replace `Infinity`, `Inf`, `-Infinity`, `-Inf`, and parse failures with missing values.
7. Drop rows with missing/non-finite values for the initial baseline.
8. Remove exact duplicate rows if present, while logging counts.
9. Create binary and multiclass label encoders.
10. Save preprocessing metadata and label mappings.

### Missing and Non-Finite Values

Initial recommendation:

- Drop rows with invalid feature values.

Reasoning:

- The observed invalid-row count is tiny compared with 2.83 million total rows.
- Dropping avoids introducing imputation behavior before the first baseline is understood.

Follow-up experiment:

- Compare median imputation for rare attack preservation.

### Feature Engineering Strategy

Initial model features:

- Use the original numeric CICIDS flow features after cleaning.
- Avoid heavy feature engineering before the first baseline.

Recommended light feature work:

- Preserve rate, count, byte, duration, IAT, flag, active, and idle feature groups.
- Optionally remove one duplicate `Fwd Header Length` column if both duplicates are identical.
- Optionally remove constant or near-constant features after profiling.
- Do not encode labels into features.
- Do not use file name or day as a model feature.

Reasoning:

- CICIDS features are already engineered network-flow features.
- Tree-based models generally learn nonlinear interactions without manual scaling or polynomial features.
- Keeping features close to the source dataset makes SHAP explanations easier to interpret.

## Class Imbalance Handling

Required:

- Use stratified splits.
- Use class-weighted baselines where available.
- Report macro-averaged metrics.
- Inspect per-class recall and confusion matrix.

Random Forest:

- Use `class_weight='balanced'` or `balanced_subsample`.

XGBoost:

- For binary classification, use `scale_pos_weight` if treating attack as the positive class, but be careful because attacks are not the minority when grouped by all attack types versus benign in this dataset.
- For multiclass classification, use sample weights derived from inverse class frequency.

Sampling:

- Do not oversample before splitting.
- If oversampling is needed later, apply it only to the training split.
- Avoid naive SMOTE on all classes at first because rare classes with tens of samples may produce unrealistic synthetic traffic.

## Normalization and Scaling

Random Forest:

- Scaling is not required.

XGBoost:

- Scaling is not required for tree boosters.

SHAP:

- Scaling is not required if explaining tree models with `TreeExplainer`.

Recommendation:

- Do not standardize features for the first Random Forest/XGBoost baselines.
- Save raw feature names and units for explainability.
- If a future linear or neural model is added, introduce a separate scaling pipeline.

## Baseline Models

### Random Forest

Strengths:

- Strong baseline for tabular IDS features.
- Handles nonlinear feature interactions.
- Minimal preprocessing requirements.
- Supports class weights.
- Easy to train and debug.
- SHAP `TreeExplainer` support is mature.
- Good first model for explainability and project demonstration.

Weaknesses:

- Large forests can be memory-heavy on 2.83 million rows.
- Probability calibration may be imperfect.
- May underperform tuned gradient boosting.

### XGBoost

Strengths:

- Often stronger than Random Forest on tabular data.
- Handles nonlinear interactions and feature sparsity well.
- Supports sample weighting.
- Efficient prediction and strong ranking performance.
- SHAP support is excellent for tree models.

Weaknesses:

- Adds dependency and environment setup risk.
- More hyperparameters to tune.
- Multiclass imbalance needs careful sample weighting.
- Can overfit if tuned aggressively without robust validation.

### Which to Implement First

Implement Random Forest first.

Reasoning:

- It is simpler and lower risk for the first Week 1 baseline.
- It can use scikit-learn only, which is likely already needed for preprocessing and metrics.
- It gives fast feature importance and SHAP compatibility.
- It establishes a reliable pipeline before introducing XGBoost-specific dependencies and tuning.

Then implement XGBoost as the second baseline once the preprocessing and evaluation pipeline are stable.

Expected model sequence:

1. Random Forest binary classifier.
2. Random Forest multiclass classifier.
3. XGBoost binary classifier.
4. XGBoost multiclass classifier.

## Evaluation Metrics

Required metrics:

- Accuracy, reported but not used as the primary metric.
- Balanced accuracy.
- Macro precision, recall, and F1.
- Weighted precision, recall, and F1.
- Per-class precision, recall, F1, and support.
- Confusion matrix.
- ROC-AUC for binary classification.
- PR-AUC for binary classification.
- Top-k accuracy for multiclass classification, if class probabilities are used downstream.

Primary decision metrics:

- Binary: macro F1, balanced accuracy, attack recall, false-positive rate.
- Multiclass: macro F1, per-class recall, confusion matrix.

SOC-oriented checks:

- False positives on benign traffic.
- Missed attacks by class.
- Confidence calibration quality.
- Whether rare attacks are consistently missed.

## SHAP Integration Plan

Goal:

- Produce local explanations for individual IDS predictions that can later be passed to the AI Security Analyst stage.

Recommended approach:

1. Start with the Random Forest model.
2. Use SHAP `TreeExplainer`.
3. Generate explanations on a representative validation/test sample, not the full 2.83 million rows.
4. Save global SHAP summaries:
   - top features overall
   - top features per class where feasible
5. Save local SHAP outputs for selected incidents:
   - predicted label
   - confidence
   - top positive features
   - top negative features
   - feature values
6. Define a compact JSON schema for later LLM input.

Suggested local explanation schema:

```json
{
  "sample_id": "...",
  "predicted_label": "PortScan",
  "confidence": 0.91,
  "top_features": [
    {
      "name": "Destination Port",
      "value": 80,
      "shap_value": 0.14,
      "direction": "supports_prediction"
    }
  ]
}
```

SHAP risks:

- Full-dataset SHAP can be slow and memory-heavy.
- Multiclass SHAP output is larger than binary output.
- Feature names must be stable before explanations are generated.

Mitigation:

- Use sampled SHAP explanation sets.
- Keep a reproducible sample seed.
- Store explanation artifacts separately from model artifacts.

## Recommended Folder and File Structure

Create this structure after the analysis/documentation phase:

```text
TrustSecAI/
├── Datasets/
├── Docs/
├── reports/
│   ├── dataset_analysis.md
│   └── week1_implementation_plan.md
├── src/
│   ├── config/
│   │   └── paths.py
│   ├── data/
│   │   ├── load_cicids.py
│   │   └── preprocess_cicids.py
│   ├── models/
│   │   ├── train_random_forest.py
│   │   ├── train_xgboost.py
│   │   └── evaluate.py
│   ├── explainability/
│   │   └── shap_explain.py
│   └── utils/
│       └── logging.py
├── notebooks/
│   └── 01_cicids_eda.ipynb
├── models/
│   ├── random_forest/
│   └── xgboost/
└── artifacts/
    ├── processed/
    ├── metrics/
    └── shap/
```

If the project should avoid creating `artifacts/`, the same subfolders can be placed under `reports/outputs/`, but separating generated artifacts from human-written reports is cleaner.

## Implementation Tasks

### Phase 1: Reproducible Data Audit

- Create a script to profile CICIDS files.
- Recompute exact missing/non-finite counts.
- Save label distributions to `reports/`.
- Verify duplicate feature behavior.

Deliverables:

- `reports/cicids_profile.csv`
- `reports/cicids_label_distribution.csv`

### Phase 2: Preprocessing

- Implement CICIDS loader.
- Normalize headers and labels.
- Clean invalid numeric values.
- Create binary and multiclass targets.
- Save cleaned feature matrix and labels.

Deliverables:

- Cleaned dataset artifacts.
- Preprocessing metadata.
- Label mapping JSON.

### Phase 3: Baseline Random Forest

- Train binary Random Forest.
- Evaluate on validation and test sets.
- Save model and metrics.
- Train multiclass Random Forest after binary baseline is validated.

Deliverables:

- Random Forest model artifact.
- Metrics report.
- Confusion matrices.

### Phase 4: XGBoost Comparison

- Add XGBoost only after Random Forest pipeline works.
- Use the same train/validation/test splits.
- Compare metrics, training time, explainability quality, and operational complexity.

Deliverables:

- XGBoost model artifact.
- RF vs XGBoost comparison report.

### Phase 5: SHAP

- Generate SHAP explanations for Random Forest.
- Produce global and local explanation artifacts.
- Validate that top features are human-readable and stable.

Deliverables:

- SHAP summary plots/data.
- Local explanation JSON examples.
- Short SHAP interpretation note in `reports/`.

## Risks

- Python execution was unavailable in the current sandbox session, so implementation may need environment validation before coding begins.
- XGBoost may not be installed locally.
- CICIDS is large enough that naive full-memory processing may be slow on limited hardware.
- Random splits may overestimate performance.
- Rare attack classes may produce unstable metrics.
- Label encoding artifacts must be fixed before any downstream mapping.

## Best-Practice Recommendations

- Keep a fixed random seed and save split indices.
- Do not tune on the test set.
- Prefer macro metrics over accuracy for model selection.
- Treat SHAP explanations as part of the model contract because later TrustSecAI components depend on them.
- Keep Week 1 artifacts versioned and reproducible.
- Add GraphRAG mapping only after the IDS labels, confidence outputs, and SHAP schema are stable.

## Immediate Next Action

The next implementation step should be a small, reproducible CICIDS profiling and preprocessing script. It should not train a model until it has produced and saved:

- cleaned schema metadata
- exact label distribution
- exact invalid-value counts
- normalized label mapping
- train/validation/test split definition

