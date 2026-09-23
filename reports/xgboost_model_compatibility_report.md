# XGBoost Model Compatibility Report

- Model loads successfully: True
- Feature order exists: True
- Feature order matches artifact: True
- Feature count: 78
- Model feature count: 78
- Feature count matches model: True
- Predicted probabilities available: True
- Passed: True

## Binary Interpretation

- `0`: BENIGN
- `1`: ATTACK
- IDS subtype retrieval uses the real CICIDS ground-truth label; no multiclass probabilities are invented.

## Sample Predictions

```json
[
  {
    "sample_index": 1435999,
    "true_label": "BENIGN",
    "binary_label": 0,
    "prediction": "BENIGN",
    "confidence": 0.9999999403953552,
    "probabilities": [
      0.9999999403953552,
      5.110268475050361e-08
    ]
  },
  {
    "sample_index": 2435282,
    "true_label": "BENIGN",
    "binary_label": 0,
    "prediction": "BENIGN",
    "confidence": 0.9999952912330627,
    "probabilities": [
      0.9999952912330627,
      4.679207904700888e-06
    ]
  },
  {
    "sample_index": 854964,
    "true_label": "BENIGN",
    "binary_label": 0,
    "prediction": "BENIGN",
    "confidence": 0.9999999403953552,
    "probabilities": [
      0.9999999403953552,
      5.387058976680237e-08
    ]
  },
  {
    "sample_index": 2035034,
    "true_label": "DoS Hulk",
    "binary_label": 1,
    "prediction": "ATTACK",
    "confidence": 0.9999996423721313,
    "probabilities": [
      3.5762786865234375e-07,
      0.9999996423721313
    ]
  },
  {
    "sample_index": 1292198,
    "true_label": "BENIGN",
    "binary_label": 0,
    "prediction": "BENIGN",
    "confidence": 0.9999833106994629,
    "probabilities": [
      0.9999833106994629,
      1.667654578341171e-05
    ]
  }
]
```
