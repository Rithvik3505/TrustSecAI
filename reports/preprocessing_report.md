# CICIDS2017 Preprocessing Report

## Summary

| Metric | Value |
|---|---:|
| Rows before cleaning | 2,830,743 |
| Rows after cleaning | 2,520,798 |
| Rows removed | 309,945 |
| Rows removed for invalid/missing/non-finite values | 2,867 |
| Duplicate rows before cleaning | 307,078 |
| Duplicate rows removed | 307,078 |
| Columns before cleaning | 80 |
| Columns after cleaning | 81 |
| Total missing feature values before invalid-row removal | 5,734 |
| Total non-finite feature values before replacement | 4,376 |

## Invalid Row Reasons

| Reason | Rows |
|---|---:|
| Missing feature value | 2,867 |
| Non-finite feature value | 2,867 |
| Unknown label | 0 |

## Label Distribution After Cleaning

| label | count | percentage |
| --- | --- | --- |
| BENIGN | 2095057 | 83.110864 |
| DoS Hulk | 172846 | 6.856797 |
| DDoS | 128014 | 5.078313 |
| PortScan | 90694 | 3.597829 |
| DoS GoldenEye | 10286 | 0.408045 |
| FTP-Patator | 5931 | 0.235283 |
| DoS slowloris | 5385 | 0.213623 |
| DoS Slowhttptest | 5228 | 0.207395 |
| SSH-Patator | 3219 | 0.127698 |
| Bot | 1948 | 0.077277 |
| Web Attack - Brute Force | 1470 | 0.058315 |
| Web Attack - XSS | 652 | 0.025865 |
| Infiltration | 36 | 0.001428 |
| Web Attack - Sql Injection | 21 | 0.000833 |
| Heartbleed | 11 | 0.000436 |

## Top Missing-Value Features Before Cleaning

| feature | dtype | missing_count | non_finite_count | source_dtype |
| --- | --- | --- | --- | --- |
| Flow Packets/s | float64 | 2867 | 2867 | float64 |
| Flow Bytes/s | float64 | 2867 | 1509 | float64 |
| Total Fwd Packets | int64 | 0 | 0 | int64 |
| Total Backward Packets | int64 | 0 | 0 | int64 |
| Destination Port | int64 | 0 | 0 | int64 |
| Flow Duration | int64 | 0 | 0 | int64 |
| Fwd Packet Length Max | int64 | 0 | 0 | int64 |
| Fwd Packet Length Min | int64 | 0 | 0 | int64 |
| Fwd Packet Length Mean | float64 | 0 | 0 | float64 |
| Fwd Packet Length Std | float64 | 0 | 0 | float64 |

## Unknown Labels

```json
{}
```

## Output Files

- Cleaned parquet: `C:\Users\LENOVO\WORK\Projects\TrustSecAI\artifacts\processed\cleaned_cicids.parquet`
- Cleaned sample CSV: `C:\Users\LENOVO\WORK\Projects\TrustSecAI\artifacts\processed\cleaned_cicids_sample.csv`
- Feature profile CSV: `reports/cicids_profile.csv`
- Label distribution CSV: `reports/cicids_label_distribution.csv`

## Assumptions

- CICIDS2017 is the only dataset used for Week 1 preprocessing.
- Label values are normalized to the approved vocabulary from the Week 1 plan.
- `BENIGN` maps to `binary_label=0`; every approved attack label maps to `binary_label=1`.
- Non-finite values are treated as invalid and removed for the first baseline dataset.
- Rows with missing feature values are removed for the first baseline dataset.
- Duplicate rows are removed after invalid rows are removed.
- The original multiclass label is preserved in the `label` column.
- A `source_file` column is retained for auditability but should not be used as a model feature.
