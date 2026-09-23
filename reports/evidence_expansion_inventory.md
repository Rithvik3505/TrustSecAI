# Evidence Expansion Inventory

```json
{
  "candidate_samples_scanned": 121,
  "selected_base_contexts": 121,
  "base_contexts_per_ids_label": {
    "DDoS": 25,
    "PortScan": 25,
    "Bot": 25,
    "Web Attack - Sql Injection": 21,
    "FTP-Patator": 25
  },
  "confidence_band_distribution": {
    "high": 111,
    "medium": 8,
    "low": 2
  },
  "source_file_distribution": {
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": 25,
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": 25,
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": 25,
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": 21,
    "Tuesday-WorkingHours.pcap_ISCX.csv": 25
  },
  "shap_coverage_per_label": {
    "DDoS": 25,
    "PortScan": 25,
    "Bot": 25,
    "Web Attack - Sql Injection": 21,
    "FTP-Patator": 25
  },
  "distinct_shap_top_feature_patterns_per_label": {
    "DDoS": 5,
    "PortScan": 6,
    "Bot": 10,
    "Web Attack - Sql Injection": 15,
    "FTP-Patator": 8
  },
  "graph_coverage_per_label": {
    "DDoS": {
      "has_retrieval": true,
      "contexts": 25
    },
    "PortScan": {
      "has_retrieval": true,
      "contexts": 25
    },
    "Bot": {
      "has_retrieval": true,
      "contexts": 25
    },
    "Web Attack - Sql Injection": {
      "has_retrieval": true,
      "contexts": 21
    },
    "FTP-Patator": {
      "has_retrieval": true,
      "contexts": 25
    }
  },
  "cve_present_count": 50,
  "cve_absent_count": 71,
  "direct_provenance_count": 71,
  "mixed_inferred_provenance_count": 50,
  "unavailable_evidence_not_synthesized": [
    "asset exposure",
    "actor attribution",
    "multiclass probabilities from binary IDS model"
  ]
}
```
