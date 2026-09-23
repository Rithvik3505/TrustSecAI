# TrustSecAI LLM Dataset Inventory

## Scope

This inventory covers the local data available for designing a supervised fine-tuning corpus for the TrustSecAI LLM phase. It is a design document only. No fine-tuning data, LoRA code, or model-training artifacts are generated here.

Primary sources inspected:

- `Datasets/CICIDS-2017/`
- `Datasets/ATTACK/attack-stix-data-master/`
- `Datasets/CAPEC/`
- `Datasets/NVD/`
- Derived TrustSecAI artifacts under `artifacts/`
- Existing project reports under `reports/`

## Summary

| Dataset | Format | Main Use For Fine-Tuning | Suitability |
|---|---|---|---|
| CICIDS2017 | CSV flow records | Incident inputs, IDS label grounding, SHAP-backed reasoning examples | Medium |
| MITRE ATT&CK | STIX 2.1 JSON | Technique/tactic/mitigation/detection knowledge | High |
| CAPEC | CSV dictionaries | Attack-pattern mechanics and adversary behavior descriptions | High |
| CWE | Derived from CAPEC/NVD references | Weakness bridge between CAPEC and CVE | Medium |
| NVD/CVE | NVD JSON 2.0 | Vulnerability context, CVSS severity, affected products, references | Medium |
| SHAP artifacts | JSON/CSV/PNG | Explainability-aware analyst reasoning | High |
| Graph retrieval artifacts | Structured JSON | Best source for synthetic instruction-response generation | Very high |
| IDS label mapping | JSON | Label-to-ATT&CK grounding | High |

## CICIDS2017

### Source

Location: `Datasets/CICIDS-2017/`

Files:

- `Monday-WorkingHours.pcap_ISCX.csv`
- `Tuesday-WorkingHours.pcap_ISCX.csv`
- `Wednesday-workingHours.pcap_ISCX.csv`
- `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
- `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
- `Friday-WorkingHours-Morning.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`

Derived cleaned source:

- `artifacts/processed/cleaned_cicids.parquet`
- `artifacts/processed/cleaned_cicids_sample.csv`

### Purpose

CICIDS2017 is the primary IDS dataset. It should not be used as a natural-language knowledge source. Its value for LLM fine-tuning is as structured incident evidence:

- IDS prediction label
- classifier confidence
- binary/multiclass ground truth
- source file/day
- top SHAP features
- graph retrieval context generated from the prediction

### Format

Raw CSV files with 79 columns: 78 flow features plus `Label`. The cleaned parquet preserves `label`, `binary_label`, and `source_file`.

### Important Fields

- `label`
- `binary_label`
- `source_file`
- network-flow features such as `Destination Port`, `Flow Duration`, packet counts, IAT features, TCP flag counts, byte/packet rates, active/idle timing

### Quality

Known issues already handled by preprocessing:

- duplicate `Fwd Header Length` feature name
- non-finite rate values
- missing/blank rows
- severe class imbalance
- label encoding artifacts in web attack classes
- file/day distribution shift

### Suitability for Fine-Tuning

Suitability is medium.

CICIDS2017 is useful for generating incident-style inputs, but it is not sufficient for training analyst-quality outputs by itself. The LLM should never learn to infer full threat intelligence from raw flow features alone. CICIDS-derived examples should always be paired with SHAP explanations and retrieved graph context.

Recommended use:

- Build synthetic SFT inputs from IDS prediction + confidence + SHAP top features + Graph Retrieval JSON.
- Avoid using raw 78-feature rows directly unless summarized.
- Preserve `source_file` metadata to study bias and distribution shift.

## MITRE ATT&CK

### Source

Location: `Datasets/ATTACK/attack-stix-data-master/`

Primary local source:

- `enterprise-attack/enterprise-attack.json`

The local Enterprise ATT&CK bundle contains 25,843 STIX objects.

### Purpose

ATT&CK is the behavioral spine of TrustSecAI. It should anchor technique identification, tactic explanation, mitigation selection, detection guidance, adversary group/tool/malware context, and later agreement analysis.

### Format

STIX 2.1 JSON bundle.

### Important Fields

Common:

- `type`
- `id`
- `created`
- `modified`
- `name`
- `description`
- `external_references`
- `revoked`
- `x_mitre_deprecated`

Technique-specific:

- ATT&CK external ID
- `kill_chain_phases`
- `x_mitre_platforms`
- `x_mitre_is_subtechnique`
- `x_mitre_detection`
- `x_mitre_data_sources`

Relationship-specific:

- `relationship_type`
- `source_ref`
- `target_ref`
- `description`

### Quality

Strengths:

- well-structured, high-quality threat behavior taxonomy
- strong provenance through STIX IDs and external references
- clear relationships among techniques, mitigations, groups, malware, tools, campaigns, and detections

Limitations:

- not written as SOC incident reports
- contains revoked and deprecated objects that must be filtered
- some descriptions are broad and require incident-specific context

### Suitability for Fine-Tuning

Suitability is high for knowledge and instruction examples.

Recommended uses:

- ATT&CK mapping explanations
- technique/tactic summaries
- mitigation recommendations
- detection guidance
- adversary context with careful uncertainty wording

Do not train the model to treat group/tool/malware relationships as attribution. They are evidence of observed technique usage, not proof that a current incident involves that actor.

## CAPEC

### Source

Location: `Datasets/CAPEC/`

Files:

- `Comprehensive Dictionary/2000.csv`
- `Attack Related Patterns/658.csv`
- `Domains of Attack/3000.csv`
- `Mechanisms of Attack/1000.csv`

The comprehensive dictionary contains 615 rows.

### Purpose

CAPEC provides attack-pattern mechanics that complement ATT&CK. It is useful for explaining how an attack may be performed, what prerequisites may exist, indicators, consequences, and pattern-level mitigations.

### Format

CSV with 20 columns.

### Fields

- `'ID`
- `Name`
- `Abstraction`
- `Status`
- `Description`
- `Alternate Terms`
- `Likelihood Of Attack`
- `Typical Severity`
- `Related Attack Patterns`
- `Execution Flow`
- `Prerequisites`
- `Skills Required`
- `Resources Required`
- `Indicators`
- `Consequences`
- `Mitigations`
- `Example Instances`
- `Related Weaknesses`
- `Taxonomy Mappings`
- `Notes`

### Quality

Strengths:

- directly useful for explaining attacker workflow and consequences
- includes ATT&CK taxonomy mappings
- includes related CWE references

Limitations:

- some fields are verbose, semi-structured, or blank
- taxonomy mappings are incomplete
- severity and likelihood are sometimes missing
- repeated alternate CAPEC views can duplicate content from the comprehensive dictionary

### Suitability for Fine-Tuning

Suitability is high for attack-mechanics and mitigation reasoning.

Recommended uses:

- threat assessment outputs
- attack pattern explanation
- prerequisite and consequence summaries
- CAPEC-to-ATT&CK bridge examples

Avoid using every CAPEC alternate view as separate training content unless deduplicated against the comprehensive dictionary.

## CWE

### Source

No standalone CWE dictionary was found in `Datasets/`. CWE nodes are created as a bridge from CAPEC and NVD references.

Sources:

- CAPEC `Related Weaknesses`
- NVD `weaknesses`
- Neo4j graph-derived `CWE` nodes

### Purpose

CWE connects attack patterns to vulnerability records:

```text
CAPECPattern -> CWE <- CVE
```

### Format

Derived graph nodes and relationship metadata, not a complete local CWE catalog.

### Fields

Available fields are minimal:

- `cwe_id`
- source/provenance fields

### Quality

Strengths:

- useful structural bridge between CAPEC and CVE
- avoids unsupported direct CAPEC-to-CVE claims

Limitations:

- no local CWE descriptions unless added later from an official CWE source
- weak standalone language content

### Suitability for Fine-Tuning

Suitability is medium.

Use CWE mostly as metadata and bridge evidence. Do not ask the fine-tuned model to produce rich CWE explanations unless a full CWE dictionary is added later.

## NVD/CVE

### Source

Location: `Datasets/NVD/`

Files:

- `nvdcve-2.0-2023.json`
- `nvdcve-2.0-2024.json`
- `nvdcve-2.0-2025.json`
- `nvdcve-2.0-2026.json`
- `nvdcve-2.0-modified.json`
- `nvdcve-2.0-recent.json`

Local counts:

| File | CVE Records |
|---|---:|
| `nvdcve-2.0-2023.json` | 10 |
| `nvdcve-2.0-2024.json` | 4 |
| `nvdcve-2.0-2025.json` | 56 |
| `nvdcve-2.0-2026.json` | 1,373 |
| `nvdcve-2.0-modified.json` | 1,170 |
| `nvdcve-2.0-recent.json` | 997 |

### Purpose

NVD/CVE provides vulnerability intelligence:

- CVE descriptions
- CVSS severity/base score/vector
- affected product configurations
- CWE weaknesses
- references

### Format

NVD CVE JSON 2.0.

### Fields

Common CVE fields:

- `id`
- `sourceIdentifier`
- `published`
- `lastModified`
- `vulnStatus`
- `descriptions`
- `metrics`
- `weaknesses`
- `configurations`
- `references`
- `cveTags`

### Quality

Strengths:

- structured vulnerability facts
- useful severity signals
- strong external references

Limitations:

- local year files are partial, especially 2023-2025
- 2026 records may include many entries without CVSS metrics
- modified/recent feeds can duplicate records from year feeds
- rejected, reserved, or unscored records require filtering
- CVE relevance is often inferred through CWE, so it should be framed as candidate vulnerability context unless asset evidence exists

### Suitability for Fine-Tuning

Suitability is medium.

Use NVD for vulnerability-focused instruction examples and severity summarization, but avoid over-weighting it. CVE context should be grounded in the retrieved graph and should preserve uncertainty.

## SHAP Explainability Artifacts

### Source

Location: `artifacts/shap/`

Files:

- `global_feature_importance.csv`
- `sample_explanations.json`
- `shap_summary_bar.png`
- `shap_summary_beeswarm.png`

### Purpose

SHAP artifacts connect model predictions to feature-level evidence.

### Suitability for Fine-Tuning

Suitability is high when paired with IDS predictions and graph context.

Recommended uses:

- analyst reasoning examples
- classifier explanation summaries
- confidence/uncertainty-aware responses
- evidence sections in incident reports

Do not use image plots directly for SFT. Use structured JSON/CSV values.

## Graph Retrieval Artifacts

### Source

Location: `artifacts/retrieval/`

Files:

- `PortScan.json`
- `FTP_Patator.json`
- `Bot.json`
- `DDoS.json`
- `Web_Attack___Sql_Injection.json`
- `validation_summary.json`

### Purpose

These are the most important sources for synthetic SFT design because they already combine:

- IDS prediction
- classifier confidence placeholder
- ATT&CK technique and tactic
- mitigations
- CAPEC patterns
- CWE/CVE/product/reference context
- groups/tools/malware
- detection guidance
- provenance

### Suitability for Fine-Tuning

Suitability is very high.

These JSON objects should become the canonical input format for future LLM instruction examples. The final corpus should teach the model to transform this structured context into controlled analyst outputs while citing evidence and preserving uncertainty.

## Additional Cybersecurity Datasets

No additional standalone cybersecurity datasets were found under `Datasets/` beyond CICIDS2017, ATT&CK, CAPEC, and NVD. The project also contains derived graph, SHAP, model metric, and retrieval artifacts that should be used for corpus construction.

