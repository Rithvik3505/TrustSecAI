# TrustSecAI Dataset Analysis

## Scope and Source Notes

This report covers all datasets currently present under `Datasets/` for the TrustSecAI project:

- `CICIDS-2017/`
- `ATTACK/attack-stix-data-master/`
- `CAPEC/`
- `NVD/`

The finalized TrustSecAI architecture is treated as the source of truth: CICIDS2017 supports Week 1 IDS model development; ATT&CK, CAPEC, and NVD support the later GraphRAG threat intelligence layer. Week 1 should not start Neo4j, GraphRAG, LLM fine-tuning, agreement analysis, or attack-chain prediction.

The PDF documents in `Docs/` were checked locally, but no usable PDF text extraction utility is available in this environment and the files do not expose searchable text through binary search. This analysis therefore uses the finalized project brief, the provided HLD image, and direct inspection of the dataset files.

## Executive Summary

The repository contains the expected data sources for the approved architecture. CICIDS2017 is immediately usable for Week 1 baseline IDS training after careful cleaning. The other datasets are structured threat intelligence corpora and should be staged for later knowledge-graph ingestion, not used in the first training pipeline.

Main findings:

- CICIDS2017 contains 2,830,743 flow records across 8 CSV files with 78 feature columns plus `Label`.
- CICIDS2017 is highly imbalanced: `BENIGN` is about 80.30% of records, while rare attacks such as `Heartbleed`, `Infiltration`, and `Web Attack - Sql Injection` have tens of samples or fewer.
- CICIDS2017 contains non-finite numeric values such as `Infinity`, mostly in rate columns, and some blank/invalid rows. These must be cleaned before model training.
- CICIDS2017 has a duplicate feature name: `Fwd Header Length` appears twice. Column names should be normalized and made unique.
- ATT&CK is available as STIX 2.1 JSON, including Enterprise ATT&CK v19.1/latest with attack patterns, tactics, mitigations, relationships, groups, malware, tools, and detection objects.
- CAPEC CSVs include attack patterns and ATT&CK taxonomy mappings, but many rows have blank taxonomy mapping and severity fields.
- NVD JSON feeds contain CVEs, CVSS metrics, weaknesses, configurations, and references, but also include rejected and unscored records that need filtering.

## CICIDS2017

### Purpose

CICIDS2017 is the primary IDS training dataset for Week 1. It provides network-flow features and labels for benign and malicious traffic. It should be used to train and evaluate the baseline intrusion detection classifier that feeds the explainability stage.

### Files

| File | Rows | Columns | Missing/blank rows | Non-finite rows |
|---|---:|---:|---:|---:|
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 225,745 | 79 | 4 | 34 |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 286,467 | 79 | 15 | 371 |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 191,033 | 79 | 28 | 122 |
| `Monday-WorkingHours.pcap_ISCX.csv` | 529,918 | 79 | 64 | 437 |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 288,602 | 79 | 18 | 207 |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 170,366 | 79 | 20 | 135 |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | 445,909 | 79 | 201 | 264 |
| `Wednesday-workingHours.pcap_ISCX.csv` | 692,703 | 79 | about 1,008 | 1,297 |

The Wednesday missing-row count was collected using a faster pattern scan because a full per-cell scan exceeded the local command timeout. It should be recomputed exactly in the implementation pipeline.

### Schema

Each CSV contains 78 numeric flow features and one target column, `Label`.

Important feature groups:

- Flow identity/volume: `Destination Port`, `Flow Duration`, `Total Fwd Packets`, `Total Backward Packets`, `Total Length of Fwd Packets`, `Total Length of Bwd Packets`
- Packet length statistics: `Fwd Packet Length Max`, `Fwd Packet Length Min`, `Fwd Packet Length Mean`, `Fwd Packet Length Std`, corresponding backward-packet fields, packet length mean/std/variance
- Flow rates: `Flow Bytes/s`, `Flow Packets/s`, `Fwd Packets/s`, `Bwd Packets/s`
- Inter-arrival timing: `Flow IAT Mean`, `Flow IAT Std`, `Flow IAT Max`, `Flow IAT Min`, `Fwd IAT *`, `Bwd IAT *`
- TCP flags: `FIN Flag Count`, `SYN Flag Count`, `RST Flag Count`, `PSH Flag Count`, `ACK Flag Count`, `URG Flag Count`, `CWE Flag Count`, `ECE Flag Count`
- Header/window/subflow features: `Fwd Header Length`, `Bwd Header Length`, `Init_Win_bytes_forward`, `Init_Win_bytes_backward`, `Subflow Fwd *`, `Subflow Bwd *`
- Activity/idle timing: `Active Mean`, `Active Std`, `Active Max`, `Active Min`, `Idle Mean`, `Idle Std`, `Idle Max`, `Idle Min`
- Target: `Label`

Schema issue:

- `Fwd Header Length` appears twice in the header. During preprocessing, duplicate feature names should be renamed deterministically, for example `Fwd Header Length` and `Fwd Header Length.1`, or one duplicate should be removed after checking whether the columns are identical.

### Labels and Class Imbalance

| Label | Count | Share |
|---|---:|---:|
| `BENIGN` | 2,273,097 | 80.3004% |
| `DoS Hulk` | 231,073 | 8.1630% |
| `PortScan` | 158,930 | 5.6144% |
| `DDoS` | 128,027 | 4.5227% |
| `DoS GoldenEye` | 10,293 | 0.3636% |
| `FTP-Patator` | 7,938 | 0.2804% |
| `SSH-Patator` | 5,897 | 0.2083% |
| `DoS slowloris` | 5,796 | 0.2048% |
| `DoS Slowhttptest` | 5,499 | 0.1943% |
| `Bot` | 1,966 | 0.0695% |
| `Web Attack - Brute Force` | 1,507 | 0.0532% |
| `Web Attack - XSS` | 652 | 0.0230% |
| `Infiltration` | 36 | 0.0013% |
| `Web Attack - Sql Injection` | 21 | 0.0007% |
| `Heartbleed` | 11 | 0.0004% |

Notes:

- The web attack labels appear in the raw file with a replacement character in the local console output. The preprocessing pipeline should normalize encoding so labels become stable ASCII values such as `Web Attack - Brute Force`, `Web Attack - XSS`, and `Web Attack - Sql Injection`.
- Rare classes are too small for reliable standalone multiclass modeling without special handling. A binary baseline is appropriate first, followed by multiclass experiments with grouped/rare-class reporting.

### Missing Values

Missing/blank values are limited but present. They should not be ignored because tree-based models and SHAP explainers can be sensitive to inconsistent preprocessing.

Recommended handling:

- Strip whitespace from all column names and label values.
- Treat empty strings, `NaN`, `nan`, `null`, and `NULL` as missing.
- Replace `Infinity`, `Inf`, `-Infinity`, and `-Inf` with missing values before imputation.
- For the first baseline, drop rows with missing or non-finite feature values because the count is small relative to total data.
- Later, compare with median imputation if preserving rare attack rows becomes important.

### Data Quality Issues

- Duplicate column name: `Fwd Header Length`.
- Non-finite values in rate features such as `Flow Bytes/s` and `Flow Packets/s`.
- Severe class imbalance.
- Very rare labels make per-class validation unstable.
- Some labels contain encoding artifacts.
- File/day-specific collection patterns can create leakage if train/test splitting is careless.
- Monday contains only benign records, so a naive random split can overstate performance.

### Recommended Preprocessing

- Load all CSVs with consistent dtypes.
- Normalize column names by stripping whitespace and making duplicates unique.
- Normalize labels to a controlled vocabulary.
- Convert all feature columns to numeric.
- Replace non-finite values with missing values.
- Drop exact duplicates if present, but record the number removed.
- Remove rows with missing/non-finite values for the initial baseline.
- Create both binary labels (`BENIGN` vs `ATTACK`) and multiclass labels.
- Use stratified splits, with an optional day/file-aware holdout as a robustness check.
- Preserve the fitted preprocessing metadata under `models/` or `artifacts/` for reproducibility.

### Potential Use Within TrustSecAI

Week 1:

- Train baseline IDS model.
- Generate model confidence values.
- Generate SHAP feature attributions.
- Provide attack type, confidence, and top features for later LLM input.

Later phases:

- Map classifier labels to ATT&CK/CAPEC concepts through a controlled mapping table.
- Provide incident-level features for GraphRAG retrieval.
- Feed classifier output and SHAP reasoning into agreement analysis.

## MITRE ATT&CK

### Purpose

MITRE ATT&CK provides adversary tactics, techniques, sub-techniques, mitigations, software, groups, tools, campaigns, data sources, detection strategies, and relationships. In TrustSecAI, this is the main structured threat-intelligence source for GraphRAG and later incident contextualization.

### Files and Format

Location: `Datasets/ATTACK/attack-stix-data-master/`

The repository contains STIX 2.1 JSON bundles for Enterprise, Mobile, and ICS ATT&CK. The current Enterprise file is:

- `enterprise-attack/enterprise-attack.json`
- Same size as `enterprise-attack-19.1.json`, indicating the latest local Enterprise release is v19.1.

### Schema

Top-level STIX bundle fields:

- `type`
- `id`
- `objects`

Important STIX object fields:

- Common: `type`, `id`, `created`, `modified`, `name`, `description`, `external_references`, `revoked`, `x_mitre_deprecated`
- Techniques: `type=attack-pattern`, `kill_chain_phases`, `x_mitre_platforms`, `x_mitre_is_subtechnique`, `x_mitre_detection`, ATT&CK ID in `external_references.external_id`
- Tactics: `type=x-mitre-tactic`
- Mitigations: `type=course-of-action`
- Relationships: `type=relationship`, `relationship_type`, `source_ref`, `target_ref`

### Local Enterprise ATT&CK Counts

| Object type | Count |
|---|---:|
| `relationship` | 21,025 |
| `x-mitre-analytic` | 1,758 |
| `attack-pattern` | 858 |
| `malware` | 729 |
| `x-mitre-detection-strategy` | 699 |
| `course-of-action` | 268 |
| `intrusion-set` | 189 |
| `x-mitre-data-component` | 109 |
| `tool` | 95 |
| `campaign` | 56 |
| `x-mitre-data-source` | 38 |
| `x-mitre-tactic` | 15 |
| Other bundle/support objects | 4 |

Active, non-revoked/non-deprecated Enterprise ATT&CK attack-pattern objects: 697.

### Important Fields

- ATT&CK technique ID, for example `T1055.011`, from `external_references.external_id`.
- Technique name and description.
- Tactic phase from `kill_chain_phases.phase_name`.
- Platform constraints from `x_mitre_platforms`.
- Detection notes from `x_mitre_detection`.
- Mitigation links via `relationship` objects pointing to `course-of-action`.

### Labels/Classes

ATT&CK is not a supervised training dataset. Its "classes" are knowledge entities:

- Tactics
- Techniques
- Sub-techniques
- Mitigations
- Groups
- Malware
- Tools
- Campaigns
- Data sources/components
- Detection strategies/analytics

### Missing Values

Missingness is object-type dependent. Not every technique has the same detection, platform, relationship, or external-reference richness. Deprecated and revoked objects are present and must be filtered or retained only with explicit versioning logic.

### Data Quality Issues

- Multiple historical versions are present. Use only the current unversioned file for initial graph ingestion unless a temporal comparison is needed.
- STIX relationships are edge records and require source/target resolution.
- Some object descriptions contain HTML-like tags and citation markers.
- ATT&CK is not directly aligned to CICIDS labels; a mapping layer is required.

### Recommended Preprocessing

- Use `enterprise-attack/enterprise-attack.json` for the first TrustSecAI knowledge graph.
- Filter or flag `revoked` and `x_mitre_deprecated` objects.
- Extract stable IDs from external references.
- Normalize relationship edges into source, relationship type, and target tables.
- Preserve source STIX IDs for traceability.
- Defer Neo4j ingestion until the GraphRAG phase.

### Potential Use Within TrustSecAI

- Retrieve likely tactics and techniques for a classifier-detected attack.
- Provide mitigations and detection guidance.
- Give the LLM structured context for security assessment generation.
- Support attack chain prediction through tactic/technique relationships in later phases.

## CAPEC

### Purpose

CAPEC provides attack-pattern knowledge, execution flows, prerequisites, consequences, mitigations, related weaknesses, and taxonomy mappings. It complements ATT&CK by describing attack patterns and exploitation mechanics.

### Files and Format

CAPEC is stored as CSV files:

| File | Rows | Status distribution |
|---|---:|---|
| `Comprehensive Dictionary/2000.csv` | 615 | Draft: 402, Stable: 154, Deprecated: 56, Usable: 2, Obsolete: 1 |
| `Attack Related Patterns/658.csv` | 177 | Draft: 112, Stable: 63, Usable: 2 |
| `Domains of Attack/3000.csv` | 559 | Draft: 402, Stable: 154, Usable: 2, Obsolete: 1 |
| `Mechanisms of Attack/1000.csv` | 559 | Draft: 402, Stable: 154, Usable: 2, Obsolete: 1 |

### Schema

Columns:

- `ID`
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

### Important Fields

- `ID`, `Name`, `Description`
- `Abstraction`, `Status`
- `Likelihood Of Attack`, `Typical Severity`
- `Execution Flow`
- `Prerequisites`
- `Indicators`
- `Consequences`
- `Mitigations`
- `Related Weaknesses`
- `Taxonomy Mappings`, especially ATT&CK mappings

### Labels/Classes

CAPEC is not an IDS training dataset. Its categorical fields include:

- Abstraction level: meta/standard/detailed patterns
- Status: draft/stable/deprecated/usable/obsolete
- Likelihood of attack
- Typical severity
- Taxonomy mappings to ATT&CK and other taxonomies

### Missing Values

Observed missingness:

| File | Blank descriptions | Blank taxonomy mappings | Blank severity |
|---|---:|---:|---:|
| `658.csv` | 0 | 0 | 21 |
| `2000.csv` | 2 | 392 | 125 |
| `3000.csv` | 2 | 336 | 70 |
| `1000.csv` | 2 | 336 | 70 |

### Data Quality Issues

- Many `Taxonomy Mappings` fields are blank, so not every CAPEC pattern can be directly joined to ATT&CK.
- Several records are deprecated or obsolete.
- Many fields encode nested content inside delimiter-heavy strings such as `::STEP`, `::TECHNIQUE`, and `::SCOPE`.
- Duplicate conceptual content exists across views of the CAPEC catalog.

### Recommended Preprocessing

- Use `Comprehensive Dictionary/2000.csv` as the primary CAPEC source.
- Treat the other CAPEC CSVs as alternate views and avoid duplicate ingestion unless their hierarchy is explicitly needed.
- Filter or flag deprecated/obsolete records.
- Parse structured strings into relation tables where useful: related patterns, execution steps, weaknesses, taxonomy mappings.
- Preserve raw text fields for retrieval and explanation.

### Potential Use Within TrustSecAI

- Provide attack-pattern context for incidents.
- Bridge classifier labels to exploit patterns and consequences.
- Enrich LLM assessments with prerequisites, indicators, consequences, and mitigations.
- Support later attack-chain reasoning by CAPEC relationships such as `ChildOf` and `CanPrecede`.

## NVD/CVE

### Purpose

NVD provides vulnerability intelligence: CVE identifiers, descriptions, CVSS scores, CWE weaknesses, affected products/configurations, references, and vulnerability status. In TrustSecAI, NVD should enrich security assessments with vulnerability context when an incident or ATT&CK/CAPEC pattern relates to exploitable software weaknesses.

### Files and Format

NVD files are JSON 2.0 feeds:

| File | CVE records | Timestamp |
|---|---:|---|
| `nvdcve-2.0-2023.json` | 10 | 2026-06-13T03:00:07.4681563 |
| `nvdcve-2.0-2024.json` | 4 | 2026-06-12T03:00:08.8883747 |
| `nvdcve-2.0-2025.json` | 56 | 2026-06-15T03:00:04.1069015 |
| `nvdcve-2.0-2026.json` | 1,373 | 2026-06-15T03:00:00.9354168 |
| `nvdcve-2.0-modified.json` | 1,170 | 2026-06-15T01:00:01.2172604 |
| `nvdcve-2.0-recent.json` | 997 | 2026-06-15T01:00:00.4404468 |

### Schema

Top-level fields:

- `version`
- `timestamp`
- `vulnerabilities`

Important CVE fields:

- `cve.id`
- `cve.sourceIdentifier`
- `cve.published`
- `cve.lastModified`
- `cve.vulnStatus`
- `cve.descriptions`
- `cve.metrics.cvssMetricV31`, `cvssMetricV30`, or `cvssMetricV2`
- `cve.weaknesses`
- `cve.configurations`
- `cve.references`

### Important Fields

- CVE ID and description.
- CVSS base score, severity, and vector string.
- CWE weaknesses.
- Affected configurations/CPEs.
- Reference URLs and tags.
- Vulnerability status.

Example observed schema:

- CVE: `CVE-2026-4775`
- Status: `Modified`
- CVSS v3.1: base score `7.8`, severity `HIGH`, vector `CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`
- Weakness: `CWE-190`
- References: 24

### Labels/Classes

NVD is not supervised IDS training data. Useful categorical values include:

- Severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, and `UNSCORED`
- Status: `Analyzed`, `Modified`, `Awaiting Analysis`, `Received`, `Undergoing Analysis`, `Deferred`, `Rejected`
- Weakness IDs such as CWE values

Severity distribution by file:

| File | Critical | High | Medium | Low | Unscored |
|---|---:|---:|---:|---:|---:|
| `nvdcve-2.0-2023.json` | 3 | 1 | 6 | 0 | 0 |
| `nvdcve-2.0-2024.json` | 0 | 0 | 3 | 1 | 0 |
| `nvdcve-2.0-2025.json` | 1 | 21 | 24 | 1 | 9 |
| `nvdcve-2.0-2026.json` | 89 | 559 | 379 | 33 | 313 |
| `nvdcve-2.0-modified.json` | 77 | 474 | 378 | 37 | 204 |
| `nvdcve-2.0-recent.json` | 68 | 397 | 301 | 31 | 200 |

### Missing Values

Missingness is significant for records that are unscored, recently received, deferred, or rejected. Rejected records may have no descriptions, metrics, weaknesses, configurations, or references.

### Data Quality Issues

- The local feeds are partial snapshots, not a complete historical NVD mirror.
- `recent` and `modified` feeds overlap with year files and can introduce duplicates.
- Rejected CVEs should be filtered or clearly marked.
- Some CVEs lack CVSS metrics.
- Configurations are nested and require careful CPE parsing.

### Recommended Preprocessing

- Deduplicate by `cve.id`, keeping the newest `lastModified` record.
- Filter `vulnStatus=Rejected` from retrieval by default.
- Preserve unscored records but mark severity as `UNSCORED`.
- Extract CVSS v3.1 preferentially, then v3.0, then v2.
- Extract CWE IDs and CPE/product nodes for later graph construction.
- Store raw references for provenance.

### Potential Use Within TrustSecAI

- Enrich incident reports with relevant vulnerabilities and severity.
- Support CVE/CWE/CPE context in GraphRAG retrieval.
- Help LLM generate remediation and prioritization guidance.
- Provide vulnerability evidence for secondary contextual security assessment.

## Cross-Dataset Risks and Recommendations

### Risks

- CICIDS labels do not directly map to ATT&CK techniques. A mapping table will be needed later and should distinguish evidence-backed mappings from heuristic mappings.
- Rare CICIDS classes may produce misleadingly high overall accuracy if macro metrics are not emphasized.
- NVD feeds are partial and overlapping; graph ingestion must deduplicate.
- ATT&CK and CAPEC contain deprecated objects that can pollute retrieval if not filtered.
- Encoding artifacts in raw CSV labels can break downstream label mapping.

### Best Practices

- Keep Week 1 focused on CICIDS preprocessing, IDS training, evaluation, and SHAP.
- Record all preprocessing decisions in artifacts for reproducibility.
- Report macro F1, balanced accuracy, per-class recall, and confusion matrices rather than accuracy alone.
- Establish a stable label vocabulary now because it will feed GraphRAG, LLM prompting, agreement analysis, and report generation later.
- Defer ATT&CK/CAPEC/NVD graph modeling until the GraphRAG milestone, but document their schemas now so future ingestion is predictable.
