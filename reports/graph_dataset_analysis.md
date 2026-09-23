# Graph Dataset Analysis

## Scope

This report analyzes the Week 2 knowledge sources that will later become the TrustSecAI graph:

- MITRE ATT&CK STIX 2.1
- CAPEC CSV dictionaries
- NVD/CVE JSON 2.0 feeds

This is design-only. No Neo4j import, vector store, GraphRAG pipeline, or LLM integration is implemented here.

## Summary

The three datasets are complementary:

- ATT&CK provides adversary behavior: tactics, techniques, sub-techniques, mitigations, groups, malware, tools, campaigns, detections, and relationships.
- CAPEC provides attack-pattern mechanics: prerequisites, execution flow, related weaknesses, consequences, mitigations, and taxonomy mappings to ATT&CK.
- NVD provides vulnerability intelligence: CVEs, CVSS metrics, CWE weaknesses, affected products, references, and vulnerability status.

The strongest cross-dataset joins are:

- TrustSecAI IDS label -> ATT&CK technique, through `artifacts/attack_label_mapping.json`.
- CAPEC -> ATT&CK, through CAPEC `Taxonomy Mappings`.
- CAPEC -> CWE, through CAPEC `Related Weaknesses`.
- CVE -> CWE, through NVD `weaknesses`.
- ATT&CK technique -> mitigation, through ATT&CK `course-of-action -mitigates-> attack-pattern`.

There is no reliable direct CAPEC -> CVE mapping in the local CAPEC CSVs. The recommended bridge is `CAPECPattern -> CWE <- CVE`.

## ATT&CK

### Local Source

Primary file:

- `Datasets/ATTACK/attack-stix-data-master/enterprise-attack/enterprise-attack.json`

The local Enterprise ATT&CK bundle contains 25,843 STIX objects.

### Entity Types

| STIX type | Count | Graph entity |
|---|---:|---|
| `attack-pattern` | 858 | Technique or SubTechnique |
| `x-mitre-tactic` | 15 | Tactic |
| `course-of-action` | 268 | Mitigation |
| `intrusion-set` | 189 | Group |
| `malware` | 729 | Malware |
| `tool` | 95 | Tool |
| `campaign` | 56 | Campaign |
| `x-mitre-data-source` | 38 | DataSource |
| `x-mitre-data-component` | 109 | DataComponent |
| `x-mitre-detection-strategy` | 699 | DetectionStrategy |
| `x-mitre-analytic` | 1,758 | Analytic |
| `relationship` | 21,025 | Graph relationships |

### Important Fields

Common fields:

- `id`
- `type`
- `created`
- `modified`
- `name`
- `description`
- `external_references`
- `revoked`
- `x_mitre_deprecated`

Technique fields:

- ATT&CK ID from `external_references.external_id`
- `kill_chain_phases`
- `x_mitre_platforms`
- `x_mitre_is_subtechnique`
- `x_mitre_detection`
- `x_mitre_data_sources`

Mitigation fields:

- ATT&CK mitigation ID from external references
- `name`
- `description`

### Existing Relationships

Observed ATT&CK relationship types:

| Relationship | Count | Meaning |
|---|---:|---|
| `uses` | 18,220 | Group/malware/tool/campaign uses a technique, tool, or malware |
| `mitigates` | 1,448 | Mitigation mitigates a technique |
| `detects` | 697 | Detection strategy detects a technique |
| `subtechnique-of` | 477 | Sub-technique belongs to parent technique |
| `revoked-by` | 157 | Deprecated lineage |
| `attributed-to` | 26 | Campaign attributed to group |

Most important typed edges:

- `malware -uses-> attack-pattern`: 10,342
- `intrusion-set -uses-> attack-pattern`: 4,546
- `course-of-action -mitigates-> attack-pattern`: 1,448
- `campaign -uses-> attack-pattern`: 1,146
- `tool -uses-> attack-pattern`: 869
- `x-mitre-detection-strategy -detects-> attack-pattern`: 697
- `attack-pattern -subtechnique-of-> attack-pattern`: 477

### Cross-References

ATT&CK cross-reference values live in `external_references`.

Important fields:

- ATT&CK technique ID, for example `T1046`.
- ATT&CK mitigation ID, for example `M1031`.
- External URLs and citation sources.

## CAPEC

### Local Source

Primary source for graph ingestion should be:

- `Datasets/CAPEC/Comprehensive Dictionary/2000.csv`

Other files are useful alternate views:

- `Attack Related Patterns/658.csv`
- `Domains of Attack/3000.csv`
- `Mechanisms of Attack/1000.csv`

### Entity Types

CAPEC should produce:

- `CAPECPattern`
- `CWE`
- CAPEC relationship edges such as `CHILD_OF`, `CAN_PRECEDE`, `CAN_FOLLOW`, `PEER_OF`, `CAN_ALSO_BE`
- Cross-reference edges to ATT&CK techniques

### Important Fields

Columns:

- `ID`
- `Name`
- `Abstraction`
- `Status`
- `Description`
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

### Existing Relationships

CAPEC `Related Attack Patterns` includes relationship natures:

| CAPEC relationship | Count in comprehensive dictionary |
|---|---:|
| `ChildOf` | 533 |
| `CanPrecede` | 162 |
| `PeerOf` | 19 |
| `CanFollow` | 10 |
| `CanAlsoBe` | 3 |

### ATT&CK Mappings

The comprehensive dictionary contains:

- 615 CAPEC rows
- 177 rows with ATT&CK taxonomy mappings
- 272 ATT&CK mapping entries
- 189 unique ATT&CK entry IDs

CAPEC stores ATT&CK IDs without the `T` prefix, for example `1040` or `1195.003`. In graph construction these should be normalized to `T1040`, `T1195.003`, etc.

### CAPEC to CVE

The local CAPEC files do not provide a dependable direct CAPEC -> CVE mapping. They do provide `Related Weaknesses`, usually CWE IDs.

Recommended path:

```text
CAPECPattern -RELATED_WEAKNESS-> CWE <-HAS_WEAKNESS- CVE
```

This bridge is preferable to string matching CVE IDs from examples.

## NVD/CVE

### Local Source

Files:

- `nvdcve-2.0-2023.json`
- `nvdcve-2.0-2024.json`
- `nvdcve-2.0-2025.json`
- `nvdcve-2.0-2026.json`
- `nvdcve-2.0-modified.json`
- `nvdcve-2.0-recent.json`

### Entity Types

NVD should produce:

- `CVE`
- `CWE`
- `Product` or `CPE`
- `Reference`
- Optional `Vendor`

### Important Fields

CVE fields:

- `cve.id`
- `cve.sourceIdentifier`
- `cve.published`
- `cve.lastModified`
- `cve.vulnStatus`
- `cve.descriptions`
- `cve.metrics`
- `cve.weaknesses`
- `cve.configurations`
- `cve.references`

CVSS fields:

- `baseScore`
- `baseSeverity`
- `vectorString`
- `attackVector`
- `attackComplexity`
- `privilegesRequired`
- `userInteraction`
- `scope`
- `confidentialityImpact`
- `integrityImpact`
- `availabilityImpact`

### Relationships

Recommended extraction:

- `CVE -HAS_WEAKNESS-> CWE`
- `CVE -AFFECTS-> CPE/Product`
- `CVE -REFERENCES-> Reference`

### Data Quality

NVD includes:

- Rejected CVEs
- Deferred CVEs
- Recently received CVEs
- Unscored CVEs
- Overlap across year, recent, and modified feeds

Recommended handling:

- Deduplicate by CVE ID.
- Keep the newest `lastModified` record.
- Exclude `Rejected` from default retrieval.
- Preserve unscored CVEs with `severity=UNSCORED`.

## Cross-Dataset Mapping Summary

| Source | Target | Mapping method | Confidence |
|---|---|---|---|
| IDS label | ATT&CK Technique | `artifacts/attack_label_mapping.json` | Manual starter mapping |
| ATT&CK Technique | Mitigation | ATT&CK `mitigates` relationship | High |
| ATT&CK Technique | Tactic | ATT&CK `kill_chain_phases` | High |
| ATT&CK Technique | SubTechnique | ATT&CK `subtechnique-of` | High |
| CAPEC Pattern | ATT&CK Technique | CAPEC `Taxonomy Mappings` | Medium/high after ID normalization |
| CAPEC Pattern | CWE | CAPEC `Related Weaknesses` | Medium/high |
| CVE | CWE | NVD `weaknesses` | High |
| CAPEC Pattern | CVE | Bridge via shared CWE | Medium |
| CVE | Product/CPE | NVD configurations | High |

## Design Recommendations

- Use ATT&CK STIX IDs and external ATT&CK IDs as separate properties.
- Normalize ATT&CK IDs to include the `T` prefix.
- Filter deprecated/revoked ATT&CK objects by default but retain status fields.
- Use CAPEC comprehensive dictionary as the primary CAPEC source.
- Build CWE as a shared bridge node between CAPEC and NVD.
- Treat NVD feeds as overlapping snapshots, not independent datasets.
- Preserve provenance on every node and relationship.

