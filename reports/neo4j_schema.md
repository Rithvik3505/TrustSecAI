# Neo4j Schema Design

## Design Goals

The TrustSecAI graph should support:

- Context retrieval for IDS predictions.
- Technique-to-mitigation lookup.
- CAPEC attack-pattern enrichment.
- CVE/CWE vulnerability enrichment.
- Multi-hop attack-chain prediction.
- Provenance-aware LLM context generation.

This schema is design-only. No Neo4j database, ingestion code, or GraphRAG implementation is created in this phase.

## Node Types

### `Technique`

Represents ATT&CK parent techniques.

Properties:

- `stix_id`
- `attack_id`
- `name`
- `description`
- `platforms`
- `detection`
- `created`
- `modified`
- `revoked`
- `deprecated`
- `source`
- `url`

### `SubTechnique`

Represents ATT&CK sub-techniques.

Properties:

- Same as `Technique`
- `parent_attack_id`

### `Tactic`

Represents ATT&CK tactics.

Properties:

- `stix_id`
- `attack_id`
- `short_name`
- `name`
- `description`
- `created`
- `modified`
- `source`
- `url`

### `Mitigation`

Represents ATT&CK courses of action.

Properties:

- `stix_id`
- `attack_id`
- `name`
- `description`
- `created`
- `modified`
- `revoked`
- `deprecated`
- `source`
- `url`

### `Group`

Represents ATT&CK intrusion sets.

Properties:

- `stix_id`
- `attack_id`
- `name`
- `aliases`
- `description`
- `created`
- `modified`
- `source`
- `url`

### `Malware`

Represents ATT&CK malware.

Properties:

- `stix_id`
- `attack_id`
- `name`
- `aliases`
- `description`
- `platforms`
- `created`
- `modified`
- `source`
- `url`

### `Tool`

Represents ATT&CK tools.

Properties:

- `stix_id`
- `attack_id`
- `name`
- `aliases`
- `description`
- `platforms`
- `created`
- `modified`
- `source`
- `url`

### `Campaign`

Represents ATT&CK campaigns.

Properties:

- `stix_id`
- `attack_id`
- `name`
- `aliases`
- `description`
- `first_seen`
- `last_seen`
- `created`
- `modified`
- `source`
- `url`

### `DetectionStrategy`

Represents ATT&CK detection strategies.

Properties:

- `stix_id`
- `attack_id`
- `name`
- `description`
- `created`
- `modified`
- `source`

### `DataSource`

Represents ATT&CK data sources.

Properties:

- `stix_id`
- `name`
- `description`
- `platforms`
- `collection_layers`
- `source`

### `DataComponent`

Represents ATT&CK data components.

Properties:

- `stix_id`
- `name`
- `description`
- `source`

### `CAPECPattern`

Represents CAPEC attack patterns.

Properties:

- `capec_id`
- `name`
- `abstraction`
- `status`
- `description`
- `likelihood`
- `severity`
- `execution_flow`
- `prerequisites`
- `skills_required`
- `resources_required`
- `indicators`
- `consequences`
- `mitigations`
- `example_instances`
- `notes`
- `source`

### `CWE`

Represents Common Weakness Enumeration IDs shared by CAPEC and NVD.

Properties:

- `cwe_id`
- `name`
- `description`
- `source`

If CWE metadata is not locally available, create minimal CWE nodes with only `cwe_id` and provenance.

### `CVE`

Represents NVD CVEs.

Properties:

- `cve_id`
- `description`
- `source_identifier`
- `published`
- `last_modified`
- `status`
- `severity`
- `base_score`
- `cvss_version`
- `vector_string`
- `attack_vector`
- `attack_complexity`
- `privileges_required`
- `user_interaction`
- `scope`
- `confidentiality_impact`
- `integrity_impact`
- `availability_impact`
- `source`

### `Product`

Represents affected CPE/product entries.

Properties:

- `cpe_uri`
- `vendor`
- `product`
- `version`
- `part`
- `source`

### `Reference`

Represents external NVD or ATT&CK/CAPEC references.

Properties:

- `url`
- `source`
- `tags`
- `name`

### `IDSLabel`

Represents TrustSecAI classifier labels.

Properties:

- `label`
- `binary_label`
- `description`
- `source`

Examples:

- `PortScan`
- `DDoS`
- `FTP-Patator`
- `Web Attack - Sql Injection`

## Relationship Types

### ATT&CK Relationships

| Relationship | From | To | Properties |
|---|---|---|---|
| `HAS_TACTIC` | `Technique`/`SubTechnique` | `Tactic` | `source`, `kill_chain_name` |
| `SUBTECHNIQUE_OF` | `SubTechnique` | `Technique` | `source`, `stix_relationship_id` |
| `MITIGATED_BY` | `Technique`/`SubTechnique` | `Mitigation` | `source`, `stix_relationship_id`, `description` |
| `DETECTED_BY` | `Technique`/`SubTechnique` | `DetectionStrategy` | `source`, `stix_relationship_id` |
| `USES_TECHNIQUE` | `Group`/`Malware`/`Tool`/`Campaign` | `Technique`/`SubTechnique` | `source`, `description`, `created`, `modified` |
| `USES_TOOL` | `Group`/`Campaign` | `Tool` | `source`, `description` |
| `USES_MALWARE` | `Group`/`Campaign` | `Malware` | `source`, `description` |
| `ATTRIBUTED_TO` | `Campaign` | `Group` | `source`, `description` |
| `REVOKED_BY` | Any ATT&CK object | Replacement object | `source` |

Direction choice:

- Store `MITIGATED_BY` from technique to mitigation for retrieval ergonomics, even though ATT&CK raw STIX stores `course-of-action -mitigates-> attack-pattern`.

### CAPEC Relationships

| Relationship | From | To | Properties |
|---|---|---|---|
| `CHILD_OF` | `CAPECPattern` | `CAPECPattern` | `source`, `raw_nature` |
| `CAN_PRECEDE` | `CAPECPattern` | `CAPECPattern` | `source`, `raw_nature` |
| `CAN_FOLLOW` | `CAPECPattern` | `CAPECPattern` | `source`, `raw_nature` |
| `PEER_OF` | `CAPECPattern` | `CAPECPattern` | `source`, `raw_nature` |
| `CAN_ALSO_BE` | `CAPECPattern` | `CAPECPattern` | `source`, `raw_nature` |
| `RELATED_WEAKNESS` | `CAPECPattern` | `CWE` | `source` |
| `MAPS_TO_ATTACK` | `CAPECPattern` | `Technique`/`SubTechnique` | `source`, `taxonomy_name`, `confidence` |

### NVD/CVE Relationships

| Relationship | From | To | Properties |
|---|---|---|---|
| `HAS_WEAKNESS` | `CVE` | `CWE` | `source` |
| `AFFECTS` | `CVE` | `Product` | `source`, `vulnerable`, `version_start`, `version_end` |
| `REFERENCES` | `CVE` | `Reference` | `source`, `tags` |

### TrustSecAI Integration Relationships

| Relationship | From | To | Properties |
|---|---|---|---|
| `DETECTED_AS` | `IDSLabel` | `Technique`/`SubTechnique` | `confidence`, `rationale`, `source` |
| `HAS_ATTACK_PATTERN` | `Technique`/`SubTechnique` | `CAPECPattern` | `source`, `confidence` |
| `ASSOCIATED_CVE` | `CAPECPattern`/`Technique` | `CVE` | `source`, `method`, `confidence` |

`ASSOCIATED_CVE` should usually be derived through CWE and marked as inferred.

## Constraints and Indexes

Recommended uniqueness constraints:

```cypher
CREATE CONSTRAINT technique_attack_id IF NOT EXISTS FOR (n:Technique) REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT subtechnique_attack_id IF NOT EXISTS FOR (n:SubTechnique) REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT tactic_attack_id IF NOT EXISTS FOR (n:Tactic) REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT mitigation_attack_id IF NOT EXISTS FOR (n:Mitigation) REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT capec_id IF NOT EXISTS FOR (n:CAPECPattern) REQUIRE n.capec_id IS UNIQUE;
CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (n:CWE) REQUIRE n.cwe_id IS UNIQUE;
CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (n:CVE) REQUIRE n.cve_id IS UNIQUE;
CREATE CONSTRAINT ids_label IF NOT EXISTS FOR (n:IDSLabel) REQUIRE n.label IS UNIQUE;
```

Recommended indexes:

- `Technique(name)`
- `SubTechnique(name)`
- `CAPECPattern(name)`
- `CVE(severity)`
- `CVE(base_score)`
- `Product(vendor)`
- `Product(product)`

## Provenance Properties

Every node should include:

- `source`
- `source_file`
- `ingested_at`
- `raw_id`

Every relationship should include:

- `source`
- `source_file`
- `raw_relationship_id`
- `confidence`
- `inferred`

## Schema Recommendation

Use ATT&CK as the behavioral spine, CAPEC as the attack-pattern/mechanics layer, NVD as the vulnerability layer, and IDS labels as TrustSecAI entry points.

Primary retrieval path:

```text
IDSLabel -> Technique/SubTechnique -> Tactic
                              -> Mitigation
                              -> CAPECPattern -> CWE <- CVE -> Product
                              -> Group/Malware/Tool/Campaign
```

