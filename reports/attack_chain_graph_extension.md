# Attack-Chain Graph Extension

## Why This Extension Was Added

The first TrustSecAI attack-chain predictor used static ATT&CK seed mappings. That made the final demo deterministic and safe, but it did not use the Neo4j knowledge graph that already contains ATT&CK, CAPEC, CWE, CVE, mitigation, and IDS-label relationships.

This extension upgrades the agent to prefer graph-backed Neo4j traversal when available, while preserving the original static mapping as a safe fallback.

## Traversal Entry Point

The agent starts from the IDS label and maps it to a seed ATT&CK technique:

| IDS label | Seed technique | Tactic |
|---|---|---|
| Web Attack - Sql Injection | `T1190` Exploit Public-Facing Application | Initial Access |
| PortScan | `T1046` Network Service Discovery | Discovery |
| FTP-Patator | `T1110` Brute Force | Credential Access |
| Bot | `T1105` Ingress Tool Transfer | Command and Control |
| DDoS | `T1498` Network Denial of Service | Impact |

The seed mappings remain unchanged from the static implementation.

## Graph Entities Used

When Neo4j is available, traversal starts from the seed `Technique` or `SubTechnique` node and retrieves:

- Connected `Tactic` nodes through `HAS_TACTIC`
- Connected `Mitigation` nodes through `MITIGATED_BY`
- CAPEC patterns through `HAS_ATTACK_PATTERN`
- CWE weaknesses through `RELATED_WEAKNESS`
- CVE candidates through `ASSOCIATED_CVE`
- Same-tactic candidate techniques through shared `HAS_TACTIC`
- Parent/subtechnique-related techniques through `SUBTECHNIQUE_OF`

The graph output is framed as candidate defensive investigation pivots, not confirmed attacker behavior.

## Candidate Ranking

Candidate next steps are ranked deterministically:

1. Direct parent/subtechnique relationships rank highest.
2. Same-tactic technique candidates rank lower.
3. CAPEC/CWE/CVE-derived context is treated as vulnerability context, not as confirmed next-step behavior.
4. Candidate next techniques are capped to 3 to 5 entries.

Each candidate includes available provenance such as relationship type, source, inferred flag, confidence, origin node, and target node.

## Fallback Behavior

If Neo4j is unavailable, unreachable, missing required nodes, or missing Python dependencies, the function returns:

```text
mode: static_fallback
graph_available: false
```

The fallback caveats include:

```text
Neo4j unavailable; used static ATT&CK seed mapping.
```

This keeps the demo stable on machines without a local Neo4j instance.

## Demo Usage

Default behavior tries graph-backed traversal and falls back safely:

```bash
python -m src.pipeline.trustsecai_demo --example-id trustsecai-gold-v1-00575 --offline-lora
```

Force graph-backed mode with fallback:

```bash
python -m src.pipeline.trustsecai_demo --example-id trustsecai-gold-v1-00575 --offline-lora --use-graph-attack-chain
```

Force static fallback:

```bash
python -m src.pipeline.trustsecai_demo --example-id trustsecai-gold-v1-00575 --offline-lora --no-graph-attack-chain
```

The generated Markdown report states the mode:

- `Attack-chain mode: graph-backed Neo4j traversal`
- `Attack-chain mode: static fallback`

## Limitations

- Graph traversal currently uses a bounded query rather than a full path-search algorithm.
- Same-tactic candidates are investigation pivots and may not represent temporal attack progression.
- CAPEC/CWE/CVE paths are vulnerability context only; they do not prove affected assets.
- No offensive procedures, exploit steps, payloads, or attacker playbooks are generated.
- Group, tool, and malware context must not be treated as attribution.
- Confidence is heuristic and should be calibrated with historical incidents and analyst feedback.

## Future Work

- Add weighted traversal using graph distance, relationship confidence, and provenance quality.
- Rank candidate next techniques with temporal alert correlation.
- Include CAPEC `CAN_PRECEDE` and `CAN_FOLLOW` relationships where available.
- Add analyst feedback to calibrate confidence.
- Add unit tests with mocked Neo4j responses for graph and fallback modes.
