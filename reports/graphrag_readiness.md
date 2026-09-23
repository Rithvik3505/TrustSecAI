# GraphRAG Readiness Report

## Summary

| Metric | Value |
|---|---:|
| Labels validated | 5 |
| Average retrieval latency ms | 418.741 |
| Max retrieval latency ms | 1440.639 |
| Average nodes retrieved | 32.00 |
| Average relationships traversed | 41.40 |

## Validation Results

| label | technique | nodes_retrieved | relationships_traversed | latency_ms | valid | errors |
| --- | --- | --- | --- | --- | --- | --- |
| PortScan | T1046 | 62 | 97 | 1440.639 | True |  |
| FTP-Patator | T1110 | 35 | 39 | 406.414 | True |  |
| Bot | T1105 | 29 | 35 | 84.006 | True |  |
| DDoS | T1498 | 7 | 7 | 74.322 | True |  |
| Web Attack - Sql Injection | T1190 | 27 | 29 | 88.325 | True |  |

## Ranking Behaviour

- Ranking prioritizes shorter graph distance from the IDS label.
- Source/original relationships are preferred over inferred relationships.
- Relationship confidence contributes to score.
- CVEs are boosted by CVSS severity and base score.
- CAPEC patterns are boosted by likelihood and severity when present.

## Known Limitations

- No vector search or semantic expansion is used yet.
- CAPEC to CVE links are inferred through shared CWE and may over-retrieve without asset/product context.
- Some labels resolve to ATT&CK and mitigations but do not have local CAPEC mappings.
- Actor context is evidence of observed technique usage in ATT&CK, not attribution.

## Potential Retrieval Ambiguity

- IDS labels such as `Bot` and broad web attack labels can map to techniques that are context-dependent.
- Inferred CVEs are vulnerability candidates, not confirmed affected assets.
- CAPEC taxonomy coverage is incomplete for some ATT&CK techniques.

## Future LLM Integration Point

The JSON produced by `RetrievalPipeline.run()` should be passed directly as structured context to the future Llama 3.1 prompt. The LLM should be instructed to cite provenance entries and preserve uncertainty.
