# TrustSecAI Training Readiness

- Status: Ready for manual review before LoRA training
- Examples: 30000
- Validation rejected: 0
- Validation warnings: 0
- Diversity flags: 0

## Readiness Checks

| Check | Result |
|---|---|
| JSONL export present | pass |
| Pretty JSON export present | pass |
| Quality report generated | pass |
| Missing provenance rejected | pass |
| Invented security IDs rejected | pass |
| Unsupported attribution rejected | pass |
| Dataset diversity report generated | pass |

## Required Human Review

- Review samples from each task family, difficulty level, and variant.
- Check that response tone matches expected SOC analyst style.
- Confirm that negative examples appropriately refuse unsupported conclusions.
- Confirm that executive summaries avoid excess technical detail.
- Confirm that GraphRAG context is framed as contextual evidence rather than proof.

## Next Step

After manual approval, this same deterministic pipeline can be used to scale toward the 20,000-30,000 example LoRA corpus.
