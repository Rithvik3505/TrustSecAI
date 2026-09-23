# TrustSecAI LoRA v1 Held-Out Test Evaluation

## lora

- File: `artifacts/evaluation/lora_v1/lora_generations_compact.jsonl`
- Total generations: 76
- Non-empty rate: 1.0
- Length chars: {'min': 1428, 'max': 2646, 'mean': 1699.67, 'median': 1633.5}
- Generated tokens: {'min': 375, 'max': 889, 'mean': 468.18, 'median': 459.0}
- Generated-token cap hit rate: 0.0 (0/76 at cap 1200)
- Metadata preservation: {'example_id': {'count': 76, 'coverage': 1.0}, 'ids_label': {'count': 76, 'coverage': 1.0}, 'task_type': {'count': 76, 'coverage': 1.0}, 'base_context_id': {'count': 76, 'coverage': 1.0}, 'sample_id': {'count': 76, 'coverage': 1.0}}
- Error/traceback rate: 0.0
- JSON parse rate: 0.8289 (63/76)
- Unsupported ID counts: {'cwe': 4}
- Unsafe attribution phrase count: 35
- GraphRAG proof wording count: 0

## Notes

These checks are lightweight automatic guards. They do not replace human SOC-quality review.
Unsupported ID checks compare generated IDs against IDs present in the prompt/context/target.
