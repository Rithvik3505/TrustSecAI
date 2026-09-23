# Gold-Candidate v1 Generation Plan

- Expanded base contexts: 121
- Recommended task variants per base context: 6-10
- Expected v1 size: approximately 726 to 968 examples
- Split strategy: group by base_context_id with 70/15/15 train/validation/test allocation.
- Review strategy: sample at least 250 examples stratified by IDS label, task family, confidence band, source file, provenance type, and CVE availability.
- Limitations: binary IDS predictions do not provide multiclass probabilities; retrieval label linkage uses the real CICIDS sub-label.
