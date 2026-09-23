"""Offline TrustSecAI end-to-end demo runner.

This CLI composes frozen LoRA evaluation output with agreement analysis,
bounded attack-chain prediction, and report generation. It does not run model
inference or modify any trained artifacts.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from src.analysis.agreement import analyze_agreement
from src.analysis.attack_chain import predict_attack_chain
from src.llm.integration.lora_client import DEFAULT_GENERATIONS_FILE, LoraClient
from src.llm.integration.prompt_builder import extract_supplied_context
from src.llm.integration.response_parser import parse_lora_output
from src.reporting.security_report_builder import build_security_report


DEFAULT_OUTPUT_DIR = Path("artifacts/demo")


def compact_graph_summary(context: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    """Create a compact graph summary from embedded context and flattened row fields."""

    graph = context.get("graph_context", {}) if isinstance(context, dict) else {}
    summary = graph.get("summary", {}) if isinstance(graph, dict) else {}
    return {
        "technique": summary.get("technique") or {"id": graph.get("attack_technique_id")},
        "tactics": summary.get("tactics") or [{"id": item} for item in graph.get("tactic_ids", [])],
        "mitigation_ids": graph.get("mitigation_ids", []),
        "capec_ids": graph.get("capec_ids", []),
        "cwe_ids": graph.get("cwe_ids", []),
        "cve_ids": graph.get("cve_ids", []),
        "provenance_type": row.get("provenance_type") or graph.get("provenance_type"),
        "has_cve": row.get("has_cve"),
    }


def build_demo_payload(row: dict[str, Any], use_graph_attack_chain: bool = True) -> dict[str, Any]:
    """Build the normalized demo payload from one offline generation row."""

    context = extract_supplied_context(row)
    metadata = row.get("metadata", {})
    classifier = context.get("classifier", {}) if context else {}
    sample = context.get("sample", {}) if context else {}
    classifier_evidence = {
        "ids_label": row.get("ids_label") or metadata.get("ids_label"),
        "model_prediction": row.get("model_prediction") or metadata.get("model_prediction"),
        "model_confidence": row.get("model_confidence") or metadata.get("model_confidence"),
        "confidence_band": metadata.get("confidence_band"),
        "sample_id": row.get("sample_id") or metadata.get("sample_id"),
        "source_file": metadata.get("source_file"),
        "ids_subtype_basis": classifier.get("ids_subtype_basis"),
        "ids_label_ground_truth": classifier.get("ids_label_ground_truth"),
    }
    shap = context.get("shap", {}) if context else {}
    graph_summary = compact_graph_summary(context, row)
    parsed = parse_lora_output(row.get("generation", ""))
    evidence_flags = {
        "has_real_shap": metadata.get("has_real_shap"),
        "has_cve": metadata.get("has_cve"),
        "requires_vulnerability_context": row.get("task_type") == "vulnerability_context",
    }
    agreement = analyze_agreement(
        classifier_prediction=str(classifier_evidence.get("model_prediction", "")),
        classifier_confidence=classifier_evidence.get("model_confidence"),
        ids_label=classifier_evidence.get("ids_label"),
        parsed_llm_output=parsed,
        evidence_flags=evidence_flags,
    )
    attack_chain = predict_attack_chain(
        classifier_evidence.get("ids_label"),
        graph_summary,
        use_graph=use_graph_attack_chain,
    )
    limitations = [
        "Offline demo uses frozen LoRA compact evaluation output; it does not run live inference.",
        "Agreement and attack-chain modules are deterministic scaffolding for the final demo.",
        "Unsafe-attribution evaluation flags are known to be overbroad and require human interpretation.",
    ]
    report = build_security_report(
        classifier_evidence=classifier_evidence,
        shap_evidence=shap,
        graph_context_summary=graph_summary,
        llm_secondary_assessment=parsed,
        agreement_result=agreement,
        attack_chain_prediction=attack_chain,
        limitations=limitations,
    )
    return {
        "metadata": metadata,
        "classifier_evidence": classifier_evidence,
        "sample": sample,
        "shap_evidence": shap,
        "graph_context_summary": graph_summary,
        "llm_secondary_assessment": parsed,
        "agreement_result": agreement,
        "attack_chain_prediction": attack_chain,
        "limitations": limitations,
        "markdown_report": report,
    }


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Run offline TrustSecAI integration demo from frozen LoRA output.")
    parser.add_argument("--example-id", default=None)
    parser.add_argument("--row-number", type=int, default=None)
    parser.add_argument("--lora-generations-file", type=Path, default=DEFAULT_GENERATIONS_FILE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--offline-lora", action="store_true", default=True)
    parser.add_argument(
        "--use-graph-attack-chain",
        dest="use_graph_attack_chain",
        action="store_true",
        default=True,
        help="Use Neo4j-backed attack-chain traversal when available, with static fallback.",
    )
    parser.add_argument(
        "--no-graph-attack-chain",
        dest="use_graph_attack_chain",
        action="store_false",
        help="Disable Neo4j traversal and use static ATT&CK seed fallback.",
    )
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    if not args.offline_lora:
        raise SystemExit("Only --offline-lora mode is supported in Phase 1 integration scaffolding.")
    client = LoraClient(generations_file=args.lora_generations_file, mode="offline")
    row = client.get_generation(example_id=args.example_id, row_number=args.row_number)
    payload = build_demo_payload(row, use_graph_attack_chain=args.use_graph_attack_chain)
    example_key = args.example_id or f"row_{args.row_number or row.get('row_number', 'unknown')}"
    safe_key = str(example_key).replace("/", "_").replace("\\", "_")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / f"demo_{safe_key}.json"
    md_path = args.output_dir / f"demo_{safe_key}.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(payload["markdown_report"], encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2))


if __name__ == "__main__":
    main()
