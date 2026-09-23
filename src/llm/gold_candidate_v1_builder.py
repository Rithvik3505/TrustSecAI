"""Generate TrustSecAI gold-candidate v1 from expanded real evidence contexts."""

from __future__ import annotations

import csv
import difflib
import hashlib
import json
import random
import re
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = ROOT / "artifacts" / "gold_candidates" / "evidence_expansion" / "gold_v1_source_contexts.jsonl"
OUTPUT_DIR = ROOT / "artifacts" / "gold_candidates" / "v1"
REVIEW_DIR = OUTPUT_DIR / "review_samples"
REPORTS = ROOT / "reports"
RANDOM_SEED = 42

TASKS = [
    ("soc_incident_assessment", "initial_triage"),
    ("soc_incident_assessment", "escalation_readiness"),
    ("attack_mapping", "mapping_explanation"),
    ("mitigation_detection", "control_followup"),
    ("uncertainty_evidence_gap", "evidence_limits"),
    ("executive_summary", "business_brief"),
    ("threat_hunting_followup", "hunt_plan"),
    ("vulnerability_context", "candidate_vulnerability_context"),
    ("multi_turn_analyst_interaction", "analyst_followup"),
]
DIFFICULTIES = ["easy", "medium", "hard", "expert"]
TARGET_LABELS = {"Bot", "DDoS", "FTP-Patator", "PortScan", "Web Attack - Sql Injection"}


def read_json(path: Path) -> Any:
    """Read UTF-8 JSON."""

    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: Any) -> None:
    """Write pretty UTF-8 JSON."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    """Write JSONL rows."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_source_contexts() -> list[dict[str, Any]]:
    """Load expanded base contexts."""

    return [json.loads(line) for line in SOURCE_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_retrieval(context: dict[str, Any]) -> dict[str, Any]:
    """Load the saved retrieval JSON referenced by a context."""

    return read_json(ROOT / context["retrieval_context_path"])


def display_id_name(identifier: str | None, name: str | None = None) -> str:
    """Format an entity identifier and name."""

    if not identifier:
        return str(name or "unknown")
    if name and name != identifier:
        return f"{name} ({identifier})"
    return identifier


def entity_name(entity: dict[str, Any]) -> str:
    """Return graph entity display name."""

    props = entity.get("properties") if isinstance(entity.get("properties"), dict) else {}
    return str(entity.get("name") or props.get("name") or entity.get("id") or entity.get("cve_id") or "")


def get_attack_summary(context: dict[str, Any], retrieval: dict[str, Any]) -> dict[str, Any]:
    """Build compact ATT&CK and graph summary from source context plus retrieval."""

    attack = retrieval.get("attack", {}) if isinstance(retrieval.get("attack"), dict) else {}
    technique = attack.get("technique", {}) if isinstance(attack.get("technique"), dict) else {}
    tactics = attack.get("tactics", [])
    mitigations = attack.get("mitigations", [])
    detections = retrieval.get("detection_guidance", [])
    groups = retrieval.get("groups", [])
    tools = retrieval.get("tools", [])
    malware = retrieval.get("malware", [])
    capec = retrieval.get("capec", [])
    cwes = retrieval.get("cwes", [])
    cves = retrieval.get("cves", [])
    products = retrieval.get("products", [])
    return {
        "technique": {
            "id": context.get("attack_technique_id") or technique.get("id"),
            "name": entity_name(technique),
        },
        "tactics": [{"id": item.get("id"), "name": entity_name(item)} for item in tactics[:2]],
        "mitigations": [{"id": item.get("id"), "name": entity_name(item)} for item in mitigations[:4]],
        "detection_guidance": [{"id": item.get("id"), "name": entity_name(item)} for item in detections[:2]],
        "capec": [{"id": item.get("id"), "name": entity_name(item)} for item in capec[:2]],
        "cwes": [{"id": item.get("id"), "name": entity_name(item)} for item in cwes[:3]],
        "cves": [{"id": item.get("id") or item.get("cve_id"), "name": entity_name(item)} for item in cves[:4]],
        "products": [{"id": item.get("id") or item.get("name"), "name": entity_name(item)} for item in products[:4]],
        "groups": [{"id": item.get("id"), "name": entity_name(item)} for item in groups[:3]],
        "tools": [{"id": item.get("id"), "name": entity_name(item)} for item in tools[:3]],
        "malware": [{"id": item.get("id"), "name": entity_name(item)} for item in malware[:3]],
        "provenance": retrieval.get("provenance", [])[:10],
    }


def shap_summary(context: dict[str, Any], max_features: int = 3) -> list[dict[str, Any]]:
    """Return top SHAP features rounded for the target output."""

    features = []
    for item in context.get("shap_top_features", [])[:max_features]:
        features.append(
            {
                "feature": item["feature"],
                "value": round(float(item["value"]), 4),
                "shap_value": round(float(item["shap_value"]), 4),
                "direction": item["direction"],
            }
        )
    return features


def shap_sentence(context: dict[str, Any], max_features: int = 3) -> str:
    """Describe SHAP evidence without fabricating features."""

    features = shap_summary(context, max_features)
    bits = [f"{f['feature']} ({f['shap_value']:+.4f}, {f['direction']})" for f in features]
    if not bits:
        return "No local SHAP evidence is present in the source context."
    return "Key local SHAP signals are " + ", ".join(bits) + "."


def confidence_sentence(context: dict[str, Any]) -> str:
    """Describe binary model confidence accurately."""

    return (
        f"The binary XGBoost classifier predicted {context['model_prediction']} with "
        f"{float(context['model_confidence']):.2%} confidence; the IDS subtype used for retrieval is the real CICIDS label "
        f"{context['ids_label_ground_truth']}."
    )


def graph_sentence(summary: dict[str, Any]) -> str:
    """Describe graph context as enrichment, not proof."""

    tech = summary["technique"]
    tactic = summary["tactics"][0] if summary["tactics"] else {}
    tactic_part = f" under {display_id_name(tactic.get('id'), tactic.get('name'))}" if tactic else ""
    return (
        f"Retrieved graph context maps the subtype to {display_id_name(tech.get('id'), tech.get('name'))}{tactic_part} "
        "as contextual intelligence, not proof of compromise."
    )


def source_refs(context: dict[str, Any]) -> list[str]:
    """Return source artifact references for an example."""

    return [
        "artifacts/gold_candidates/evidence_expansion/gold_v1_source_contexts.jsonl",
        "artifacts/gold_candidates/evidence_expansion/model_predictions.jsonl",
        "artifacts/gold_candidates/evidence_expansion/local_shap_expanded.jsonl",
        context["retrieval_context_path"],
    ]


def instruction(task: str, label: str) -> str:
    """Create task instruction."""

    return {
        "soc_incident_assessment": f"Assess the {label} IDS alert for SOC triage using the supplied classifier, SHAP, and graph evidence.",
        "attack_mapping": f"Explain the ATT&CK mapping for the {label} context without overclaiming the graph evidence.",
        "mitigation_detection": f"Recommend grounded mitigation and detection follow-up for the {label} context.",
        "uncertainty_evidence_gap": f"Identify uncertainty, evidence gaps, and unsupported claims for the {label} context.",
        "executive_summary": f"Write a concise executive summary for the {label} context.",
        "threat_hunting_followup": f"Create a threat-hunting hypothesis and follow-up evidence plan for the {label} context.",
        "vulnerability_context": f"Analyze CVE/CWE/CAPEC vulnerability context for the {label} context.",
        "multi_turn_analyst_interaction": f"Respond to a short analyst interaction about the {label} context.",
    }[task]


def build_input(context: dict[str, Any], summary: dict[str, Any], task: str, difficulty: str) -> dict[str, Any]:
    """Build SFT input payload."""

    return {
        "classifier": {
            "model_type": "binary_xgboost",
            "model_prediction": context["model_prediction"],
            "model_confidence": context["model_confidence"],
            "confidence_band": context["confidence_band"],
            "ids_subtype_basis": "real_cicids_ground_truth_label",
            "ids_label_ground_truth": context["ids_label_ground_truth"],
        },
        "sample": {
            "sample_id": context["stable_sample_id"],
            "source_file": context["source_file"],
            "selected_feature_values": context.get("selected_feature_values", {}),
        },
        "shap": {
            "has_real_shap": True,
            "top_features": context.get("shap_top_features", [])[:10],
        },
        "graph_context": {
            "retrieval_context_path": context["retrieval_context_path"],
            "attack_technique_id": context.get("attack_technique_id"),
            "tactic_ids": context.get("tactic_ids", []),
            "mitigation_ids": context.get("mitigation_ids", []),
            "capec_ids": context.get("capec_ids", []),
            "cwe_ids": context.get("cwe_ids", []),
            "cve_ids": context.get("cve_ids", []),
            "product_ids": context.get("product_ids", []),
            "provenance_type": context.get("provenance_type"),
            "evidence_completeness": context.get("evidence_completeness", {}),
            "summary": summary,
        },
        "analyst_constraints": {
            "task_type": task,
            "difficulty": difficulty,
            "use_only_supplied_context": True,
            "do_not_invent_multiclass_probabilities": True,
            "graph_context_is_not_proof": True,
            "no_asset_exposure_evidence_unless_supplied": True,
        },
        "base_context_id": context["base_context_id"],
    }


def common_basis(context: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    """Common grounded output fields."""

    limitations = []
    if not context["evidence_completeness"].get("has_cve"):
        limitations.append("No CVE evidence is present in the supplied graph context.")
    if context["evidence_completeness"].get("has_cve") and not context["evidence_completeness"].get("has_asset_exposure_evidence"):
        limitations.append("CVE and product entries are candidate enrichment only; asset exposure is not established.")
    if summary["groups"] or summary["tools"] or summary["malware"]:
        limitations.append("ATT&CK group, tool, and malware entries are usage context, not attribution.")
    if context.get("provenance_type") == "mixed_direct_and_inferred":
        limitations.append("Some graph relationships are inferred and should be weighted below direct provenance.")
    return {
        "ids_label": context["ids_label_ground_truth"],
        "sample_id": context["stable_sample_id"],
        "classifier_evidence": confidence_sentence(context),
        "shap_evidence": shap_summary(context, 3),
        "graph_interpretation": graph_sentence(summary),
        "limitations": limitations,
        "provenance": summary["provenance"],
    }


def id_names(items: list[dict[str, Any]], limit: int = 4) -> list[str]:
    """Return id/name strings."""

    return [display_id_name(item.get("id"), item.get("name")) for item in items[:limit]]


def build_output(task: str, context: dict[str, Any], summary: dict[str, Any], variant_seed: int, task_variant: str) -> dict[str, Any]:
    """Build grounded target output for one task."""

    base = common_basis(context, summary)
    label = context["ids_label_ground_truth"]
    conf_band = context["confidence_band"]
    mitigations = id_names(summary["mitigations"])
    detections = id_names(summary["detection_guidance"], 2)
    cves = id_names(summary["cves"])
    cwes = id_names(summary["cwes"])
    capec = id_names(summary["capec"], 2)
    products = id_names(summary["products"])
    strong = "high" if conf_band == "high" else "limited" if conf_band == "low" else "moderate"

    if task == "soc_incident_assessment":
        triage_angle = (
            "Prioritize immediate alert validation and source-flow review."
            if task_variant == "initial_triage"
            else "Prioritize escalation readiness only if independent telemetry corroborates the sample."
        )
        return {
            **base,
            "assessment_focus": task_variant,
            "assessment": (
                f"The {label} context should be treated as a {strong}-confidence triage candidate. "
                f"{shap_sentence(context, 3)} The graph mapping should guide enrichment and follow-up, not incident declaration by itself."
            ),
            "triage_actions": [
                triage_angle,
                "Compare the SHAP-highlighted flow characteristics against packet and session telemetry.",
                "Escalate if independent telemetry supports the mapped behavior.",
            ],
            "recommended_mitigations": mitigations,
        }
    if task == "attack_mapping":
        return {
            **base,
            "attack_mapping": {
                "technique": display_id_name(summary["technique"].get("id"), summary["technique"].get("name")),
                "tactics": id_names(summary["tactics"], 2),
                "rationale": (
                    f"The retrieval label is the real CICIDS subtype {label}; the binary classifier did not produce a multiclass subtype probability. "
                    f"The ATT&CK mapping is therefore contextual and should be cited as enrichment."
                ),
            },
        }
    if task == "mitigation_detection":
        return {
            **base,
            "mitigation_recommendations": mitigations,
            "detection_recommendations": detections
            + [
                "Tune rules against the top local SHAP features only after reviewing false-positive impact.",
                "Preserve the sample_id and base_context_id during escalation for leakage-safe review.",
            ],
        }
    if task == "uncertainty_evidence_gap":
        gaps = list(base["limitations"])
        if conf_band in {"medium", "low"}:
            gaps.append(f"Classifier confidence is {conf_band}; analyst review should precede any firm conclusion.")
        return {
            **base,
            "uncertainty_assessment": "The evidence supports triage and contextual reasoning, but not attribution, asset exposure, or confirmed compromise.",
            "evidence_gaps": gaps,
            "unsupported_claims_to_refuse": [
                "Do not claim actor attribution from ATT&CK usage context.",
                "Do not claim vulnerable products unless asset exposure evidence is supplied.",
                "Do not state that the binary model produced IDS subtype probabilities.",
            ],
        }
    if task == "executive_summary":
        return {
            **base,
            "executive_summary": (
                f"TrustSecAI identified a binary {context['model_prediction']} result associated with the CICIDS subtype {label}. "
                f"Confidence is {float(context['model_confidence']):.2%}. The main operational action is SOC validation and targeted control review; "
                "the graph context enriches the alert but does not prove compromise."
            ),
            "business_action": "Preserve relevant logs, validate affected traffic, and review the grounded mitigations before operational changes.",
        }
    if task == "threat_hunting_followup":
        return {
            **base,
            "hunt_hypothesis": (
                f"If this {label} sample reflects malicious activity, related telemetry may align with "
                f"{display_id_name(summary['technique'].get('id'), summary['technique'].get('name'))}."
            ),
            "follow_up_evidence": [
                "Search for repeated flow patterns matching the strongest SHAP features.",
                "Correlate timing and peer endpoints from the source capture.",
                "Look for independent detections before using group/tool/malware context in an assessment.",
            ],
        }
    if task == "vulnerability_context":
        assessment = (
            "No CVE/CWE/CAPEC enrichment is present for this context."
            if not cves and not cwes and not capec
            else "Use vulnerability entries as candidate context only; no supplied evidence confirms product exposure."
        )
        return {
            **base,
            "vulnerability_context": {
                "capec": capec,
                "cwes": cwes,
                "cves": cves,
                "products": products,
                "assessment": assessment,
            },
        }
    if task == "multi_turn_analyst_interaction":
        return {
            **base,
            "conversation": [
                {"role": "analyst", "content": f"What is the strongest evidence for the {label} alert?"},
                {
                    "role": "assistant",
                    "content": f"{confidence_sentence(context)} {shap_sentence(context, 2)} {graph_sentence(summary)}",
                },
                {"role": "analyst", "content": "What should I avoid saying?"},
                {
                    "role": "assistant",
                    "content": "Avoid attribution, confirmed compromise, asset exposure, or multiclass probability claims unless separate evidence supplies them.",
                },
            ],
        }
    raise ValueError(task)


def stable_hash(text: str) -> str:
    """Return short stable hash."""

    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]


def build_records(contexts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate v1 SFT examples from base contexts."""

    rng = random.Random(RANDOM_SEED)
    records = []
    counter = 1
    for context_index, context in enumerate(contexts):
        retrieval = load_retrieval(context)
        summary = get_attack_summary(context, retrieval)
        task_items = list(TASKS)
        rng.shuffle(task_items)
        selected_tasks = task_items[:7]
        # Preserve every task family by adding the two rarer tasks on a rotation.
        if context_index % 4 == 0 and not any(task == "multi_turn_analyst_interaction" for task, _ in selected_tasks):
            selected_tasks[-1] = ("multi_turn_analyst_interaction", "analyst_followup")
        if context_index % 3 == 0 and not any(task == "vulnerability_context" for task, _ in selected_tasks):
            selected_tasks[-2] = ("vulnerability_context", "candidate_vulnerability_context")
        for task, task_variant in selected_tasks:
            difficulty = DIFFICULTIES[(counter - 1) % len(DIFFICULTIES)]
            example_id = f"trustsecai-gold-v1-{counter:05d}"
            metadata = {
                "example_id": example_id,
                "base_context_id": context["base_context_id"],
                "sample_id": context["stable_sample_id"],
                "ids_label": context["ids_label_ground_truth"],
                "model_prediction": context["model_prediction"],
                "model_confidence": context["model_confidence"],
                "confidence_band": context["confidence_band"],
                "task_type": task,
                "task_variant": task_variant,
                "difficulty": difficulty,
                "provenance_type": context["provenance_type"],
                "has_real_shap": context["evidence_completeness"]["has_real_shap"],
                "has_cve": context["evidence_completeness"]["has_cve"],
                "source_file": context["source_file"],
                "source_artifact_refs": source_refs(context),
                "review_status": "candidate_unreviewed",
                "created_at": date.today().isoformat(),
                "generation_method": "gold_v1_from_expanded_real_evidence",
            }
            records.append(
                {
                    "instruction": instruction(task, context["ids_label_ground_truth"]),
                    "input": build_input(context, summary, task, difficulty),
                    "output": build_output(task, context, summary, counter, task_variant),
                    "metadata": metadata,
                }
            )
            counter += 1
    return records


def output_text(record: dict[str, Any]) -> str:
    """Serialize target output for duplicate checks."""

    return json.dumps(record["output"], sort_keys=True, ensure_ascii=False)


def target_text(record: dict[str, Any]) -> str:
    """Extract readable target text excluding provenance."""

    def walk(value: Any, key: str = "") -> list[str]:
        if key == "provenance":
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            out = []
            for item in value:
                out.extend(walk(item))
            return out
        if isinstance(value, dict):
            out = []
            for k, v in value.items():
                out.extend(walk(v, k))
            return out
        return []

    return " ".join(walk(record["output"]))


def validate(records: list[dict[str, Any]], splits: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Validate v1 records."""

    ids = [r["metadata"]["example_id"] for r in records]
    duplicate_ids = [item for item, count in Counter(ids).items() if count > 1]
    duplicate_outputs = [item for item, count in Counter(output_text(r) for r in records).items() if count > 1]
    security_patterns = {
        "attack": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
        "capec": re.compile(r"\bCAPEC-\d+\b"),
        "cve": re.compile(r"\bCVE-\d{4}-\d+\b"),
        "cwe": re.compile(r"\bCWE-\d+\b"),
    }
    allowed = {
        "attack": {r["metadata"].get("ids_label") for r in records},
        "capec": set(),
        "cve": set(),
        "cwe": set(),
    }
    allowed_attack = set()
    for record in records:
        graph = record["input"]["graph_context"]
        if graph.get("attack_technique_id"):
            allowed_attack.add(graph["attack_technique_id"])
        allowed["capec"].update(graph.get("capec_ids", []))
        allowed["cve"].update(graph.get("cve_ids", []))
        allowed["cwe"].update(graph.get("cwe_ids", []))
    allowed["attack"] = allowed_attack

    flagged = []
    blocked_phrases = [
        "training example",
        "future module",
        "persona",
        "proof of compromise from graph",
        "attributed to",
    ]
    for record in records:
        meta = record["metadata"]
        text = target_text(record)
        low = text.lower()
        if not meta.get("source_artifact_refs"):
            flagged.append({"example_id": meta["example_id"], "issue": "missing source artifact reference"})
        if not meta.get("base_context_id"):
            flagged.append({"example_id": meta["example_id"], "issue": "missing base_context_id"})
        if meta.get("sample_id") is None:
            flagged.append({"example_id": meta["example_id"], "issue": "missing sample_id"})
        if "asset exposure is confirmed" in low or "product is exposed" in low:
            flagged.append({"example_id": meta["example_id"], "issue": "fabricated asset exposure wording"})
        if "graph proves" in low or "graph confirms compromise" in low:
            flagged.append({"example_id": meta["example_id"], "issue": "graph context treated as proof"})
        if "produced ids subtype probabilities" in low and "do not state" not in low:
            flagged.append({"example_id": meta["example_id"], "issue": "fabricated multiclass probability wording"})
        for phrase in blocked_phrases:
            if phrase in low:
                flagged.append({"example_id": meta["example_id"], "issue": f"blocked phrase: {phrase}"})
        for kind, pattern in security_patterns.items():
            for found in pattern.findall(text):
                if found not in allowed[kind]:
                    flagged.append({"example_id": meta["example_id"], "issue": f"unsupported {kind} id: {found}"})
    split_base = {name: {r["metadata"]["base_context_id"] for r in rows} for name, rows in splits.items()}
    leakage = {
        "train_validation": sorted(split_base["train"] & split_base["validation"]),
        "train_test": sorted(split_base["train"] & split_base["test"]),
        "validation_test": sorted(split_base["validation"] & split_base["test"]),
    }
    if any(leakage.values()):
        flagged.append({"example_id": "split", "issue": "base_context_id leakage across splits"})
    return {
        "total_examples": len(records),
        "duplicate_ids": duplicate_ids,
        "duplicate_target_outputs": len(duplicate_outputs),
        "flagged_examples": flagged,
        "split_leakage": leakage,
        "passed": not duplicate_ids and not duplicate_outputs and not flagged,
    }


def split_records(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Split by base_context_id without leakage."""

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[record["metadata"]["base_context_id"]].append(record)
    base_ids = sorted(grouped)
    random.Random(RANDOM_SEED).shuffle(base_ids)
    train_cut = int(len(base_ids) * 0.70)
    val_cut = train_cut + int(len(base_ids) * 0.15)
    split_ids = {"train": base_ids[:train_cut], "validation": base_ids[train_cut:val_cut], "test": base_ids[val_cut:]}
    splits = {}
    for split, ids in split_ids.items():
        rows = []
        for base_id in ids:
            for record in grouped[base_id]:
                copied = json.loads(json.dumps(record))
                copied["metadata"]["split"] = split
                rows.append(copied)
        splits[split] = rows
    return splits


def repeated_rate(values: list[str]) -> float:
    """Return repeated exact value rate."""

    counts = Counter(values)
    return round(sum(c for c in counts.values() if c > 1) / max(1, len(values)), 4)


def diversity(records: list[dict[str, Any]], splits: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Measure target-output diversity only."""

    texts = [target_text(r) for r in records]
    sentences = [re.split(r"(?<=[.!?])\s+", t.strip()) for t in texts]
    openings = [s[0][:160] for s in sentences if s and s[0]]
    closings = [s[-1][:160] for s in sentences if s and s[-1]]
    tokens = re.findall(r"[a-z][a-z0-9']+", " ".join(texts).lower())
    near = 0
    by_task_context: dict[tuple[str, str], list[str]] = defaultdict(list)
    for record, text in zip(records, texts):
        by_task_context[(record["metadata"]["base_context_id"], record["metadata"]["task_type"])].append(text)
    for values in by_task_context.values():
        for i in range(len(values)):
            for j in range(i + 1, len(values)):
                if difflib.SequenceMatcher(None, values[i], values[j]).ratio() > 0.92:
                    near += 1
    shap_patterns = defaultdict(set)
    for record in records:
        feats = tuple(f["feature"] for f in record["input"]["shap"]["top_features"][:4])
        shap_patterns[record["metadata"]["ids_label"]].add(feats)
    split_base = {name: {r["metadata"]["base_context_id"] for r in rows} for name, rows in splits.items()}
    return {
        "total_examples": len(records),
        "unique_base_contexts": len({r["metadata"]["base_context_id"] for r in records}),
        "examples_per_base_context": dict(Counter(r["metadata"]["base_context_id"] for r in records)),
        "exact_duplicate_target_outputs": sum(c - 1 for c in Counter(output_text(r) for r in records).values() if c > 1),
        "near_duplicate_target_outputs": near,
        "repeated_opening_rate": repeated_rate(openings),
        "repeated_closing_rate": repeated_rate(closings),
        "vocabulary_diversity": round(len(set(tokens)) / max(1, len(tokens)), 4),
        "task_distribution": dict(Counter(r["metadata"]["task_type"] for r in records)),
        "ids_label_distribution": dict(Counter(r["metadata"]["ids_label"] for r in records)),
        "confidence_band_distribution": dict(Counter(r["metadata"]["confidence_band"] for r in records)),
        "shap_coverage": dict(Counter(r["metadata"]["has_real_shap"] for r in records)),
        "distinct_shap_top_feature_patterns_per_label": {k: len(v) for k, v in shap_patterns.items()},
        "cve_distribution": dict(Counter("cve_present" if r["metadata"]["has_cve"] else "cve_absent" for r in records)),
        "provenance_type_distribution": dict(Counter(r["metadata"]["provenance_type"] for r in records)),
        "source_file_distribution": dict(Counter(r["metadata"]["source_file"] for r in records)),
        "split_leakage_status": {
            "train_validation": sorted(split_base["train"] & split_base["validation"]),
            "train_test": sorted(split_base["train"] & split_base["test"]),
            "validation_test": sorted(split_base["validation"] & split_base["test"]),
        },
    }


def make_review_package(records: list[dict[str, Any]]) -> None:
    """Create stratified review package and manifest."""

    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    rng = random.Random(RANDOM_SEED)
    selected: dict[str, dict[str, Any]] = {}
    buckets: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        m = record["metadata"]
        shap_pattern = tuple(f["feature"] for f in record["input"]["shap"]["top_features"][:3])
        key = (m["ids_label"], m["task_type"], m["difficulty"], m["confidence_band"], m["provenance_type"], m["has_cve"], shap_pattern)
        buckets[key].append(record)
    for rows in buckets.values():
        rng.shuffle(rows)
        selected[rows[0]["metadata"]["example_id"]] = rows[0]
    remaining = [r for r in records if r["metadata"]["example_id"] not in selected]
    rng.shuffle(remaining)
    for record in remaining:
        if len(selected) >= min(250, len(records)):
            break
        selected[record["metadata"]["example_id"]] = record
    sample = list(selected.values())
    write_json(REVIEW_DIR / "review_samples.json", sample)
    for task, rows in group_by(sample, "task_type").items():
        write_json(REVIEW_DIR / f"task_{task}.json", rows[:30])
    for label, rows in group_by(sample, "ids_label").items():
        safe = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
        write_json(REVIEW_DIR / f"label_{safe}.json", rows[:30])

    with (OUTPUT_DIR / "review_manifest.csv").open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "example_id",
            "base_context_id",
            "sample_id",
            "ids_label",
            "model_prediction",
            "model_confidence",
            "confidence_band",
            "task_type",
            "difficulty",
            "provenance_type",
            "has_real_shap",
            "has_cve",
            "source_file",
            "review_status",
            "reviewer_decision",
            "reviewer_notes",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in sample:
            m = record["metadata"]
            writer.writerow({key: m.get(key, "") for key in fieldnames[:-2]} | {"reviewer_decision": "", "reviewer_notes": ""})


def group_by(records: list[dict[str, Any]], metadata_key: str) -> dict[str, list[dict[str, Any]]]:
    """Group records by a metadata key."""

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[str(record["metadata"][metadata_key])].append(record)
    return grouped


def write_reports(records: list[dict[str, Any]], splits: dict[str, list[dict[str, Any]]], quality: dict[str, Any], div: dict[str, Any]) -> None:
    """Write all v1 reports."""

    REPORTS.mkdir(parents=True, exist_ok=True)
    summary = [
        "# TrustSecAI Gold-Candidate v1 Report",
        "",
        "Generated from expanded real evidence contexts only. The old 30k synthetic corpus and v0 examples were not used as inputs.",
        "",
        f"- Total examples: {len(records)}",
        f"- Unique base contexts: {div['unique_base_contexts']}",
        f"- Task distribution: {div['task_distribution']}",
        f"- IDS label distribution: {div['ids_label_distribution']}",
        f"- Confidence-band distribution: {div['confidence_band_distribution']}",
        f"- CVE distribution: {div['cve_distribution']}",
    ]
    (REPORTS / "trustsecai_gold_candidate_v1_report.md").write_text("\n".join(summary) + "\n", encoding="utf-8")

    split_lines = ["# Gold-Candidate v1 Split Report", "", "Splits are grouped by `base_context_id`.", ""]
    for split, rows in splits.items():
        split_lines.extend(
            [
                f"## {split}",
                "",
                f"- Examples: {len(rows)}",
                f"- Base contexts: {len({r['metadata']['base_context_id'] for r in rows})}",
                f"- IDS labels: {dict(Counter(r['metadata']['ids_label'] for r in rows))}",
                f"- Confidence bands: {dict(Counter(r['metadata']['confidence_band'] for r in rows))}",
                f"- Source files: {dict(Counter(r['metadata']['source_file'] for r in rows))}",
                "",
            ]
        )
    split_lines.extend(["## Leakage Check", "", f"- {quality['split_leakage']}"])
    (REPORTS / "gold_candidate_v1_split_report.md").write_text("\n".join(split_lines) + "\n", encoding="utf-8")

    (REPORTS / "gold_candidate_v1_quality_report.md").write_text(
        "# Gold-Candidate v1 Quality Report\n\n```json\n" + json.dumps(quality, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    (REPORTS / "gold_candidate_v1_diversity_report.md").write_text(
        "# Gold-Candidate v1 Diversity Report\n\n```json\n" + json.dumps(div, indent=2) + "\n```\n",
        encoding="utf-8",
    )
    readiness = [
        "# Gold-Candidate v1 Training Readiness",
        "",
        f"- Automated validation passed: {quality['passed']}",
        "- Status: candidate set ready for human review, not gold-approved training.",
        "- LoRA training should wait until the review manifest is marked approve/revise/reject.",
        "- Keep split grouping by base_context_id for all downstream experiments.",
    ]
    (REPORTS / "gold_candidate_v1_training_readiness.md").write_text("\n".join(readiness) + "\n", encoding="utf-8")
    guide = [
        "# Gold-Candidate v1 Review Guide",
        "",
        "Checklist:",
        "",
        "1. Is every claim grounded in classifier, SHAP, or graph evidence?",
        "2. Is binary confidence described as BENIGN/ATTACK confidence only?",
        "3. Is the IDS subtype clearly tied to the CICIDS ground-truth label?",
        "4. Are CVEs treated as candidate context unless asset exposure is supplied?",
        "5. Is ATT&CK group/tool/malware context kept separate from attribution?",
        "6. Does the response avoid treating graph context as proof of compromise?",
        "7. Is the tone appropriate for the task?",
        "8. Mark approve, revise, or reject in the review manifest.",
    ]
    (REPORTS / "gold_candidate_v1_review_guide.md").write_text("\n".join(guide) + "\n", encoding="utf-8")
    review_count = sum(1 for _ in (OUTPUT_DIR / "review_manifest.csv").open(encoding="utf-8")) - 1
    review_summary = [
        "# Gold-Candidate v1 Review Summary",
        "",
        f"- Review sample size: {review_count}",
        f"- Review samples directory: `{(OUTPUT_DIR / 'review_samples').as_posix()}`",
        f"- Review manifest: `{(OUTPUT_DIR / 'review_manifest.csv').as_posix()}`",
    ]
    (REPORTS / "gold_candidate_v1_review_summary.md").write_text("\n".join(review_summary) + "\n", encoding="utf-8")


def main() -> None:
    """Build v1 candidate dataset."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    contexts = load_source_contexts()
    records = build_records(contexts)
    splits = split_records(records)
    quality = validate(records, splits)
    div = diversity(records, splits)

    write_jsonl(OUTPUT_DIR / "trustsecai_gold_candidate_v1.jsonl", records)
    write_json(OUTPUT_DIR / "trustsecai_gold_candidate_v1_pretty.json", records)
    write_json(OUTPUT_DIR / "trustsecai_gold_candidate_v1_quality_report.json", quality)
    for split, rows in splits.items():
        write_jsonl(OUTPUT_DIR / f"{split}.jsonl", rows)
    make_review_package(records)
    write_reports(records, splits, quality, div)


if __name__ == "__main__":
    main()
