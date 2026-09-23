"""Bounded defensive attack-chain prediction.

The predictor prefers graph-backed Neo4j traversal when available and falls
back to static ATT&CK seed mappings when Neo4j is unavailable. All outputs are
defensive investigation pivots, not offensive procedures or attacker playbooks.
"""

from __future__ import annotations

from typing import Any

ATTACK_CHAIN_SEEDS: dict[str, dict[str, Any]] = {
    "Web Attack - Sql Injection": {
        "seed_technique": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
        "next_steps": [
            {"tactic": "Execution", "technique": "Command and Scripting Interpreter", "id": "T1059"},
            {"tactic": "Credential Access", "technique": "Credentials from Web Applications", "id": "candidate"},
            {"tactic": "Exfiltration", "technique": "Exfiltration Over Web Service", "id": "T1567"},
        ],
        "mitigations": ["M1016 Vulnerability Scanning", "M1030 Network Segmentation", "M1035 Limit Access to Resource Over Network"],
        "confidence": "medium",
    },
    "PortScan": {
        "seed_technique": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        "next_steps": [
            {"tactic": "Discovery", "technique": "Remote System Discovery", "id": "T1018"},
            {"tactic": "Credential Access", "technique": "Brute Force", "id": "T1110"},
            {"tactic": "Lateral Movement", "technique": "Remote Services", "id": "T1021"},
        ],
        "mitigations": ["M1031 Network Intrusion Prevention", "M1030 Network Segmentation", "M1018 User Account Management"],
        "confidence": "medium",
    },
    "FTP-Patator": {
        "seed_technique": {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        "next_steps": [
            {"tactic": "Persistence", "technique": "Valid Accounts", "id": "T1078"},
            {"tactic": "Discovery", "technique": "File and Directory Discovery", "id": "T1083"},
            {"tactic": "Collection", "technique": "Data from Local System", "id": "T1005"},
        ],
        "mitigations": ["M1036 Account Use Policies", "M1032 Multi-factor Authentication", "M1027 Password Policies"],
        "confidence": "medium",
    },
    "Bot": {
        "seed_technique": {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
        "next_steps": [
            {"tactic": "Command and Control", "technique": "Application Layer Protocol", "id": "T1071"},
            {"tactic": "Execution", "technique": "Command and Scripting Interpreter", "id": "T1059"},
            {"tactic": "Impact", "technique": "Endpoint Denial of Service", "id": "T1499"},
        ],
        "mitigations": ["M1031 Network Intrusion Prevention", "M1037 Filter Network Traffic", "M1040 Behavior Prevention on Endpoint"],
        "confidence": "low",
    },
    "DDoS": {
        "seed_technique": {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
        "next_steps": [
            {"tactic": "Impact", "technique": "Endpoint Denial of Service", "id": "T1499"},
            {"tactic": "Command and Control", "technique": "Application Layer Protocol", "id": "T1071"},
        ],
        "mitigations": ["M1037 Filter Network Traffic", "M1030 Network Segmentation", "M1031 Network Intrusion Prevention"],
        "confidence": "medium",
    },
}


def _fallback_chain(ids_label: str | None, graph_context: dict[str, Any] | None, reason: str | None = None) -> dict[str, Any]:
    """Return the original static mapping with the new normalized fields."""

    label = ids_label or "unknown"
    seed = ATTACK_CHAIN_SEEDS.get(label)
    if not seed:
        return {
            "mode": "static_fallback",
            "graph_available": False,
            "seed": {
                "ids_label": label,
                "technique_id": None,
                "technique_name": None,
                "tactic": None,
            },
            "candidate_next_steps": [],
            "seed_technique": None,
            "likely_next_tactics_techniques": [],
            "mitigations": [],
            "vulnerability_context": {"capec": [], "cwes": [], "cves": []},
            "caveats": ["No static seed mapping is available for this IDS label."],
            "fallback_reason": reason,
            "confidence": "low",
        }
    caveats = [
        "This is a defensive hypothesis for prioritizing investigation, not an instruction sequence.",
        "Graph context and ATT&CK mappings provide contextual intelligence, not proof of attacker behavior.",
        "This output is not attribution and does not confirm compromise.",
    ]
    if reason:
        caveats.append("Neo4j unavailable; used static ATT&CK seed mapping.")
        caveats.append(f"Graph fallback reason: {reason}")
    if graph_context and not graph_context.get("cve_ids"):
        caveats.append("No CVE evidence is present in the supplied context.")
    seed_technique = seed["seed_technique"]
    candidate_next_steps = [
        {
            "technique_id": item.get("id"),
            "technique_name": item.get("technique"),
            "tactic": item.get("tactic"),
            "rationale": "Static ATT&CK seed mapping suggests this as a defensive investigation pivot.",
            "provenance": [{"source": "static_seed_mapping", "relationship_type": "STATIC_FALLBACK", "inferred": True}],
            "confidence": "low" if item.get("id") == "candidate" else "medium",
        }
        for item in seed["next_steps"]
    ]
    return {
        "mode": "static_fallback",
        "graph_available": False,
        "seed": {
            "ids_label": label,
            "technique_id": seed_technique.get("id"),
            "technique_name": seed_technique.get("name"),
            "tactic": seed_technique.get("tactic"),
        },
        "candidate_next_steps": candidate_next_steps,
        "seed_technique": seed_technique,
        "likely_next_tactics_techniques": seed["next_steps"],
        "mitigations": seed["mitigations"],
        "vulnerability_context": {"capec": [], "cwes": [], "cves": []},
        "caveats": caveats,
        "fallback_reason": reason,
        "confidence": seed["confidence"],
    }


def _node_props(node: Any) -> dict[str, Any]:
    """Return plain node properties."""

    return dict(node) if node is not None else {}


def _relationship_provenance(rel: Any, relationship_type: str, origin: str, target: str) -> dict[str, Any]:
    """Return compact relationship provenance."""

    props = dict(rel) if rel is not None else {}
    return {
        "source": props.get("source") or "Neo4j knowledge graph",
        "relationship_type": relationship_type,
        "inferred": bool(props.get("inferred", False)),
        "confidence": props.get("confidence"),
        "method": props.get("method"),
        "origin_node": origin,
        "target_node": target,
    }


def _get_seed_mapping(ids_label: str | None) -> dict[str, Any] | None:
    return ATTACK_CHAIN_SEEDS.get(ids_label or "")


def _query_graph_chain(driver: Any, database: str | None, ids_label: str, limit: int) -> dict[str, Any]:
    """Run bounded graph traversal from the seed ATT&CK technique."""

    seed_mapping = _get_seed_mapping(ids_label)
    if not seed_mapping:
        raise ValueError(f"No seed mapping exists for IDS label: {ids_label}")
    seed_id = seed_mapping["seed_technique"]["id"]
    query = """
    MATCH (seed)
    WHERE (seed:Technique OR seed:SubTechnique) AND seed.attack_id = $attack_id
    OPTIONAL MATCH (seed)-[tactic_rel:HAS_TACTIC]->(tactic:Tactic)
    OPTIONAL MATCH (seed)-[mit_rel:MITIGATED_BY]->(mitigation:Mitigation)
    OPTIONAL MATCH (seed)-[capec_rel:HAS_ATTACK_PATTERN]->(capec:CAPECPattern)
    OPTIONAL MATCH (capec)-[cwe_rel:RELATED_WEAKNESS]->(cwe:CWE)
    OPTIONAL MATCH (capec)-[cve_rel:ASSOCIATED_CVE]->(cve:CVE)
    WITH seed,
         collect(DISTINCT {node: tactic, rel: tactic_rel}) AS tactics,
         collect(DISTINCT {node: mitigation, rel: mit_rel}) AS mitigations,
         collect(DISTINCT {node: capec, rel: capec_rel}) AS capecs,
         collect(DISTINCT {node: cwe, rel: cwe_rel}) AS cwes,
         collect(DISTINCT {node: cve, rel: cve_rel}) AS cves
    OPTIONAL MATCH (seed)-[:HAS_TACTIC]->(same_tactic:Tactic)<-[same_rel:HAS_TACTIC]-(candidate)
    WHERE (candidate:Technique OR candidate:SubTechnique)
      AND candidate.attack_id <> seed.attack_id
    WITH seed, tactics, mitigations, capecs, cwes, cves,
         collect(DISTINCT {node: candidate, rel: same_rel, tactic: same_tactic, rank_group: "same_tactic"}) AS same_tactic_candidates
    OPTIONAL MATCH (seed)-[sub_rel:SUBTECHNIQUE_OF]-(sub_related)
    WHERE sub_related:Technique OR sub_related:SubTechnique
    WITH seed, tactics, mitigations, capecs, cwes, cves, same_tactic_candidates,
         collect(DISTINCT {node: sub_related, rel: sub_rel, tactic: null, rank_group: "subtechnique_related"}) AS sub_candidates
    RETURN seed, tactics, mitigations, capecs, cwes, cves, same_tactic_candidates + sub_candidates AS candidates
    LIMIT 1
    """
    with driver.session(database=database) as session:
        record = session.run(query, {"attack_id": seed_id}).single()
    if not record:
        raise LookupError(f"Seed ATT&CK technique not found in Neo4j: {seed_id}")

    seed_props = _node_props(record["seed"])
    tactics = [_node_props(item["node"]) for item in record["tactics"] if item.get("node") is not None]
    tactic_name = tactics[0].get("name") or tactics[0].get("short_name") if tactics else seed_mapping["seed_technique"].get("tactic")

    mitigations = []
    for item in record["mitigations"]:
        node = item.get("node")
        if node is None:
            continue
        props = _node_props(node)
        mid = props.get("attack_id")
        name = props.get("name")
        mitigations.append(
            {
                "id": mid,
                "name": name,
                "provenance": _relationship_provenance(item.get("rel"), "MITIGATED_BY", seed_id, str(mid)),
            }
        )

    capecs = []
    for item in record["capecs"]:
        node = item.get("node")
        if node is None:
            continue
        props = _node_props(node)
        capecs.append(
            {
                "id": props.get("capec_id"),
                "name": props.get("name"),
                "provenance": _relationship_provenance(item.get("rel"), "HAS_ATTACK_PATTERN", seed_id, str(props.get("capec_id"))),
            }
        )

    cwes = []
    for item in record["cwes"]:
        node = item.get("node")
        if node is None:
            continue
        props = _node_props(node)
        cwes.append(
            {
                "id": props.get("cwe_id"),
                "name": props.get("name"),
                "provenance": _relationship_provenance(item.get("rel"), "RELATED_WEAKNESS", "CAPEC", str(props.get("cwe_id"))),
            }
        )

    cves = []
    for item in record["cves"]:
        node = item.get("node")
        if node is None:
            continue
        props = _node_props(node)
        cves.append(
            {
                "id": props.get("cve_id"),
                "severity": props.get("severity"),
                "base_score": props.get("base_score"),
                "provenance": _relationship_provenance(item.get("rel"), "ASSOCIATED_CVE", "CAPEC", str(props.get("cve_id"))),
            }
        )

    candidates = []
    seen: set[str] = {seed_id}
    for item in record["candidates"]:
        node = item.get("node")
        if node is None:
            continue
        props = _node_props(node)
        attack_id = props.get("attack_id")
        if not attack_id or attack_id in seen:
            continue
        seen.add(attack_id)
        rank_group = item.get("rank_group")
        tactic_props = _node_props(item.get("tactic"))
        relationship_type = "SUBTECHNIQUE_OF" if rank_group == "subtechnique_related" else "HAS_TACTIC"
        rank = 1 if rank_group == "subtechnique_related" else 3
        candidates.append(
            {
                "rank": rank,
                "technique_id": attack_id,
                "technique_name": props.get("name"),
                "tactic": tactic_props.get("name") or tactic_props.get("short_name") or tactic_name,
                "rationale": (
                    "Direct subtechnique/parent relationship from the seed technique."
                    if rank_group == "subtechnique_related"
                    else "Shares a tactic with the seed technique; use as a bounded defensive investigation pivot."
                ),
                "provenance": [_relationship_provenance(item.get("rel"), relationship_type, seed_id, str(attack_id))],
                "confidence": "medium" if rank == 1 else "low",
            }
        )

    candidates = sorted(candidates, key=lambda row: (row["rank"], row["technique_id"]))[:limit]
    caveats = [
        "This is a defensive hypothesis for prioritizing investigation, not an instruction sequence.",
        "Graph traversal returns candidate investigation pivots; it does not prove compromise.",
        "Group, tool, and malware context must not be treated as attribution.",
    ]
    if not cves:
        caveats.append("No CVE evidence was reached from the graph traversal for this seed.")
    return {
        "mode": "graph",
        "graph_available": True,
        "seed": {
            "ids_label": ids_label,
            "technique_id": seed_props.get("attack_id") or seed_id,
            "technique_name": seed_props.get("name") or seed_mapping["seed_technique"].get("name"),
            "tactic": tactic_name,
        },
        "candidate_next_steps": candidates,
        "seed_technique": {
            "id": seed_props.get("attack_id") or seed_id,
            "name": seed_props.get("name") or seed_mapping["seed_technique"].get("name"),
            "tactic": tactic_name,
        },
        "likely_next_tactics_techniques": [
            {"id": item.get("technique_id"), "technique": item.get("technique_name"), "tactic": item.get("tactic")}
            for item in candidates
        ],
        "mitigations": mitigations or seed_mapping["mitigations"],
        "vulnerability_context": {
            "capec": capecs[:10],
            "cwes": cwes[:10],
            "cves": sorted(cves, key=lambda row: (-(row.get("base_score") or 0), row.get("id") or ""))[:10],
        },
        "caveats": caveats,
        "confidence": "medium" if candidates else "low",
    }


def predict_attack_chain(
    ids_label: str | None,
    graph_context: dict[str, Any] | None = None,
    use_graph: bool = True,
    candidate_limit: int = 5,
    driver: Any | None = None,
    database: str | None = None,
) -> dict[str, Any]:
    """Return a bounded defensive chain hypothesis for the IDS label."""

    if not use_graph:
        return _fallback_chain(ids_label, graph_context)

    owns_driver = driver is None
    try:
        from src.graph.neo4j_utils import get_driver, get_neo4j_config

        cfg = get_neo4j_config()
        active_driver = driver or get_driver(cfg)
        active_database = database if database is not None else cfg.database
        return _query_graph_chain(active_driver, active_database, ids_label or "unknown", candidate_limit)
    except Exception as exc:
        return _fallback_chain(ids_label, graph_context, str(exc))
    finally:
        if owns_driver and "active_driver" in locals():
            active_driver.close()
