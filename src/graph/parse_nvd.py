"""Parse local NVD/CVE JSON feeds for TrustSecAI graph ingestion."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.graph.cwe_builder import normalize_cwe_id
from src.utils.paths import DATASETS_DIR


NVD_DIR = DATASETS_DIR / "NVD"


@dataclass
class NvdParseResult:
    """Parsed NVD payload."""

    source_files: list[str]
    ingested_at: str
    cves: list[dict[str, Any]] = field(default_factory=list)
    products: list[dict[str, Any]] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)
    has_weakness: list[dict[str, Any]] = field(default_factory=list)
    affects: list[dict[str, Any]] = field(default_factory=list)
    reference_edges: list[dict[str, Any]] = field(default_factory=list)
    cwe_ids: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)
    rejected_cves: list[str] = field(default_factory=list)


def nvd_files(nvd_dir: Path = NVD_DIR) -> list[Path]:
    """Return local NVD JSON feeds in deterministic order."""

    names = [
        "nvdcve-2.0-2023.json",
        "nvdcve-2.0-2024.json",
        "nvdcve-2.0-2025.json",
        "nvdcve-2.0-2026.json",
        "nvdcve-2.0-modified.json",
        "nvdcve-2.0-recent.json",
    ]
    return [nvd_dir / name for name in names if (nvd_dir / name).exists()]


def english_description(descriptions: list[dict[str, Any]]) -> str:
    """Return English CVE description."""

    for item in descriptions or []:
        if item.get("lang") == "en":
            return item.get("value") or ""
    return (descriptions or [{}])[0].get("value", "") if descriptions else ""


def best_cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    """Extract best available CVSS metric."""

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            metric = values[0]
            data = metric.get("cvssData", {})
            return {
                "cvss_version": data.get("version") or key,
                "severity": data.get("baseSeverity") or metric.get("baseSeverity") or "UNSCORED",
                "base_score": data.get("baseScore"),
                "vector_string": data.get("vectorString"),
                "attack_vector": data.get("attackVector"),
                "attack_complexity": data.get("attackComplexity"),
                "privileges_required": data.get("privilegesRequired"),
                "user_interaction": data.get("userInteraction"),
                "scope": data.get("scope"),
                "confidentiality_impact": data.get("confidentialityImpact"),
                "integrity_impact": data.get("integrityImpact"),
                "availability_impact": data.get("availabilityImpact"),
            }
    return {"severity": "UNSCORED", "base_score": None}


def parse_cpe_uri(cpe_uri: str) -> dict[str, str]:
    """Parse basic vendor/product/version fields from CPE 2.3 URI."""

    parts = cpe_uri.split(":")
    return {
        "part": parts[2] if len(parts) > 2 else "",
        "vendor": parts[3] if len(parts) > 3 else "",
        "product": parts[4] if len(parts) > 4 else "",
        "version": parts[5] if len(parts) > 5 else "",
    }


def iter_cpe_matches(config: Any):
    """Yield cpeMatch dictionaries recursively from NVD configurations."""

    if isinstance(config, dict):
        for match in config.get("cpeMatch", []) or []:
            yield match
        for node in config.get("nodes", []) or []:
            yield from iter_cpe_matches(node)
    elif isinstance(config, list):
        for item in config:
            yield from iter_cpe_matches(item)


def parse_nvd(nvd_dir: Path = NVD_DIR) -> NvdParseResult:
    """Parse local NVD feeds and deduplicate CVEs by latest lastModified."""

    files = nvd_files(nvd_dir)
    ingested_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    latest: dict[str, tuple[str, dict[str, Any], str]] = {}

    for path in files:
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            last_modified = cve.get("lastModified") or ""
            if cve_id not in latest or last_modified >= latest[cve_id][0]:
                latest[cve_id] = (last_modified, cve, str(path))

    result = NvdParseResult(source_files=[str(path) for path in files], ingested_at=ingested_at)
    products_by_uri: dict[str, dict[str, Any]] = {}
    refs_by_url: dict[str, dict[str, Any]] = {}

    for _, cve, source_file in latest.values():
        cve_id = cve.get("id")
        status = cve.get("vulnStatus")
        if status == "Rejected":
            result.rejected_cves.append(cve_id)
            continue
        cvss = best_cvss(cve.get("metrics") or {})
        node = {
            "cve_id": cve_id,
            "description": english_description(cve.get("descriptions") or []),
            "source_identifier": cve.get("sourceIdentifier"),
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "status": status,
            "source": "NVD",
            "source_file": source_file,
            "raw_id": cve_id,
            "ingested_at": ingested_at,
            **cvss,
        }
        result.cves.append(node)

        for weakness in cve.get("weaknesses", []) or []:
            for description in weakness.get("description", []) or []:
                cwe_id = normalize_cwe_id(description.get("value") or "")
                if not cwe_id:
                    continue
                result.cwe_ids.add(cwe_id)
                result.has_weakness.append(
                    {
                        "source_id": cve_id,
                        "target_id": cwe_id,
                        "raw_relationship_id": f"{cve_id}:HAS_WEAKNESS:{cwe_id}",
                        "source": "NVD",
                        "source_file": source_file,
                        "confidence": "source",
                        "inferred": False,
                        "ingested_at": ingested_at,
                    }
                )

        for match in iter_cpe_matches(cve.get("configurations") or []):
            cpe_uri = match.get("criteria") or match.get("cpe23Uri")
            if not cpe_uri:
                continue
            product = {
                "cpe_uri": cpe_uri,
                **parse_cpe_uri(cpe_uri),
                "source": "NVD",
                "source_file": source_file,
                "raw_id": cpe_uri,
                "ingested_at": ingested_at,
            }
            products_by_uri[cpe_uri] = product
            result.affects.append(
                {
                    "source_id": cve_id,
                    "target_id": cpe_uri,
                    "raw_relationship_id": f"{cve_id}:AFFECTS:{cpe_uri}",
                    "source": "NVD",
                    "source_file": source_file,
                    "vulnerable": bool(match.get("vulnerable", True)),
                    "version_start_including": match.get("versionStartIncluding"),
                    "version_start_excluding": match.get("versionStartExcluding"),
                    "version_end_including": match.get("versionEndIncluding"),
                    "version_end_excluding": match.get("versionEndExcluding"),
                    "confidence": "source",
                    "inferred": False,
                    "ingested_at": ingested_at,
                }
            )

        for ref in cve.get("references", []) or []:
            url = ref.get("url")
            if not url:
                continue
            refs_by_url[url] = {
                "url": url,
                "name": ref.get("source"),
                "tags": ref.get("tags") or [],
                "source": "NVD",
                "source_file": source_file,
                "raw_id": url,
                "ingested_at": ingested_at,
            }
            result.reference_edges.append(
                {
                    "source_id": cve_id,
                    "target_id": url,
                    "raw_relationship_id": f"{cve_id}:REFERENCES:{url}",
                    "source": "NVD",
                    "source_file": source_file,
                    "tags": ref.get("tags") or [],
                    "confidence": "source",
                    "inferred": False,
                    "ingested_at": ingested_at,
                }
            )

    result.products = list(products_by_uri.values())
    result.references = list(refs_by_url.values())
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parse local NVD feeds.")
    parser.add_argument("--nvd-dir", type=Path, default=NVD_DIR)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    parsed = parse_nvd(args.nvd_dir)
    print(json.dumps({
        "cves": len(parsed.cves),
        "products": len(parsed.products),
        "references": len(parsed.references),
        "has_weakness": len(parsed.has_weakness),
        "affects": len(parsed.affects),
        "reference_edges": len(parsed.reference_edges),
        "cwe_ids": len(parsed.cwe_ids),
        "rejected_cves": len(parsed.rejected_cves),
    }, indent=2))


if __name__ == "__main__":
    main()

