"""Create a spreadsheet-friendly review workbook for gold-candidate v1.

The environment may not have openpyxl/xlsxwriter installed, so this script
creates a minimal XLSX workbook directly with the Office Open XML format and
also writes a CSV fallback for later decision import.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import zipfile
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape


ROOT = Path(__file__).resolve().parents[2]
V1_DIR = ROOT / "artifacts" / "gold_candidates" / "v1"
DATASET_PATH = V1_DIR / "trustsecai_gold_candidate_v1.jsonl"
MANIFEST_PATH = V1_DIR / "review_manifest.csv"
WORKBOOK_PATH = V1_DIR / "review_workbook.xlsx"
CSV_PATH = V1_DIR / "review_workbook.csv"
REPORT_PATH = ROOT / "reports" / "gold_candidate_v1_review_workbook_report.md"

REVIEW_COLUMNS = [
    "review_status",
    "reviewer_decision",
    "reviewer_notes",
    "needs_revision",
    "revised_output",
    "example_id",
    "base_context_id",
    "sample_id",
    "split",
    "ids_label",
    "model_prediction",
    "model_confidence",
    "confidence_band",
    "task_type",
    "difficulty",
    "source_file",
    "provenance_type",
    "has_real_shap",
    "has_cve",
    "has_inferred_edges",
    "attack_technique_id",
    "tactic_ids",
    "mitigation_ids",
    "capec_ids",
    "cwe_ids",
    "cve_ids",
    "shap_top_features",
    "instruction",
    "input_summary",
    "output_text",
    "grounding_check",
    "uncertainty_check",
    "attribution_check",
    "graph_not_proof_check",
    "shap_check",
    "tone_check",
]

EDITABLE_COLUMNS = {
    "reviewer_decision",
    "reviewer_notes",
    "needs_revision",
    "revised_output",
    "grounding_check",
    "uncertainty_check",
    "attribution_check",
    "graph_not_proof_check",
    "shap_check",
    "tone_check",
}

WRAP_COLUMNS = {"instruction", "input_summary", "output_text", "revised_output", "reviewer_notes"}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load JSONL records."""

    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_manifest_ids(path: Path) -> list[str]:
    """Load review sample IDs from review manifest in manifest order."""

    with path.open(newline="", encoding="utf-8") as handle:
        return [row["example_id"] for row in csv.DictReader(handle)]


def load_split_map() -> dict[str, str]:
    """Map example ID to train/validation/test split."""

    split_map: dict[str, str] = {}
    for split in ["train", "validation", "test"]:
        path = V1_DIR / f"{split}.jsonl"
        if not path.exists():
            continue
        for record in load_jsonl(path):
            split_map[record["metadata"]["example_id"]] = split
    return split_map


def compact_json(value: Any, limit: int = 26000) -> str:
    """Serialize structured content compactly for spreadsheet cells."""

    text = json.dumps(value, ensure_ascii=False, indent=2)
    if len(text) > limit:
        return text[: limit - 30] + "\n... [truncated for spreadsheet]"
    return text


def ids(values: list[Any]) -> str:
    """Join identifiers for review display."""

    return "; ".join(str(v) for v in values if v)


def shap_features(record: dict[str, Any], limit: int = 4) -> str:
    """Format top SHAP features for review."""

    features = record["input"]["shap"]["top_features"][:limit]
    parts = []
    for feature in features:
        parts.append(
            f"{feature['feature']}={float(feature['value']):.4g}, "
            f"SHAP={float(feature['shap_value']):+.4f}, {feature['direction']}"
        )
    return "; ".join(parts)


def input_summary(record: dict[str, Any]) -> str:
    """Create compact human-readable input summary."""

    meta = record["metadata"]
    graph = record["input"]["graph_context"]
    completeness = graph.get("evidence_completeness", {})
    gaps = []
    if not completeness.get("has_cve"):
        gaps.append("no CVE evidence")
    if not completeness.get("has_asset_exposure_evidence"):
        gaps.append("no asset exposure evidence")
    if completeness.get("has_inferred_edges"):
        gaps.append("contains inferred graph edges")
    return (
        f"IDS label: {meta['ids_label']} | Binary prediction: {meta['model_prediction']} | "
        f"Confidence: {float(meta['model_confidence']):.2%} ({meta['confidence_band']}) | "
        f"Top SHAP: {shap_features(record)} | ATT&CK: {graph.get('attack_technique_id')} | "
        f"Tactics: {ids(graph.get('tactic_ids', [])) or 'none'} | "
        f"Mitigations: {ids(graph.get('mitigation_ids', [])) or 'none'} | "
        f"CVEs: {'present' if meta['has_cve'] else 'absent'} | "
        f"Provenance: {meta['provenance_type']} | Evidence gaps: {', '.join(gaps) if gaps else 'none flagged'}"
    )


def flatten_review_row(record: dict[str, Any], split_map: dict[str, str]) -> dict[str, Any]:
    """Flatten one review record into workbook columns."""

    meta = record["metadata"]
    graph = record["input"]["graph_context"]
    completeness = graph.get("evidence_completeness", {})
    row = {
        "review_status": meta.get("review_status", "candidate_unreviewed"),
        "reviewer_decision": "pending",
        "reviewer_notes": "",
        "needs_revision": "no",
        "revised_output": "",
        "example_id": meta["example_id"],
        "base_context_id": meta["base_context_id"],
        "sample_id": meta["sample_id"],
        "split": split_map.get(meta["example_id"], ""),
        "ids_label": meta["ids_label"],
        "model_prediction": meta["model_prediction"],
        "model_confidence": meta["model_confidence"],
        "confidence_band": meta["confidence_band"],
        "task_type": meta["task_type"],
        "difficulty": meta["difficulty"],
        "source_file": meta["source_file"],
        "provenance_type": meta["provenance_type"],
        "has_real_shap": meta["has_real_shap"],
        "has_cve": meta["has_cve"],
        "has_inferred_edges": completeness.get("has_inferred_edges", False),
        "attack_technique_id": graph.get("attack_technique_id", ""),
        "tactic_ids": ids(graph.get("tactic_ids", [])),
        "mitigation_ids": ids(graph.get("mitigation_ids", [])),
        "capec_ids": ids(graph.get("capec_ids", [])),
        "cwe_ids": ids(graph.get("cwe_ids", [])),
        "cve_ids": ids(graph.get("cve_ids", [])),
        "shap_top_features": shap_features(record),
        "instruction": record["instruction"],
        "input_summary": input_summary(record),
        "output_text": compact_json(record["output"]),
        "grounding_check": "pending",
        "uncertainty_check": "pending",
        "attribution_check": "pending",
        "graph_not_proof_check": "pending",
        "shap_check": "pending",
        "tone_check": "pending",
    }
    return row


def make_review_rows() -> list[dict[str, Any]]:
    """Build flattened review rows from v1 dataset and manifest."""

    records = {record["metadata"]["example_id"]: record for record in load_jsonl(DATASET_PATH)}
    split_map = load_split_map()
    rows = []
    for example_id in load_manifest_ids(MANIFEST_PATH):
        if example_id in records:
            rows.append(flatten_review_row(records[example_id], split_map))
    return rows


def write_csv(rows: list[dict[str, Any]]) -> None:
    """Write machine-readable CSV fallback."""

    CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CSV_PATH.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=REVIEW_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def col_letter(index: int) -> str:
    """Convert 1-based column index to Excel letters."""

    letters = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def cell_xml(row_idx: int, col_idx: int, value: Any, style: int = 0) -> str:
    """Render one XLSX cell using inline strings or numbers."""

    ref = f"{col_letter(col_idx)}{row_idx}"
    style_attr = f' s="{style}"' if style else ""
    if value is None:
        value = ""
    if isinstance(value, bool):
        value = "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{ref}"{style_attr}><v>{value}</v></c>'
    text = escape(str(value), {'"': "&quot;"})
    return f'<c r="{ref}" t="inlineStr"{style_attr}><is><t xml:space="preserve">{text}</t></is></c>'


def sheet_xml(
    name: str,
    rows: list[list[Any]],
    widths: dict[int, float] | None = None,
    autofilter: bool = True,
    freeze_header: bool = True,
    editable_cols: set[int] | None = None,
    wrap_cols: set[int] | None = None,
    validations: list[tuple[str, str]] | None = None,
) -> str:
    """Render a worksheet XML document."""

    widths = widths or {}
    editable_cols = editable_cols or set()
    wrap_cols = wrap_cols or set()
    max_col = max((len(row) for row in rows), default=1)
    max_row = len(rows)
    parts = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>']
    parts.append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">')
    if freeze_header:
        parts.append('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft"/></sheetView></sheetViews>')
    if widths:
        parts.append("<cols>")
        for idx in range(1, max_col + 1):
            width = widths.get(idx, 14)
            parts.append(f'<col min="{idx}" max="{idx}" width="{width}" customWidth="1"/>')
        parts.append("</cols>")
    parts.append("<sheetData>")
    for r_idx, row in enumerate(rows, start=1):
        parts.append(f'<row r="{r_idx}">')
        for c_idx, value in enumerate(row, start=1):
            style = 1 if r_idx == 1 else 0
            if r_idx > 1 and c_idx in editable_cols:
                style = 3
            elif r_idx > 1 and c_idx in wrap_cols:
                style = 2
            parts.append(cell_xml(r_idx, c_idx, value, style))
        parts.append("</row>")
    parts.append("</sheetData>")
    if autofilter and rows:
        parts.append(f'<autoFilter ref="A1:{col_letter(max_col)}{max_row}"/>')
    if validations:
        parts.append(f'<dataValidations count="{len(validations)}">')
        for sqref, formula in validations:
            parts.append(f'<dataValidation type="list" allowBlank="1" showErrorMessage="1" sqref="{sqref}"><formula1>"{formula}"</formula1></dataValidation>')
        parts.append("</dataValidations>")
    parts.append("</worksheet>")
    return "".join(parts)


def workbook_xml(sheet_names: list[str]) -> str:
    """Render workbook XML."""

    sheets = "".join(
        f'<sheet name="{escape(name)}" sheetId="{idx}" r:id="rId{idx}"/>'
        for idx, name in enumerate(sheet_names, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{sheets}</sheets></workbook>"
    )


def workbook_rels(sheet_names: list[str]) -> str:
    """Render workbook relationships."""

    rels = []
    for idx in range(1, len(sheet_names) + 1):
        rels.append(f'<Relationship Id="rId{idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{idx}.xml"/>')
    rels.append(f'<Relationship Id="rId{len(sheet_names)+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(rels)
        + "</Relationships>"
    )


def content_types(sheet_count: int) -> str:
    """Render XLSX content types."""

    overrides = [
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
    ]
    for idx in range(1, sheet_count + 1):
        overrides.append(f'<Override PartName="/xl/worksheets/sheet{idx}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        + "".join(overrides)
        + "</Types>"
    )


def root_rels() -> str:
    """Render root package relationships."""

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )


def styles_xml() -> str:
    """Render simple workbook styles."""

    return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>
  <fills count="4"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FFD9EAF7"/><bgColor indexed="64"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFF2CC"/><bgColor indexed="64"/></patternFill></fill></fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="4">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"><alignment wrapText="1" vertical="top"/></xf>
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"><alignment wrapText="1" vertical="top"/></xf>
    <xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1"><alignment wrapText="1" vertical="top"/></xf>
  </cellXfs>
</styleSheet>"""


def instructions_rows() -> list[list[Any]]:
    """Build Review_Instructions sheet rows."""

    return [
        ["TrustSecAI Gold-Candidate v1 Human Review Workbook"],
        ["Purpose", "Review selected candidate SFT examples and mark approve, revise, or reject."],
        ["Decision options", "pending, approve, revise, reject"],
        ["Revision workflow", "Set needs_revision=yes and write revised_output when reviewer_decision=revise."],
        ["Binary classifier confidence", "model_prediction is BENIGN or ATTACK only; model_confidence is binary confidence."],
        ["IDS subtype", "IDS subtype comes from the CICIDS ground-truth label used for retrieval, not multiclass model probability."],
        ["GraphRAG context", "Graph context is contextual intelligence, not proof of compromise."],
        ["CVE context", "CVEs are candidate context unless asset exposure evidence exists."],
        ["Attribution safety", "ATT&CK group/tool/malware links are usage context only and are not attribution."],
        ["Checklist 1", "Is every factual claim grounded in supplied evidence?"],
        ["Checklist 2", "Is uncertainty appropriate?"],
        ["Checklist 3", "Does SHAP wording reflect the real top features?"],
        ["Checklist 4", "Does the output avoid treating graph context as confirmed compromise?"],
        ["Checklist 5", "Is the tone appropriate for the task?"],
    ]


def summary_rows(rows: list[dict[str, Any]]) -> list[list[Any]]:
    """Build Summary_By_Task rows with multiple dimensions."""

    out = [["dimension", "value", "count"]]
    for dimension in ["task_type", "difficulty", "ids_label", "confidence_band", "has_cve", "provenance_type"]:
        for value, count in Counter(str(row[dimension]) for row in rows).most_common():
            out.append([dimension, value, count])
    return out


def summary_by_label_rows(rows: list[dict[str, Any]]) -> list[list[Any]]:
    """Build label coverage summary."""

    labels = sorted({row["ids_label"] for row in rows})
    out = [["ids_label", "count", "high", "medium", "low", "cve_present", "cve_absent", "tasks"]]
    for label in labels:
        subset = [row for row in rows if row["ids_label"] == label]
        conf = Counter(row["confidence_band"] for row in subset)
        cve = Counter(str(row["has_cve"]) for row in subset)
        tasks = ", ".join(f"{task}:{count}" for task, count in Counter(row["task_type"] for row in subset).most_common())
        out.append([label, len(subset), conf.get("high", 0), conf.get("medium", 0), conf.get("low", 0), cve.get("True", 0), cve.get("False", 0), tasks])
    return out


def high_risk_rows(rows: list[dict[str, Any]]) -> list[list[Any]]:
    """Build high-risk review sheet rows."""

    header = REVIEW_COLUMNS
    high_risk_tasks = {"vulnerability_context", "uncertainty_evidence_gap", "multi_turn_analyst_interaction"}
    selected = [
        row
        for row in rows
        if row["confidence_band"] in {"low", "medium"}
        or str(row["has_cve"]) == "True"
        or str(row["has_inferred_edges"]) == "True"
        or row["task_type"] in high_risk_tasks
    ]
    return [header] + [[row.get(col, "") for col in header] for row in selected]


def near_duplicate_rows(rows: list[dict[str, Any]]) -> list[list[Any]]:
    """Build near-duplicate review sheet from same base_context_id/task_type groups."""

    header = ["group_key"] + REVIEW_COLUMNS
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["base_context_id"], row["task_type"])].append(row)
    out = [header]
    for key, group in grouped.items():
        if len(group) > 1:
            group_key = " | ".join(key)
            for row in group:
                out.append([group_key] + [row.get(col, "") for col in REVIEW_COLUMNS])
    return out


def column_widths(headers: list[str]) -> dict[int, float]:
    """Assign practical column widths."""

    widths = {}
    for idx, header in enumerate(headers, start=1):
        if header in {"instruction", "input_summary", "output_text", "revised_output"}:
            widths[idx] = 60
        elif header in {"reviewer_notes", "shap_top_features"}:
            widths[idx] = 42
        elif header.endswith("_ids"):
            widths[idx] = 26
        elif header in {"example_id", "base_context_id", "source_file"}:
            widths[idx] = 34
        else:
            widths[idx] = 18
    return widths


def make_workbook(rows: list[dict[str, Any]]) -> None:
    """Create the XLSX workbook."""

    review_all = [REVIEW_COLUMNS] + [[row.get(col, "") for col in REVIEW_COLUMNS] for row in rows]
    sheets = {
        "Review_Instructions": instructions_rows(),
        "Review_All": review_all,
        "Summary_By_Task": summary_rows(rows),
        "Summary_By_Label": summary_by_label_rows(rows),
        "High_Risk_Review": high_risk_rows(rows),
        "Near_Duplicate_Review": near_duplicate_rows(rows),
    }
    sheet_names = list(sheets)
    editable_idx = {idx for idx, col in enumerate(REVIEW_COLUMNS, start=1) if col in EDITABLE_COLUMNS}
    wrap_idx = {idx for idx, col in enumerate(REVIEW_COLUMNS, start=1) if col in WRAP_COLUMNS}
    validations = [
        (f"B2:B{len(review_all)}", "pending,approve,revise,reject"),
        (f"D2:D{len(review_all)}", "yes,no"),
    ]
    for col in ["grounding_check", "uncertainty_check", "attribution_check", "graph_not_proof_check", "shap_check", "tone_check"]:
        letter = col_letter(REVIEW_COLUMNS.index(col) + 1)
        validations.append((f"{letter}2:{letter}{len(review_all)}", "pending,pass,fail,unsure"))

    with zipfile.ZipFile(WORKBOOK_PATH, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types(len(sheet_names)))
        archive.writestr("_rels/.rels", root_rels())
        archive.writestr("xl/workbook.xml", workbook_xml(sheet_names))
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels(sheet_names))
        archive.writestr("xl/styles.xml", styles_xml())
        for idx, name in enumerate(sheet_names, start=1):
            data = sheets[name]
            if name == "Review_All":
                xml = sheet_xml(name, data, column_widths(REVIEW_COLUMNS), True, True, editable_idx, wrap_idx, validations)
            elif name in {"High_Risk_Review", "Near_Duplicate_Review"}:
                headers = data[0] if data else REVIEW_COLUMNS
                xml = sheet_xml(name, data, column_widths(headers), True, True, set(), set(range(1, len(headers) + 1)), None)
            else:
                xml = sheet_xml(name, data, {1: 28, 2: 90, 3: 16}, True, True, set(), {2}, None)
            archive.writestr(f"xl/worksheets/sheet{idx}.xml", xml)


def write_report(rows: list[dict[str, Any]]) -> None:
    """Write workbook generation report."""

    lines = [
        "# Gold-Candidate v1 Review Workbook Report",
        "",
        f"Created: {date.today().isoformat()}",
        "",
        f"- Workbook path: `{WORKBOOK_PATH.as_posix()}`",
        f"- CSV path: `{CSV_PATH.as_posix()}`",
        f"- Review rows: {len(rows)}",
        f"- Examples by task: {dict(Counter(row['task_type'] for row in rows))}",
        f"- Examples by IDS label: {dict(Counter(row['ids_label'] for row in rows))}",
        f"- Examples by confidence band: {dict(Counter(row['confidence_band'] for row in rows))}",
        f"- CVE present/absent: {dict(Counter('cve_present' if str(row['has_cve']) == 'True' else 'cve_absent' for row in rows))}",
        "",
        "## Reviewer Workflow",
        "",
        "1. Open `review_workbook.xlsx` and work mainly in the `Review_All` sheet.",
        "2. Use dropdowns to set `reviewer_decision` to approve, revise, or reject.",
        "3. If revising, set `needs_revision=yes` and write the corrected target in `revised_output`.",
        "4. Use the check columns to mark grounding, uncertainty, attribution, graph-proof, SHAP, and tone review.",
        "5. Save the workbook and/or export decisions through `review_workbook.csv` for the later approved-dataset task.",
        "",
        "No dataset examples were modified by this script.",
    ]
    REPORT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""

    parser = argparse.ArgumentParser(description="Create TrustSecAI gold-candidate v1 review workbook.")
    parser.add_argument("--dataset", type=Path, default=DATASET_PATH)
    parser.add_argument("--manifest", type=Path, default=MANIFEST_PATH)
    return parser.parse_args()


def main() -> None:
    """CLI entrypoint."""

    args = parse_args()
    global DATASET_PATH, MANIFEST_PATH
    DATASET_PATH = args.dataset
    MANIFEST_PATH = args.manifest
    rows = make_review_rows()
    write_csv(rows)
    make_workbook(rows)
    write_report(rows)


if __name__ == "__main__":
    main()
