"""
ede_audit_tool.py — Agentilizer v2.0
Excessive Data Exposure Audit Tool for n8n Workflows

Standalone CLI that audits n8n workflow JSON files for Excessive Data Exposure (EDE),
producing human-readable text reports or machine-readable JSON output.

Usage:
    python ede_audit_tool.py --workflow path/to/workflow.json
    python ede_audit_tool.py --folder  path/to/workflows/
    python ede_audit_tool.py --workflow workflow.json --output report.txt
    python ede_audit_tool.py --workflow workflow.json --format json
    python ede_audit_tool.py --version

Research: Ali, S. (2026). Data Minimization for Agentic AI.
          Leeds Beckett University MSc Cyber Security.
"""

import sys
import io
import json
import argparse
import sqlite3
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pii_taxonomy import detect_pii, PII_CATEGORIES, is_pii as _is_pii, pii_category
from exposure_core import (
    calc_exposure, FUNCTIONAL_FIELDS, extract_leaf_fields, leaf_name
)
from node_scope import classify_scope

# ── Windows UTF-8 fix ─────────────────────────────────────────────────────────
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

VERSION      = "2.0"
TOOL_NAME    = "Agentilizer"
TOOL_FULL    = f"{TOOL_NAME} v{VERSION}"
RESEARCH_REF = (
    "O. Illiashenko and S. Ali, 'Measuring Excessive Data Exposure in\n"
    "Agentic AI Workflow Automation,' IEEE DESSERT 2026."
)

# Fields that control workflow routing — never counted as unnecessary EDE
SKIP_NODE_TYPES = frozenset({
    "stickynote", "noOp", "manualTrigger", "start", "stickyNote",
})

RISK_THRESHOLDS = [
    (0.70, "HIGH"),
    (0.40, "MEDIUM"),
    (0.20, "LOW"),
    (0.00, "MINIMAL"),
]


# ── Data classes ──────────────────────────────────────────────────────────────
@dataclass
class NodeResult:
    position:           int
    node_name:          str
    node_type:          str
    short_type:         str
    node_scope:         str
    status:             str
    fields_passed:      int   = 0
    fields_required:    int   = 0
    fields_unnecessary: int   = 0
    overexposure_ratio: float = 0.0
    unnecessary_fields: list  = field(default_factory=list)
    pii_exposed:        list  = field(default_factory=list)
    pii_unnecessary:    list  = field(default_factory=list)
    pii_via_expression: int   = 0
    gdpr_concern:       str   = "NO"


@dataclass
class WorkflowResult:
    filename:           str
    timestamp:          str
    nodes_total:        int
    nodes_assessed:     int
    nodes_unassessed:   int
    risk_level:         str
    avg_ede:            float
    nodes_with_ede:     int
    unnecessary_pii_total: int
    gdpr_concerns:      int
    node_results:       list[NodeResult] = field(default_factory=list)


# ── Registry loader ───────────────────────────────────────────────────────────
def load_registry(db_path: Path) -> tuple[dict, dict, int, int]:
    """Load field registry from SQLite database."""
    con = sqlite3.connect(str(db_path))
    global_reg: dict[str, dict] = {}
    for node_name, field_name, required, is_pii, pii_confidence in con.execute(
        "SELECT node_name, field_name, required, is_pii, pii_confidence FROM nodes"
    ):
        key = node_name.lower()
        if key not in global_reg:
            global_reg[key] = {"required": set(), "optional": set(),
                               "all_pii": set(), "pii_confidence_map": {}}
        if required:
            global_reg[key]["required"].add(field_name)
        else:
            global_reg[key]["optional"].add(field_name)
        if is_pii:
            global_reg[key]["all_pii"].add(field_name)
            global_reg[key]["pii_confidence_map"][field_name] = pii_confidence or ""

    op_reg: dict[str, dict] = {}
    for node_name, operation, resource, req_json in con.execute(
        "SELECT node_name, operation, resource, required_fields FROM node_operations"
    ):
        key = node_name.lower()
        if key not in op_reg:
            op_reg[key] = {}
        try:
            req_fields = frozenset(json.loads(req_json)) - FUNCTIONAL_FIELDS
        except Exception:
            req_fields = frozenset()
        op_reg[key][(operation.lower(), resource.lower())] = req_fields

    node_count = len(global_reg)
    op_count   = sum(len(v) for v in op_reg.values())
    con.close()
    return global_reg, op_reg, node_count, op_count


# ── PII detection (delegates to pii_taxonomy) ─────────────────────────────────
def is_pii(field_name: str) -> bool:
    return _is_pii(field_name)


# ── Node analysis ─────────────────────────────────────────────────────────────
def extract_short_name(node_type: str) -> str:
    return node_type.split(".")[-1].lower()


def get_required_fields(
    short_name: str,
    operation:  str,
    resource:   str,
    global_reg: dict,
    op_reg:     dict,
) -> Optional[frozenset]:
    op_val  = (operation or "*").lower()
    res_val = (resource  or "*").lower()
    if short_name in op_reg:
        combos = op_reg[short_name]
        for key in [(op_val, res_val), (op_val, "*"), ("*", res_val), ("*", "*")]:
            if key in combos:
                return combos[key]
    if short_name in global_reg:
        return frozenset(global_reg[short_name]["required"]) - FUNCTIONAL_FIELDS
    return None


def analyse_node(
    node:       dict,
    position:   int,
    global_reg: dict,
    op_reg:     dict,
) -> NodeResult:
    node_type  = node.get("type", "")
    node_name  = node.get("name", f"Node#{position}")
    short_type = extract_short_name(node_type)
    scope      = classify_scope(node_type)

    if short_type in SKIP_NODE_TYPES:
        return NodeResult(
            position=position, node_name=node_name,
            node_type=node_type, short_type=short_type,
            node_scope=scope, status="unassessed",
        )

    params    = node.get("parameters", {}) or {}
    operation = str(params.get("operation", "")).strip() or "*"
    resource  = str(params.get("resource",  "")).strip() or "*"
    required  = get_required_fields(short_type, operation, resource, global_reg, op_reg)

    if required is None:
        return NodeResult(
            position=position, node_name=node_name,
            node_type=node_type, short_type=short_type,
            node_scope=scope, status="unassessed",
        )

    reg_entry    = global_reg.get(short_type, {})
    all_pii_set  = reg_entry.get("all_pii", set())
    pii_conf_map = reg_entry.get("pii_confidence_map", {})

    exp = calc_exposure(
        params,
        set(required),
        all_pii_set,
        pii_confidence_map=pii_conf_map,
    )

    unnecessary   = exp["unnecessary_field_names"]
    pii_unnec     = exp["pii_unnecessary_names"]
    pii_exposed_l = [n for n in exp["leaf_fields"] if is_pii(leaf_name(n))]

    if pii_unnec:
        gdpr = "YES"
    elif unnecessary:
        gdpr = "DM(non-PII)"
    else:
        gdpr = "NO"

    return NodeResult(
        position=position,
        node_name=node_name,
        node_type=node_type,
        short_type=short_type,
        node_scope=scope,
        status="assessed",
        fields_passed=exp["fields_passed"],
        fields_required=exp["fields_required"],
        fields_unnecessary=exp["fields_unnecessary"],
        overexposure_ratio=exp["overexposure_ratio"],
        unnecessary_fields=unnecessary,
        pii_exposed=[leaf_name(p) for p in pii_exposed_l],
        pii_unnecessary=pii_unnec,
        pii_via_expression=exp["pii_via_expression"],
        gdpr_concern=gdpr,
    )


# ── Workflow-level analysis ───────────────────────────────────────────────────
def analyse_workflow(
    workflow_path: Path,
    global_reg:    dict,
    op_reg:        dict,
) -> Optional[WorkflowResult]:
    try:
        raw = workflow_path.read_text(encoding="utf-8", errors="replace")
        wf  = json.loads(raw)
    except Exception:
        return None

    nodes = wf.get("nodes")
    if not isinstance(nodes, list) or len(nodes) == 0:
        return None

    results: list[NodeResult] = []
    for pos, node in enumerate(nodes):
        if not isinstance(node, dict) or "type" not in node:
            continue
        results.append(analyse_node(node, pos, global_reg, op_reg))

    assessed   = [r for r in results if r.status == "assessed"]
    unassessed = [r for r in results if r.status == "unassessed"]

    avg_ede = (sum(r.overexposure_ratio for r in assessed) / len(assessed)
               if assessed else 0.0)

    risk_level = "MINIMAL"
    for threshold, label in RISK_THRESHOLDS:
        if avg_ede >= threshold:
            risk_level = label
            break

    nodes_with_ede  = sum(1 for r in assessed if r.fields_unnecessary > 0)
    unnecessary_pii = sum(len(r.pii_unnecessary) for r in assessed)
    gdpr_concerns   = sum(1 for r in assessed if r.gdpr_concern == "YES")

    return WorkflowResult(
        filename=workflow_path.name,
        timestamp=datetime.now().isoformat(timespec="seconds"),
        nodes_total=len(results),
        nodes_assessed=len(assessed),
        nodes_unassessed=len(unassessed),
        risk_level=risk_level,
        avg_ede=avg_ede,
        nodes_with_ede=nodes_with_ede,
        unnecessary_pii_total=unnecessary_pii,
        gdpr_concerns=gdpr_concerns,
        node_results=results,
    )


# ── Text report formatter ─────────────────────────────────────────────────────
def format_text_report(
    result:     WorkflowResult,
    node_count: int,
    op_count:   int,
) -> str:
    lines = []
    a = lines.append

    a("╔══════════════════════════════════════════════════════════════╗")
    a("║          EDE-AUDITOR — Excessive Data Exposure Tool          ║")
    a("║          n8n Workflow Privacy Audit Report v2.0              ║")
    a("╚══════════════════════════════════════════════════════════════╝")
    a("")
    a(f"Workflow   : {result.filename}")
    a(f"Analysed   : {result.timestamp}")
    a(f"Nodes total: {result.nodes_total} | "
      f"Assessed: {result.nodes_assessed} | "
      f"Unassessed: {result.nodes_unassessed}")
    a("")

    risk     = result.risk_level
    avg_pct  = f"{result.avg_ede * 100:.1f}%"
    width    = 47
    a("┌" + "─" * width + "┐")
    a(f"│{'  RISK LEVEL: ' + risk + '  |  Avg EDE Rate: ' + avg_pct:<{width}}│")
    a(f"│{'  Unnecessary PII transmissions: ' + str(result.unnecessary_pii_total):<{width}}│")
    a(f"│{'  GDPR Art.5(1)(c) concerns    : ' + str(result.gdpr_concerns) + ' node(s)':<{width}}│")
    a("└" + "─" * width + "┘")

    a("")
    a("── NODE FINDINGS " + "─" * 46)

    ede_nodes = sorted(
        [r for r in result.node_results
         if r.status == "assessed" and r.fields_unnecessary > 0],
        key=lambda r: r.overexposure_ratio,
        reverse=True,
    )

    if not ede_nodes:
        a("")
        a("  No EDE detected in any assessed node.")
    else:
        for r in ede_nodes:
            a("")
            a(f"[RISK] Node #{r.position} — {r.node_name} ({r.short_type}) [{r.node_scope}]")
            a(f"  EDE Rate    : {r.overexposure_ratio*100:.1f}%  "
              f"({r.fields_unnecessary} of {r.fields_passed} fields not declared required)")
            unnec_str = ", ".join(r.unnecessary_fields) if r.unnecessary_fields else "none"
            a(f"  Unnecessary : {unnec_str}")
            pii_str = ", ".join(r.pii_exposed) if r.pii_exposed else "none"
            a(f"  PII exposed : {pii_str}")
            a(f"  GDPR        : {r.gdpr_concern}")
            if r.pii_via_expression:
                a(f"  PII in expressions: {r.pii_via_expression} reference(s) — manual review needed")
            if r.unnecessary_fields:
                fields_str = ", ".join(r.unnecessary_fields)
                a(f"  → Review whether [{fields_str}] is necessary for the stated")
                a(f"    purpose before transmitting to {r.short_type}.")
                a(f"    Not declared required by the platform for this operation;")
                a(f"    review whether transmission is necessary for the stated purpose.")

    a("")
    zero_ede = sum(1 for r in result.node_results
                   if r.status == "assessed" and r.fields_unnecessary == 0)
    a(f"Nodes with zero EDE: {zero_ede} (not shown)")
    a(f"Nodes unassessed (community/custom): {result.nodes_unassessed} (not shown)")

    # GDPR summary
    a("")
    a("── GDPR SUMMARY " + "─" * 47)
    gdpr_yes_nodes = [r for r in result.node_results if r.gdpr_concern == "YES"]
    gdpr_dm_nodes  = [r for r in result.node_results if r.gdpr_concern == "DM(non-PII)"]
    all_pii_unnec  = []
    for r in result.node_results:
        all_pii_unnec.extend(r.pii_unnecessary)

    if gdpr_yes_nodes:
        a("")
        a("⚠  GDPR Article 5(1)(c) — Data Minimisation Concern Detected")
        a("The following nodes transmit personal data fields not declared required")
        a("by the platform for this operation.  Under GDPR Article 5(1)(c),")
        a("personal data should be limited to what is necessary for the purpose.")
        a("")
        affected = [f"{r.node_name} ({r.short_type})" for r in gdpr_yes_nodes]
        a(f"Affected nodes        : {', '.join(affected)}")
        unique_pii = sorted(set(all_pii_unnec))
        a(f"Unnecessary PII fields: {', '.join(unique_pii) if unique_pii else 'see node findings'}")
    elif gdpr_dm_nodes:
        a("")
        a("ℹ  Data Minimisation Concern (non-PII)")
        a("Unnecessary non-personal fields are being transmitted.")
    else:
        a("")
        a("✓  No data minimisation concerns detected.")

    # Methodology
    a("")
    a("── METHODOLOGY & LIMITATIONS " + "─" * 34)
    pii_term_count = sum(len(v) for v in PII_CATEGORIES.values())
    a(f"Ground truth : n8n open-source node definitions (required:true fields)")
    a(f"Registry     : {node_count} official nodes, {op_count} operation combinations")
    a(f"PII taxonomy : {pii_term_count} terms across {len(PII_CATEGORIES)} categories (token-based matching v2)")
    a(f"Analysis     : Static — workflow JSON configuration only")
    a("")
    a("Known limitations:")
    a(" • PII detection uses field name matching — false positives possible")
    a(" • Community/LangChain nodes may not be assessed")
    a(" • Static analysis — runtime behaviour may differ")
    a(" • Results are upper-bound EDE estimates")
    a(" • This tool does not guarantee GDPR compliance")

    a("")
    a("── CITATION " + "─" * 51)
    a("If you use Agentilizer in research, please cite:")
    a(RESEARCH_REF)
    a("")
    a("Tool repository: [GitHub URL — to be added after publication]")
    a("═" * 62)

    return "\n".join(lines)


# ── JSON report formatter ─────────────────────────────────────────────────────
def format_json_report(result: WorkflowResult) -> str:
    nodes_output = []
    for r in result.node_results:
        if r.status == "unassessed":
            continue
        nodes_output.append({
            "position":           r.position,
            "name":               r.node_name,
            "type":               r.node_type,
            "scope":              r.node_scope,
            "ede_rate":           round(r.overexposure_ratio, 4),
            "fields_passed":      r.fields_passed,
            "fields_required":    r.fields_required,
            "fields_unnecessary": r.fields_unnecessary,
            "unnecessary_fields": r.unnecessary_fields,
            "pii_exposed":        r.pii_exposed,
            "pii_unnecessary":    r.pii_unnecessary,
            "pii_via_expression": r.pii_via_expression,
            "gdpr_concern":       r.gdpr_concern,
        })
    output = {
        "tool":      TOOL_FULL,
        "workflow":  result.filename,
        "timestamp": result.timestamp,
        "summary": {
            "risk_level":            result.risk_level,
            "avg_ede_ratio":         round(result.avg_ede, 4),
            "nodes_total":           result.nodes_total,
            "nodes_assessed":        result.nodes_assessed,
            "nodes_unassessed":      result.nodes_unassessed,
            "nodes_with_ede":        result.nodes_with_ede,
            "unnecessary_pii_total": result.unnecessary_pii_total,
            "gdpr_concerns":         result.gdpr_concerns,
        },
        "nodes": nodes_output,
        "limitations": [
            "PII detection uses field name matching — false positives possible",
            "Community nodes not assessed",
            "Static analysis only",
            "Results are upper-bound EDE estimates",
            "Does not guarantee GDPR compliance",
        ],
    }
    return json.dumps(output, indent=2, ensure_ascii=False)


# ── Folder audit ──────────────────────────────────────────────────────────────
def audit_folder(
    folder_path: Path,
    global_reg:  dict,
    op_reg:      dict,
    node_count:  int,
    op_count:    int,
    output_fmt:  str,
) -> None:
    json_files = sorted(folder_path.rglob("*.json"))
    print(f"Scanning {len(json_files)} JSON files in {folder_path}...")
    print()
    summaries = []
    valid = 0
    for jf in json_files:
        result = analyse_workflow(jf, global_reg, op_reg)
        if result is None:
            continue
        valid += 1
        if output_fmt == "json":
            print(format_json_report(result))
        else:
            print(format_text_report(result, node_count, op_count))
            print()
        summaries.append(result)

    print("── FOLDER AUDIT SUMMARY " + "─" * 39)
    print(f"Workflows scanned  : {len(json_files)}")
    print(f"Valid n8n workflows: {valid}")
    print()
    if summaries:
        summaries.sort(key=lambda r: r.avg_ede, reverse=True)
        rank_w = 4; risk_w = 7; ede_w = 8; gdpr_w = 4; file_w = 45
        hdr = (f"{'Rank':<{rank_w}}  {'Risk':<{risk_w}}  {'Avg EDE':>{ede_w}}  "
               f"{'GDPR':>{gdpr_w}}  {'Filename'}")
        print(hdr)
        print("─" * 4 + "  " + "─" * 7 + "  " + "─" * 8 + "  " +
              "─" * 4 + "  " + "─" * file_w)
        for i, r in enumerate(summaries, 1):
            gdpr_flag = "YES" if r.gdpr_concerns > 0 else "NO"
            print(f"{i:<{rank_w}}  {r.risk_level:<{risk_w}}  "
                  f"{r.avg_ede*100:>{ede_w}.1f}%  "
                  f"{gdpr_flag:>{gdpr_w}}  "
                  f"{r.filename[:file_w]}")
        counts = {}
        for r in summaries:
            counts[r.risk_level] = counts.get(r.risk_level, 0) + 1
        parts = [f"{counts.get(k, 0)} {k}" for k in ["HIGH", "MEDIUM", "LOW", "MINIMAL"]]
        print()
        print(f"Overall risk: {', '.join(parts)}")


# ── CLI entry point ───────────────────────────────────────────────────────────
def build_db_path() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent / "data" / "ede_research_v2.db"


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ede_audit_tool.py",
        description=(
            f"{TOOL_FULL} — Excessive Data Exposure Audit Tool for n8n Workflows.\n"
            "Analyses workflow JSON files to detect unnecessary data field transmissions\n"
            "that may concern GDPR Article 5(1)(c) — the data minimisation principle."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--workflow", metavar="FILE",
                       help="Path to a single n8n workflow JSON file")
    group.add_argument("--folder",   metavar="DIR",
                       help="Path to a folder — all .json files are audited recursively")
    parser.add_argument("--output",  metavar="FILE",
                        help="Save report to this file (default: print to stdout)")
    parser.add_argument("--format",  choices=["text", "json"], default="text")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args()

    if args.version:
        db_path    = build_db_path()
        _, _, nc, oc = load_registry(db_path) if db_path.exists() else ({}, {}, 0, 0)
        pii_terms  = sum(len(v) for v in PII_CATEGORIES.values())
        print(f"{TOOL_FULL}")
        print("Excessive Data Exposure Audit Tool for n8n Workflows")
        print(f"Registry : {nc} nodes, {oc} operation combinations, {pii_terms} PII terms")
        print(f"Research : Ali, S. (2026) — Leeds Beckett University")
        return

    if not args.workflow and not args.folder:
        parser.print_help()
        return

    db_path = build_db_path()
    if not db_path.exists():
        print(f"ERROR: Registry database not found at {db_path}", file=sys.stderr)
        print("Run Phase 1 and Phase 3 scripts first to build the registry.", file=sys.stderr)
        sys.exit(1)

    global_reg, op_reg, node_count, op_count = load_registry(db_path)

    if args.folder:
        folder = Path(args.folder)
        if not folder.is_dir():
            print(f"ERROR: Not a directory: {folder}", file=sys.stderr)
            sys.exit(1)
        audit_folder(folder, global_reg, op_reg, node_count, op_count, args.format)
        return

    wf_path = Path(args.workflow)
    if not wf_path.exists():
        print(f"ERROR: File not found: {wf_path}", file=sys.stderr)
        sys.exit(1)

    result = analyse_workflow(wf_path, global_reg, op_reg)
    if result is None:
        print(f"ERROR: {wf_path.name} does not appear to be a valid n8n workflow JSON.",
              file=sys.stderr)
        sys.exit(1)

    if args.format == "json":
        report = format_json_report(result)
    else:
        report = format_text_report(result, node_count, op_count)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")
        print(f"Report saved to {out_path}")
    else:
        print(report)


if __name__ == "__main__":
    main()
