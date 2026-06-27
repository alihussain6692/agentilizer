"""
s7_compute_exposure.py — Unified EDE pipeline

Replaces the standalone pipeline logic with direct calls to the tool's
engine (ede_audit_tool.analyse_node), so the pipeline and web/CLI tool
run identical code.

Output table: exposure_findings_unified (same columns as exposure_findings)
The original exposure_findings table is NOT touched.
"""

import sys
import json
import sqlite3
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

# ede_audit_tool rewrites sys.stdout.buffer at import time; reopen fd 1
# directly afterwards so all subsequent print() calls work cleanly.
import ede_audit_tool as ede
sys.stdout = open(1, "w", encoding="utf-8", errors="replace", closefd=False)

DB_PATH = SCRIPTS_DIR.parent / "data" / "ede_research_v2.db"

CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS exposure_findings_unified (
    id                    INTEGER PRIMARY KEY,
    workflow_id           INTEGER NOT NULL,
    node_type             TEXT    NOT NULL,
    node_scope            TEXT    NOT NULL DEFAULT 'unknown',
    fields_passed         INTEGER NOT NULL DEFAULT 0,
    fields_required       INTEGER NOT NULL DEFAULT 0,
    fields_unnecessary    INTEGER NOT NULL DEFAULT 0,
    overexposure_ratio    REAL    NOT NULL DEFAULT 0.0,
    pii_fields_exposed    INTEGER NOT NULL DEFAULT 0,
    pii_fields_required   INTEGER NOT NULL DEFAULT 0,
    pii_fields_unnecessary INTEGER NOT NULL DEFAULT 0,
    pii_high_unnecessary  INTEGER NOT NULL DEFAULT 0,
    pii_medium_unnecessary INTEGER NOT NULL DEFAULT 0,
    pii_low_unnecessary   INTEGER NOT NULL DEFAULT 0,
    pii_via_expression    INTEGER NOT NULL DEFAULT 0
)
"""

INSERT_SQL = """
INSERT INTO exposure_findings_unified
  (workflow_id, node_type, node_scope,
   fields_passed, fields_required, fields_unnecessary,
   overexposure_ratio,
   pii_fields_exposed, pii_fields_required, pii_fields_unnecessary,
   pii_high_unnecessary, pii_medium_unnecessary, pii_low_unnecessary,
   pii_via_expression)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def pii_confidence_counts(pii_unnec: list, pii_conf_map: dict) -> tuple[int, int, int]:
    """Return (high, medium, low) counts for unnecessary PII fields."""
    high = medium = low = 0
    for field in pii_unnec:
        conf = pii_conf_map.get(field, "")
        if not conf:
            from pii_taxonomy import detect_pii
            conf = detect_pii(field).confidence
        if conf == "high":
            high += 1
        elif conf == "medium":
            medium += 1
        else:
            low += 1
    return high, medium, low


def main() -> None:
    print("=" * 60)
    print("Unified EDE Pipeline — tool engine (ede_audit_tool)")
    print("=" * 60)
    print(f"\nDatabase: {DB_PATH}")

    con = sqlite3.connect(str(DB_PATH))
    con.execute("PRAGMA journal_mode = WAL")

    # Load registry via the TOOL's loader (now with PII map)
    print("\nLoading registry via ede_audit_tool.load_registry() ...")
    global_reg, op_reg, node_count, op_count = ede.load_registry(DB_PATH)
    print(f"  Global registry: {node_count} node types")
    print(f"  Op-aware entries: {op_count} combos")

    # Create (or clear) unified findings table
    print("\nCreating/clearing exposure_findings_unified ...")
    con.execute(CREATE_TABLE)
    con.execute("DELETE FROM exposure_findings_unified")
    con.commit()

    # Count source rows
    total_rows = con.execute("SELECT COUNT(*) FROM workflow_nodes").fetchone()[0]
    print(f"  workflow_nodes rows: {total_rows:,}")
    print("\nProcessing (progress every 2000 workflows) ...")

    CHUNK = 5_000
    BATCH = 2_000

    findings_batch: list[tuple] = []
    processed          = 0
    assessed_count     = 0
    unassessed_count   = 0
    workflows_seen: set[int] = set()
    workflows_reported = 0
    prev_wf_id         = None
    offset             = 0

    while True:
        rows = con.execute(
            "SELECT workflow_id, node_type, node_name, parameters_json"
            " FROM workflow_nodes"
            f" LIMIT {CHUNK} OFFSET {offset}"
        ).fetchall()
        if not rows:
            break
        offset += CHUNK

        for wf_id, node_type, node_name, params_json in rows:
            processed += 1

            if wf_id != prev_wf_id:
                workflows_seen.add(wf_id)
                n_wf = len(workflows_seen)
                if n_wf % 2000 == 0 and n_wf != workflows_reported:
                    workflows_reported = n_wf
                    print(f"  [{n_wf:>6} workflows | {processed:>8} rows] "
                          f"assessed={assessed_count:,} unassessed={unassessed_count:,}",
                          flush=True)
                prev_wf_id = wf_id

            try:
                params = json.loads(params_json) if params_json else {}
                if not isinstance(params, dict):
                    params = {}
            except Exception:
                params = {}

            # Reconstruct the node dict that analyse_node expects
            node = {"type": node_type, "name": node_name, "parameters": params}

            # Call the SAME function the web tool uses (position 0 — irrelevant for DB storage)
            result = ede.analyse_node(node, 0, global_reg, op_reg)

            if result.status == "unassessed":
                unassessed_count += 1
                continue

            assessed_count += 1

            # Derive per-confidence PII counts from the registry map
            reg_entry    = global_reg.get(result.short_type, {})
            pii_conf_map = reg_entry.get("pii_confidence_map", {})
            pii_high, pii_med, pii_low = pii_confidence_counts(
                result.pii_unnecessary, pii_conf_map
            )

            # pii_fields_exposed = all PII leaf fields (both required and unnecessary)
            from exposure_core import leaf_name
            pii_exposed = len([f for f in result.pii_exposed])
            # fields_required from NodeResult
            fields_req  = result.fields_required

            findings_batch.append((
                wf_id,
                node_type,
                result.node_scope,
                result.fields_passed,
                fields_req,
                result.fields_unnecessary,
                result.overexposure_ratio,
                pii_exposed,          # pii_fields_exposed
                0,                    # pii_fields_required (not tracked by NodeResult)
                len(result.pii_unnecessary),  # pii_fields_unnecessary
                pii_high,
                pii_med,
                pii_low,
                result.pii_via_expression,
            ))

            if len(findings_batch) >= BATCH:
                con.executemany(INSERT_SQL, findings_batch)
                con.commit()
                findings_batch.clear()

    # Final flush
    if findings_batch:
        con.executemany(INSERT_SQL, findings_batch)
        con.commit()

    total_stored = con.execute(
        "SELECT COUNT(*) FROM exposure_findings_unified"
    ).fetchone()[0]

    print(f"\n  Processing complete.")
    print(f"  Rows processed         : {processed:,}")
    print(f"  Workflows seen         : {len(workflows_seen):,}")
    print(f"  Assessed (stored)      : {assessed_count:,}")
    print(f"  Unassessed (skipped)   : {unassessed_count:,}")
    print(f"  Findings stored        : {total_stored:,}")

    # Three-population quick check
    print("\nThree-population summary (exposure_findings_unified):")
    for label, cond in [
        ("all_matched",      "1=1"),
        ("resolvable",       "fields_required>0 AND node_scope!='unknown'"),
        ("egress_ai",        "fields_required>0 AND node_scope IN ('egress','ai')"),
    ]:
        r = con.execute(
            f"SELECT COUNT(*), ROUND(AVG(overexposure_ratio)*100,2)"
            f" FROM exposure_findings_unified WHERE {cond}"
        ).fetchone()
        print(f"  {label}: {r[0]:,} nodes  avg_ede={r[1]}%")

    con.close()
    print("\nDone.")


if __name__ == "__main__":
    main()
