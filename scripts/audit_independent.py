"""
audit_independent.py — INDEPENDENT re-derivation audit of EDE + PII numbers.

PURPOSE
-------
This script does NOT import calc_exposure, exposure_core, or ede_audit_tool
for its CORE EDE MATH. It re-implements the EDE ratio and the unnecessary-PII
count FROM SCRATCH, based purely on the methodology definition, then compares
its independent results against the stored exposure_findings_unified table.

It DOES import:
  - node_scope.classify_scope  (scope classification is methodology, not the
    metric under audit; reused so we test the SAME population)
  - pii_taxonomy.detect_pii     (the PII taxonomy IS the agreed definition; we
    test that stored counts match it, so we must use the same detector)

If the INDEPENDENT EDE math agrees with the stored ratios, the formula is
correct (not merely self-consistent). If the INDEPENDENT PII recount agrees
with stored pii_fields_unnecessary, the registry rebuild was applied correctly.

Run:  python audit_independent.py
"""

import sqlite3, json, sys
from pathlib import Path
from collections import defaultdict

DB = r"D:\MS\Project\data\ede_research_v2.db"
SCRIPTS = r"D:\MS\Project\scripts"
sys.path.insert(0, SCRIPTS)

from node_scope import classify_scope          # population definition (not under audit)
from pii_taxonomy import detect_pii            # the agreed PII definition

# ─────────────────────────────────────────────────────────────────────────────
# INDEPENDENT re-implementation of the registry loader.
# Reads the same nodes / node_operations tables but builds the lookup with
# OUR OWN code, so we are not trusting the engine's loader.
# ─────────────────────────────────────────────────────────────────────────────

# Functional / control fields excluded from EDE (methodology: routing config,
# not transmitted business data). Mirror of the documented FUNCTIONAL_FIELDS.
FUNCTIONAL_FIELDS = frozenset({
    "operation", "resource", "mode", "authentication", "requestMethod",
    "method", "url", "options", "additionalFields", "additionalOptions",
    "filters", "updateFields", "jsonParameters", "specifyBody",
    "resource Locator", "__rl", "value", "cachedResultName", "cachedResultUrl",
})

def load_registry_independent(con):
    """Build required-field + PII sets per node, with our own loader."""
    global_reg = {}
    for node_name, field_name, required, is_pii, pii_conf in con.execute(
        "SELECT node_name, field_name, required, is_pii, pii_confidence FROM nodes"
    ):
        key = node_name.lower()
        e = global_reg.setdefault(key, {"required": set(), "optional": set(),
                                        "all_pii": set(), "pii_conf": {}})
        if required:
            e["required"].add(field_name)
        else:
            e["optional"].add(field_name)
        if is_pii:
            e["all_pii"].add(field_name)
            e["pii_conf"][field_name] = pii_conf or ""

    op_reg = {}
    for node_name, operation, resource, req_json in con.execute(
        "SELECT node_name, operation, resource, required_fields FROM node_operations"
    ):
        key = node_name.lower()
        try:
            req = frozenset(json.loads(req_json)) - FUNCTIONAL_FIELDS
        except Exception:
            req = frozenset()
        op_reg.setdefault(key, {})[(operation.lower(), resource.lower())] = req
    return global_reg, op_reg


def required_for(short, params, global_reg, op_reg):
    """Independent required-set resolution with the same fallback chain."""
    op  = str(params.get("operation", "")).strip().lower() or "*"
    res = str(params.get("resource", "")).strip().lower() or "*"
    if short in op_reg:
        for k in [(op, res), (op, "*"), ("*", res), ("*", "*")]:
            if k in op_reg[short]:
                return set(op_reg[short][k])
    if short in global_reg:
        return set(global_reg[short]["required"]) - FUNCTIONAL_FIELDS
    return None


def leaf_fields_independent(params):
    """
    Independent flattening: return the set of leaf field names actually passed,
    excluding functional/control fields. Mirrors methodology: we count business
    data fields the workflow author put on the node.
    """
    passed = set()
    for k, v in params.items():
        if k in FUNCTIONAL_FIELDS:
            continue
        passed.add(k)
    return passed


def ede_independent(short, params, global_reg, op_reg):
    """
    INDEPENDENT EDE computation. Returns (status, scope-irrelevant) dict:
      fields_passed, fields_required(count of required actually present?),
      fields_unnecessary, ratio, pii_unnecessary_names
    Methodology: ratio = unnecessary_passed / passed, where unnecessary =
    passed fields not in the required set.
    """
    required = required_for(short, params, global_reg, op_reg)
    if required is None:
        return None  # unassessed (no registry entry)

    passed = leaf_fields_independent(params)
    if not passed:
        return {"passed": 0, "required_n": len(required), "unnecessary": 0,
                "ratio": 0.0, "pii_unnec": []}

    unnecessary = {f for f in passed if f not in required}
    ratio = len(unnecessary) / len(passed)

    # PII among the UNNECESSARY fields (independent detect_pii call)
    pii_unnec = [f for f in unnecessary if detect_pii(f).is_pii]

    return {
        "passed": len(passed),
        "required_n": len(required),
        "unnecessary": len(unnecessary),
        "ratio": ratio,
        "pii_unnec": pii_unnec,
    }


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    con = sqlite3.connect(DB)
    global_reg, op_reg = load_registry_independent(con)

    print("="*68)
    print("INDEPENDENT AUDIT — EDE + PII re-derived from scratch vs stored table")
    print("="*68)

    # Pull every node, classify scope independently, compute EDE independently.
    indep_egress_ai_ratios = []
    indep_pii_total = 0
    indep_pii_high = 0
    indep_wf_with_pii = set()
    indep_resolvable = 0
    indep_all_matched = 0
    bucket = defaultdict(int)

    # Also collect 10 sample nodes for hand-verification
    samples = []

    rows = con.execute(
        "SELECT workflow_id, node_type, parameters_json FROM workflow_nodes"
    ).fetchall()

    for wf_id, node_type, pj in rows:
        short = node_type.rsplit(".", 1)[-1].lower()
        scope = classify_scope(node_type)
        try:
            params = json.loads(pj) if pj else {}
            if not isinstance(params, dict): params = {}
        except Exception:
            params = {}

        # skip the same non-data node types the engine skips
        if short in ("stickynote", "noop", "manualtrigger", "start"):
            continue

        res = ede_independent(short, params, global_reg, op_reg)
        if res is None:
            continue  # unassessed

        indep_all_matched += 1

        # resolvable = required set known (req>0) AND scope != unknown
        is_resolvable = res["required_n"] > 0 and scope != "unknown"
        if is_resolvable:
            indep_resolvable += 1

        # egress+ai resolvable population (the headline)
        if res["required_n"] > 0 and scope in ("egress", "ai"):
            r = res["ratio"]
            indep_egress_ai_ratios.append(r)
            # distribution buckets
            if r == 0:                      bucket["=0"] += 1
            elif r < 0.25:                  bucket["0-0.25"] += 1
            elif r < 0.5:                   bucket["0.25-0.5"] += 1
            elif r < 0.75:                  bucket["0.5-0.75"] += 1
            elif r < 1.0:                   bucket["0.75-1.0"] += 1
            else:                           bucket["=1.0"] += 1
            # PII
            for f in res["pii_unnec"]:
                indep_pii_total += 1
                if detect_pii(f).confidence == "high":
                    indep_pii_high += 1
                indep_wf_with_pii.add(wf_id)
            # collect samples
            if len(samples) < 10 and res["unnecessary"] > 0:
                samples.append((wf_id, short, scope, res))

    n = len(indep_egress_ai_ratios)
    indep_avg = sum(indep_egress_ai_ratios) / n * 100 if n else 0

    print("\n--- CHECK A1: INDEPENDENT egress+AI EDE (re-derived from raw) ---")
    print(f"  nodes (independent)      : {n}")
    print(f"  avg EDE (independent)    : {indep_avg:.2f}%")
    print(f"  --> stored should be     : 42428 nodes / 50.75%")

    print("\n--- CHECK A2: INDEPENDENT population counts ---")
    print(f"  all_matched (independent): {indep_all_matched}   (stored 193063)")
    print(f"  resolvable  (independent): {indep_resolvable}   (stored 50756)")

    print("\n--- CHECK A3: INDEPENDENT PII (strict, re-derived) ---")
    print(f"  PII total (independent)  : {indep_pii_total}   (stored 2165)")
    print(f"  PII high  (independent)  : {indep_pii_high}    (stored 673)")
    print(f"  workflows w/ PII (indep) : {len(indep_wf_with_pii)}  (stored 1273)")

    print("\n--- CHECK A4: INDEPENDENT distribution buckets (bimodal claim) ---")
    for b in ["=0","0-0.25","0.25-0.5","0.5-0.75","0.75-1.0","=1.0"]:
        print(f"    {b:<10}: {bucket.get(b,0)}")
    print("  --> 0-0.25 bucket should be 0 (bimodal); stored: =0 9897, "
          "0.25-0.5 1877, 0.5-0.75 19822, 0.75-1.0 10832")

    # ── CHECK B: cross-check independent vs STORED per-node, on the samples ──
    print("\n--- CHECK B: 10 HAND-VERIFY SAMPLES (independent vs stored row) ---")
    for wf_id, short, scope, res in samples:
        srow = con.execute(
            "SELECT fields_passed, fields_required, fields_unnecessary, "
            "overexposure_ratio, pii_fields_unnecessary "
            "FROM exposure_findings_unified WHERE workflow_id=? AND short_type=? LIMIT 1",
            (wf_id, short)
        ).fetchone()
        print(f"\n  wf={wf_id} node={short} scope={scope}")
        print(f"    INDEP: passed={res['passed']} unnec={res['unnecessary']} "
              f"ratio={res['ratio']:.3f} pii={len(res['pii_unnec'])}")
        if srow:
            print(f"    STORED: passed={srow[0]} req={srow[1]} unnec={srow[2]} "
                  f"ratio={srow[3]:.3f} pii={srow[4]}")
        else:
            print(f"    STORED: (no matching row found)")

    # ── CHECK B2: re-derive stored average two ways ─────────────────────────
    print("\n--- CHECK B2: stored avg EDE re-derived two ways ---")
    sql_avg = con.execute(
        "SELECT COUNT(*), AVG(overexposure_ratio)*100 FROM exposure_findings_unified "
        "WHERE fields_required>0 AND node_scope IN ('egress','ai')"
    ).fetchone()
    ratios = [r[0] for r in con.execute(
        "SELECT overexposure_ratio FROM exposure_findings_unified "
        "WHERE fields_required>0 AND node_scope IN ('egress','ai')"
    )]
    py_avg = sum(ratios)/len(ratios)*100 if ratios else 0
    print(f"  SQL AVG()   : {sql_avg[0]} nodes / {sql_avg[1]:.2f}%")
    print(f"  Python loop : {len(ratios)} nodes / {py_avg:.2f}%")
    print(f"  match: {abs(sql_avg[1]-py_avg) < 0.01}")

    # ── CHECK B3: population partition sanity ───────────────────────────────
    print("\n--- CHECK B3: population partition (subset checks) ---")
    egress_ai = con.execute(
        "SELECT COUNT(*) FROM exposure_findings_unified "
        "WHERE fields_required>0 AND node_scope IN ('egress','ai')"
    ).fetchone()[0]
    resolvable = con.execute(
        "SELECT COUNT(*) FROM exposure_findings_unified "
        "WHERE fields_required>0 AND node_scope!='unknown'"
    ).fetchone()[0]
    all_m = con.execute(
        "SELECT COUNT(*) FROM exposure_findings_unified"
    ).fetchone()[0]
    print(f"  egress_ai({egress_ai}) <= resolvable({resolvable}) <= all({all_m})")
    print(f"  subset holds: {egress_ai <= resolvable <= all_m}")

    con.close()
    print("\n" + "="*68)
    print("AUDIT COMPLETE — compare INDEP vs STORED above. Any mismatch = investigate.")
    print("="*68)


if __name__ == "__main__":
    main()