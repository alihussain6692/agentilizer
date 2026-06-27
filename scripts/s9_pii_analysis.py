import sqlite3, json, sys
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'scripts'))
DB_PATH = PROJECT_ROOT / 'data' / 'ede_research_v2.db'

import ede_audit_tool as ede
from node_scope import classify_scope
from pii_taxonomy import pii_category

con = sqlite3.connect(DB_PATH)

print("="*60)
print("STRICT PII BREAKDOWN — req>0 egress+AI (unified engine)")
print("="*60)

# ── BLOCK 1: Stored counts from unified table, strict population ──
print("\n--- BLOCK 1: PII COUNTS (req>0 egress+ai, from unified table) ---")
r = con.execute("""
    SELECT SUM(pii_fields_unnecessary), SUM(pii_high_unnecessary),
           SUM(pii_medium_unnecessary), SUM(pii_low_unnecessary),
           SUM(pii_via_expression)
    FROM exposure_findings_unified
    WHERE fields_required>0 AND node_scope IN ('egress','ai')
""").fetchone()
print(f"  total unnecessary PII : {r[0]}")
print(f"  high confidence       : {r[1]}")
print(f"  medium confidence     : {r[2]}")
print(f"  low confidence        : {r[3]}")
print(f"  via_expression (ref)  : {r[4]}")
print(f"  high+med+low check    : {(r[1] or 0)+(r[2] or 0)+(r[3] or 0)}")

# ── BLOCK 2: Compare to the OLD all-egress+ai count (to prove the gap) ──
print("\n--- BLOCK 2: COMPARISON — strict vs all (the implied-default gap) ---")
r_all = con.execute("""
    SELECT SUM(pii_fields_unnecessary), SUM(pii_high_unnecessary)
    FROM exposure_findings_unified
    WHERE node_scope IN ('egress','ai')
""").fetchone()
r_strict = con.execute("""
    SELECT SUM(pii_fields_unnecessary), SUM(pii_high_unnecessary)
    FROM exposure_findings_unified
    WHERE fields_required>0 AND node_scope IN ('egress','ai')
""").fetchone()
print(f"  egress+ai ALL    : {r_all[0]} total / {r_all[1]} high")
print(f"  egress+ai req>0  : {r_strict[0]} total / {r_strict[1]} high")
print(f"  GAP (req=0 nodes): {r_all[0]-r_strict[0]} total / {r_all[1]-r_strict[1]} high")
print(f"  --> this gap is the 'implied-default' limitation figure for the paper")

# ── BLOCK 3: Top unnecessary PII field NAMES, strict population ──
print("\n--- BLOCK 3: TOP UNNECESSARY PII FIELDS (req>0 egress+ai, recomputed) ---")
global_reg, op_reg, _, _ = ede.load_registry(DB_PATH)

pii_field_counts = defaultdict(int)
recompute_total = 0

# Re-run the unified engine per node, but ONLY count nodes that are
# egress/ai AND assessed AND fields_required>0 (strict population)
for wf_id, node_type, pj in con.execute(
    "SELECT workflow_id, node_type, parameters_json FROM workflow_nodes"):
    if classify_scope(node_type) not in ("egress","ai"):
        continue
    try:
        params = json.loads(pj) if pj else {}
        if not isinstance(params, dict): params = {}
    except: params = {}
    node = {"type": node_type, "name": "", "parameters": params}
    res = ede.analyse_node(node, 0, global_reg, op_reg)
    if res.status != "assessed":
        continue
    if res.fields_required <= 0:        # STRICT: skip req=0
        continue
    for nm in res.pii_unnecessary:
        pii_field_counts[nm] += 1
        recompute_total += 1

print(f"  recomputed strict total = {recompute_total}")
print(f"  (cross-check vs stored BLOCK 1 total = {r_strict[0]})")
total = sum(pii_field_counts.values()) or 1
print(f"  {'Field':<28}{'Count':>8}{'% of PII':>10}")
for nm,c in sorted(pii_field_counts.items(), key=lambda x:-x[1])[:25]:
    print(f"  {nm:<28}{c:>8}{100*c/total:>9.1f}%")

# ── BLOCK 4: PII by taxonomy category, strict population ──
print("\n--- BLOCK 4: PII BY CATEGORY (req>0 egress+ai) ---")
cat_counts = defaultdict(int)
for nm,c in pii_field_counts.items():
    cat = pii_category(nm) or "uncategorised"
    cat_counts[cat] += c
print(f"  {'Category':<20}{'Count':>8}{'%':>8}")
for cat,c in sorted(cat_counts.items(), key=lambda x:-x[1]):
    print(f"  {cat:<20}{c:>8}{100*c/total:>7.1f}%")

# ── BLOCK 5: How many workflows have any strict PII exposure ──
print("\n--- BLOCK 5: WORKFLOW-LEVEL PII (req>0 egress+ai) ---")
r = con.execute("""
    SELECT COUNT(DISTINCT workflow_id)
    FROM exposure_findings_unified
    WHERE fields_required>0 AND node_scope IN ('egress','ai')
      AND pii_fields_unnecessary>0
""").fetchone()
print(f"  workflows with >=1 strict PII-exposing node: {r[0]}")

con.close()
print("\n=== STRICT PII BREAKDOWN COMPLETE ===")
