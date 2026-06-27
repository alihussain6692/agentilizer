"""
s8_results.py

Recomputes all Results-section breakdowns against exposure_findings_unified
(the single-engine unified table). Reads ede_research_v2.db only.
"""

import sqlite3, json, sys
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR  = PROJECT_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

DB_PATH = PROJECT_ROOT / "data" / "ede_research_v2.db"

# ede_audit_tool rewrites sys.stdout at import time; reopen fd 1 afterwards.
import ede_audit_tool as ede
sys.stdout = open(1, "w", encoding="utf-8", errors="replace", closefd=False)

from node_scope import classify_scope

TABLE = "exposure_findings_unified"

con = sqlite3.connect(str(DB_PATH))

# ── Service category map ──────────────────────────────────────────────────────
CATEGORY = {}
def addcat(cat, names):
    for n in names: CATEGORY[n.lower()] = cat
addcat("Email", ["gmail","microsoftOutlook","emailSend","emailReadImap","sendEmail",
    "mailchimp","sendGrid","mailjet","mandrill","postmark","sparkPost","sendInBlue","elasticEmail"])
addcat("Communication", ["slack","telegram","discord","mattermost","twilio","vonage",
    "messagebird","plivo","whatsApp","teams","microsoftTeams","zoom","intercom","crisp",
    "drift","freshdesk","zendesk","helpScout","livechat"])
addcat("CRM", ["hubspot","salesforce","pipedrive","zohocrm","copper","activeCampaign",
    "vbout","sugarcrm","monday","clickup"])
addcat("Storage", ["googleDrive","dropbox","box","oneDrive","googleSheets","airtable",
    "notion","coda","googleDocs","microsoftWord","microsoftExcel","s3","awsS3","googleCloudStorage"])
addcat("Developer", ["github","gitlab","jira","asana","trello","linear","basecamp",
    "todoist","harvest","clockify","toggl"])
addcat("Ecommerce", ["shopify","woocommerce","stripe","paypal","chargebee","quickbooks","xero","freshbooks"])
addcat("Marketing", ["googleAnalytics","mixpanel","segment","amplitude","customerIo","klaviyo","convertkit"])
addcat("Social", ["twitter","facebook","instagram","linkedIn"])
addcat("Database", ["postgres","mysql","mongodb","redis","microsoftSql","mariadb",
    "cockroachDb","snowflake","bigQuery","dynamoDb"])
addcat("HTTP", ["httpRequest"])

def short_name(nt): return nt.rsplit(".", 1)[-1].lower()

def category_of(nt, scope):
    if scope == "ai": return "AI / LLM"
    return CATEGORY.get(short_name(nt), "Other egress")

# ── Load registry via the tool's loader ──────────────────────────────────────
global_reg, op_reg, node_count, op_count = ede.load_registry(DB_PATH)

print("=" * 60)
print("RESULTS BREAKDOWN — unified engine (exposure_findings_unified)")
print("=" * 60)

# ── BLOCK 1: Headline recap ───────────────────────────────────────────────────
print("\n--- 1. HEADLINE RECAP ---")
r = con.execute(f"""SELECT COUNT(*), ROUND(AVG(overexposure_ratio)*100,2)
    FROM {TABLE} WHERE fields_required>0 AND node_scope IN ('egress','ai')""").fetchone()
print(f"Egress+AI resolvable nodes: {r[0]}  | avg EDE: {r[1]}%")
r = con.execute(f"""SELECT SUM(pii_fields_unnecessary), SUM(pii_high_unnecessary)
    FROM {TABLE} WHERE node_scope IN ('egress','ai')""").fetchone()
print(f"Egress+AI ALL unnecessary PII: {r[0]} (high {r[1]})")

# ── BLOCK 2: EDE by service category (resolvable egress+AI) ──────────────────
print("\n--- 2. EDE BY SERVICE CATEGORY (resolvable egress+AI) ---")
cat_stats = defaultdict(lambda: [0, 0.0])
for nt, scope, ratio in con.execute(f"""SELECT node_type, node_scope, overexposure_ratio
    FROM {TABLE} WHERE fields_required>0 AND node_scope IN ('egress','ai')"""):
    c = category_of(nt, scope)
    cat_stats[c][0] += 1; cat_stats[c][1] += ratio
print(f"{'Category':<16}{'Nodes':>8}{'AvgEDE%':>10}")
for c, (n, s) in sorted(cat_stats.items(), key=lambda x: -x[1][1] / max(x[1][0], 1)):
    print(f"{c:<16}{n:>8}{100*s/n:>9.1f}%")

# ── BLOCK 3: Top 20 node types by avg EDE (resolvable, >=20 inst) ────────────
print("\n--- 3. TOP 20 NODE TYPES BY AVG EDE (resolvable egress+AI, >=20 inst) ---")
print(f"{'Node type':<40}{'Inst':>7}{'AvgEDE%':>10}{'AvgUnnec':>10}")
for nt, inst, ede_pct, unn in con.execute(f"""SELECT node_type, COUNT(*),
    ROUND(AVG(overexposure_ratio)*100,1), ROUND(AVG(fields_unnecessary),1)
    FROM {TABLE} WHERE fields_required>0 AND node_scope IN ('egress','ai')
    GROUP BY node_type HAVING COUNT(*)>=20 ORDER BY AVG(overexposure_ratio) DESC LIMIT 20"""):
    print(f"{short_name(nt):<40}{inst:>7}{ede_pct:>9}%{unn:>10}")

# ── BLOCK 4: EDE by workflow source (resolvable egress+AI) ───────────────────
print("\n--- 4. EDE BY WORKFLOW SOURCE (resolvable egress+AI) ---")
print(f"{'Source':<35}{'Nodes':>8}{'AvgEDE%':>10}")
for src, n, ede_pct in con.execute(f"""SELECT w.source, COUNT(*),
    ROUND(AVG(ef.overexposure_ratio)*100,1)
    FROM {TABLE} ef JOIN workflows w ON ef.workflow_id=w.id
    WHERE ef.fields_required>0 AND ef.node_scope IN ('egress','ai')
    GROUP BY w.source ORDER BY COUNT(*) DESC"""):
    print(f"{src:<35}{n:>8}{ede_pct:>9}%")

# ── BLOCK 5: EDE distribution buckets (resolvable egress+AI) ─────────────────
print("\n--- 5. EDE DISTRIBUTION (resolvable egress+AI) ---")
buckets = [
    ("EDE = 0",          "overexposure_ratio=0"),
    ("0 < EDE < 0.25",   "overexposure_ratio>0 AND overexposure_ratio<0.25"),
    ("0.25 <= EDE < 0.5","overexposure_ratio>=0.25 AND overexposure_ratio<0.5"),
    ("0.5 <= EDE < 0.75","overexposure_ratio>=0.5 AND overexposure_ratio<0.75"),
    ("0.75 <= EDE < 1.0","overexposure_ratio>=0.75 AND overexposure_ratio<1.0"),
    ("EDE = 1.0",        "overexposure_ratio=1.0"),
]
for label, cond in buckets:
    n = con.execute(f"""SELECT COUNT(*) FROM {TABLE}
        WHERE fields_required>0 AND node_scope IN ('egress','ai') AND {cond}""").fetchone()[0]
    print(f"  {label:<20}{n:>8}")

# ── BLOCK 6: PII by confidence (egress+AI ALL) ────────────────────────────────
print("\n--- 6. PII BY CONFIDENCE (egress+AI ALL) ---")
r = con.execute(f"""SELECT SUM(pii_fields_unnecessary), SUM(pii_high_unnecessary),
    SUM(pii_medium_unnecessary), SUM(pii_low_unnecessary), SUM(pii_via_expression)
    FROM {TABLE} WHERE node_scope IN ('egress','ai')""").fetchone()
print(f"  total={r[0]} high={r[1]} medium={r[2]} low={r[3]} via_expression={r[4]}")

# ── BLOCK 7: Top 25 unnecessary PII fields (recomputed via unified engine) ────
print("\n--- 7. TOP 25 UNNECESSARY PII FIELDS (egress+AI ALL, recomputed via ede.analyse_node) ---")
pii_field_counts = defaultdict(int)
recompute_total  = 0

for wf_id, node_type, node_name, pj in con.execute(
    "SELECT workflow_id, node_type, node_name, parameters_json FROM workflow_nodes"
):
    if classify_scope(node_type) not in ("egress", "ai"):
        continue
    try:
        params = json.loads(pj) if pj else {}
        if not isinstance(params, dict): params = {}
    except Exception:
        params = {}

    node   = {"type": node_type, "name": node_name or "", "parameters": params}
    result = ede.analyse_node(node, 0, global_reg, op_reg)

    if result.status != "assessed":
        continue
    for nm in result.pii_unnecessary:
        pii_field_counts[nm] += 1
        recompute_total += 1

# Cross-check against stored sum
stored_pii_total = con.execute(
    f"SELECT SUM(pii_fields_unnecessary) FROM {TABLE} WHERE node_scope IN ('egress','ai')"
).fetchone()[0] or 0
print(f"  recomputed total unnecessary PII = {recompute_total}")
print(f"  stored sum (exposure_findings_unified) = {stored_pii_total}")
cross_ok = recompute_total == stored_pii_total
print(f"  cross-check: {'PASS' if cross_ok else 'MISMATCH'}")
total = sum(pii_field_counts.values())
print(f"  {'Field':<28}{'Count':>8}{'% of PII':>10}")
for nm, c in sorted(pii_field_counts.items(), key=lambda x: -x[1])[:25]:
    print(f"  {nm:<28}{c:>8}{100*c/total:>9.1f}%")

# ── BLOCK 8: Workflow-level stats (egress+AI resolvable) ─────────────────────
print("\n--- 8. WORKFLOW-LEVEL (egress+AI resolvable) ---")
total_wf = con.execute(f"""SELECT COUNT(DISTINCT workflow_id) FROM {TABLE}
    WHERE fields_required>0 AND node_scope IN ('egress','ai')""").fetchone()[0]
any_ede_wf = con.execute(f"""SELECT COUNT(DISTINCT workflow_id) FROM {TABLE}
    WHERE fields_required>0 AND node_scope IN ('egress','ai')
    AND overexposure_ratio>0""").fetchone()[0]
high_ede_wf = con.execute(f"""SELECT COUNT(DISTINCT workflow_id) FROM {TABLE}
    WHERE fields_required>0 AND node_scope IN ('egress','ai')
    AND overexposure_ratio>=0.5""").fetchone()[0]
print(f"  Workflows with resolvable egress/ai node : {total_wf}")
print(f"  Of those — any EDE  (ratio>0)            : {any_ede_wf}"
      f"  ({100*any_ede_wf/total_wf:.1f}%)")
print(f"  Of those — high EDE (ratio>=0.5)         : {high_ede_wf}"
      f"  ({100*high_ede_wf/total_wf:.1f}%)")

con.close()
print("\n=== RESULTS BREAKDOWN COMPLETE (unified engine) ===")
