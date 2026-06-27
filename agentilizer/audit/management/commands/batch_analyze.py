import sqlite3, json, tempfile, os, sys, time
from pathlib import Path
from django.core.management.base import BaseCommand
from audit.models import AuditJob, AuditResult, CollectiveReport
from audit.services.ede_service import run_ede_audit
from django.core.files.base import ContentFile

sys.path.insert(0, r"D:\MS\Project\scripts")
from exposure_core import classify_populations

V2_DB = Path(r"D:\MS\Project\data\ede_research_v2.db")

class Command(BaseCommand):
    help = "Batch analyze the 20,546 v2 workflows through the framework engine"

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=0,
            help="Limit number of workflows (0 = all)")
        parser.add_argument("--report-name", type=str,
            default="V2 Full Dataset Validation")

    def handle(self, *args, **opts):
        # ede_audit_tool import wraps then GC-closes sys.stdout.buffer; pre-warm it
        # here and immediately reopen fd 1 so all subsequent prints work cleanly.
        from audit.services.ede_service import _import_ede
        _import_ede()
        sys.stdout = open(1, "w", encoding="utf-8", closefd=False)
        self.stdout = sys.stdout  # sync Django's cached reference to the fresh stream

        limit = opts["limit"]
        con = sqlite3.connect(V2_DB)
        cur = con.cursor()
        q = "SELECT id, filename, raw_json FROM workflows ORDER BY id"
        if limit:
            q += f" LIMIT {limit}"
        rows = cur.execute(q).fetchall()
        con.close()

        total = len(rows)
        print(f"Loaded {total} workflows from v2 DB")

        workflows_done = 0
        workflows_error = 0
        all_node_records = []

        tmpdir = tempfile.mkdtemp(prefix="batch_v2_")
        start = time.time()

        for i, (wf_id, filename, raw_json) in enumerate(rows, 1):
            tmp_path = os.path.join(tmpdir, f"wf_{wf_id}.json")
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(raw_json)

            try:
                ede = run_ede_audit(tmp_path)
                if ede.get("error"):
                    workflows_error += 1
                else:
                    # Collect only assessed (registry-matched) node records
                    for nr in ede.get("node_results", []):
                        if nr.get("status") == "assessed":
                            all_node_records.append(nr)
                    workflows_done += 1
            except Exception as e:
                workflows_error += 1
                if workflows_error <= 5:
                    print(f"  ERROR wf {wf_id}: {e}")
            finally:
                try: os.remove(tmp_path)
                except: pass

            if i % 1000 == 0:
                el = time.time() - start
                print(f"  [{i}/{total}] done={workflows_done} "
                    f"errors={workflows_error} ({el:.0f}s)")

        pops = classify_populations(all_node_records)

        head = pops["egress_ai_resolvable"]
        gdpr_flags = sum(1 for r in all_node_records if r.get("gdpr_concern"))
        report = CollectiveReport.objects.create(
            name=opts["report_name"],
            total_workflows=workflows_done,
            avg_ede_across_all=head["avg_ede"],
            total_gdpr_flags=gdpr_flags,
            total_pii_violations=head["pii_total"],
            highest_risk="HIGH",
            total_aibom_issues=0,
            summary={
                "populations": pops,
                "headline_population": "egress_ai_resolvable",
                "headline_avg_ede": head["avg_ede"],
                "source": "v2 full dataset via management command",
            },
        )
        self.stdout.write(f"\nSaved CollectiveReport id={report.id} for dashboard")

        self.stdout.write("\n" + "="*60)
        self.stdout.write("THREE-POPULATION RESULTS (framework engine, v2 workflows)")
        self.stdout.write("="*60)
        for key, label in [
            ("all_matched", "All matched (upper bound)"),
            ("resolvable", "Resolvable (req>0, scope!=unknown)"),
            ("egress_ai_resolvable", "Egress+AI resolvable (HEADLINE)"),
        ]:
            p = pops[key]
            self.stdout.write(f"\n{label}:")
            self.stdout.write(f"  nodes={p['n']}  avgEDE={p['avg_ede']}%  "
                              f"anyEDE={p['any_ede']}  highEDE={p['high_ede']}")
            self.stdout.write(f"  PII total={p['pii_total']}  high={p['pii_high']}")
        self.stdout.write("\n" + "="*60)
