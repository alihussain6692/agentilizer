"""
Phase 2: Workflow Dataset Collector  (v2 — multi-source + deduplication)

Scans all source directories under data/workflows/ recursively, validates
each workflow JSON, deduplicates by MD5 hash of the nodes array, and loads
unique workflows into the SQLite database.

Sources scanned:
  official_n8n/                — official n8n template API (Phase 2b)
  n8n-workflows/               — Zie619/n8n-workflows GitHub repo
  n8n-workflow-all-templates/  — community collection
  n8n-automation-templates-5000/ — automation template pack
  n8n-workflow-templates/      — workflow template repo
  awesome-n8n-templates/       — curated awesome list

Tables populated:
  workflows       — one row per unique (hash-deduplicated) workflow
  workflow_nodes  — one row per node instance within each workflow

Output:
  data/ede_research.db              (primary)
  data/registry/phase2_final_summary.txt
"""

import hashlib
import json
import sys
import io
from pathlib import Path
# Force UTF-8 console output on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sqlite3
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "ede_research_v2.db"

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT  = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = PROJECT_ROOT / "data" / "Unique_Dataset"
REGISTRY_DIR  = PROJECT_ROOT / "data" / "registry"
REGISTRY_DIR.mkdir(parents=True, exist_ok=True)

OUT_SUMMARY = REGISTRY_DIR / "phase2_final_summary.txt"

# ── Source directories to scan (order determines which copy wins on duplicates)
# Most authoritative sources listed first so their copy is kept.
SOURCE_DIRS = [
    "official_n8n",
    "n8n-workflow-all-templates",
    "n8n-workflow-templates",
    "n8n-automation-templates-5000",
    "n8n-workflows",
    "awesome-n8n-templates",
]

# ── Utility node types excluded from external_node_count ─────────────────────
UTILITY_NODE_TYPES: set[str] = {
    "n8n-nodes-base.if",
    "n8n-nodes-base.switch",
    "n8n-nodes-base.merge",
    "n8n-nodes-base.noOp",
    "n8n-nodes-base.splitInBatches",
    "n8n-nodes-base.set",
    "n8n-nodes-base.code",
    "n8n-nodes-base.function",
    "n8n-nodes-base.functionItem",
    "n8n-nodes-base.stickyNote",
    "n8n-nodes-base.start",
}

# ── PII term list for parameter scanning ─────────────────────────────────────
PII_TERMS: list[str] = [
    "email", "phone", "name", "firstname", "lastname",
    "address", "city", "postcode", "zip", "country",
    "dob", "dateofbirth", "age", "gender",
    "ssn", "nin", "passport",
    "ip", "deviceid", "userid",
    "accountnumber", "salary", "nationalid", "healthrecord",
    "employeeid", "creditcard", "iban", "taxid",
    "socialsecurity", "nationalinsurance",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _iter_strings(obj) -> list[str]:
    """Recursively collect every string key and value from a nested structure."""
    results: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            results.append(str(k))
            results.extend(_iter_strings(v))
    elif isinstance(obj, list):
        for item in obj:
            results.extend(_iter_strings(item))
    elif isinstance(obj, str):
        results.append(obj)
    return results


def has_pii_in_params(parameters: dict) -> bool:
    """Return True if any key or value in parameters contains a PII term."""
    for s in _iter_strings(parameters):
        s_norm = s.lower().replace("_", "").replace("-", "").replace(" ", "")
        for term in PII_TERMS:
            if term in s_norm:
                return True
    return False


def nodes_md5(nodes: list) -> str:
    """
    Compute a stable MD5 hash of the nodes array for deduplication.
    Sort nodes by their 'type' + 'name' to be robust against ordering differences.
    """
    canonical = json.dumps(
        sorted(nodes, key=lambda n: (n.get("type", ""), n.get("name", ""))),
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.md5(canonical.encode("utf-8")).hexdigest()


def infer_category(json_path: Path, source_dir: Path) -> str:
    """
    Infer category from subfolder structure within a source directory.
    For the canonical workflows/ tree the subfolder IS the category.
    For flat sources, fall back to the immediate parent folder name.
    """
    try:
        rel = json_path.relative_to(source_dir)
        parts = rel.parts
        if len(parts) >= 2:       # path has at least one subfolder
            return parts[0]
    except ValueError:
        pass
    parent = json_path.parent.name
    return parent if parent and parent != source_dir.name else "uncategorised"


def validate_workflow(data) -> tuple[bool, str]:
    """
    A valid n8n workflow must be a dict with a 'nodes' list of >= 2 entries,
    each node having a 'type' field.
    """
    if not isinstance(data, dict):
        return False, "top-level is not an object"
    nodes = data.get("nodes")
    if not isinstance(nodes, list):
        return False, "no 'nodes' array"
    if len(nodes) < 2:
        return False, f"only {len(nodes)} node(s)"
    for i, node in enumerate(nodes):
        if not node.get("type"):
            return False, f"node[{i}] missing 'type'"
    return True, ""


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("Phase 2 — Workflow Dataset Collector  (v2, multi-source)")
    print("=" * 60)

    # ── Discover all JSON files across all source directories ─────────────────
    print("\nScanning source directories ...")
    all_files: list[tuple[Path, str, Path]] = []  # (path, source_name, source_dir)

    for src_name in SOURCE_DIRS:
        src_dir = WORKFLOWS_DIR / src_name
        if not src_dir.exists():
            print(f"  SKIP (not found): {src_name}")
            continue
        files = sorted(src_dir.rglob("*.json"))
        print(f"  {src_name:<40} {len(files):>6} JSON files")
        for f in files:
            all_files.append((f, src_name, src_dir))

    # Also scan any other top-level JSON files not in the listed source dirs
    for f in sorted(WORKFLOWS_DIR.glob("*.json")):
        all_files.append((f, "root", WORKFLOWS_DIR))

    total_files = len(all_files)
    print(f"\nTotal JSON files to process: {total_files}")

    # ── Open database and clear existing Phase 2 data ─────────────────────────
    print(f"\nOpening database -> {DB_PATH.relative_to(PROJECT_ROOT)}")
    assert DB_PATH.exists(), f"v2 DB not found: {DB_PATH}"
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA foreign_keys = ON")

    print("  Clearing existing workflow data ...")
    con.execute("DELETE FROM workflow_nodes")
    con.execute("DELETE FROM workflows")
    con.commit()

    # ── First pass: validate, hash, deduplicate, collect workflow rows ─────────
    print("\nPass 1/2 — Validating and deduplicating ...")

    seen_hashes:  set[str]   = set()    # MD5 hashes of nodes arrays already queued
    wf_batch:     list[tuple] = []      # rows for workflows table
    wf_paths:     list[Path]  = []      # parallel list: source path for each wf_batch row

    valid_count    = 0
    duplicate_count = 0
    skipped_count  = 0
    json_errors    = 0
    skip_log: list[str] = []

    for idx, (json_path, src_name, src_dir) in enumerate(all_files, 1):
        if idx % 500 == 0 or idx == total_files:
            print(f"  [{idx:>6}/{total_files}]  valid={valid_count}  "
                  f"dupes={duplicate_count}  skipped={skipped_count}", flush=True)

        # ── Parse ─────────────────────────────────────────────────────────────
        try:
            raw_text = json_path.read_text(encoding="utf-8", errors="replace")
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            json_errors += 1
            skipped_count += 1
            skip_log.append(f"JSON_ERR  [{src_name}] {json_path.name}: {exc}")
            continue
        except Exception as exc:
            skipped_count += 1
            skip_log.append(f"READ_ERR  [{src_name}] {json_path.name}: {exc}")
            continue

        # ── Handle top-level arrays (some files are arrays of workflows) ───────
        if isinstance(data, list):
            skipped_count += 1
            skip_log.append(f"ARRAY     [{src_name}] {json_path.name}")
            continue

        # ── Validate ──────────────────────────────────────────────────────────
        is_valid, reason = validate_workflow(data)
        if not is_valid:
            skipped_count += 1
            skip_log.append(f"INVALID   [{src_name}] {json_path.name}: {reason}")
            continue

        # ── Deduplicate by nodes hash ──────────────────────────────────────────
        h = nodes_md5(data["nodes"])
        if h in seen_hashes:
            duplicate_count += 1
            continue
        seen_hashes.add(h)

        # ── Extract metadata ──────────────────────────────────────────────────
        nodes = data["nodes"]
        node_count = len(nodes)
        external_count = sum(
            1 for n in nodes
            if n.get("type", "").lower() not in UTILITY_NODE_TYPES
        )
        pii_found = any(has_pii_in_params(n.get("parameters", {})) for n in nodes)
        category  = infer_category(json_path, src_dir)
        filename  = str(json_path.relative_to(WORKFLOWS_DIR))

        wf_batch.append((
            filename,
            src_name,
            category,
            node_count,
            external_count,
            1 if pii_found else 0,
            h,                          # nodes_hash
            json.dumps(data, ensure_ascii=False),   # raw_json
        ))
        wf_paths.append(json_path)
        valid_count += 1

    print(f"\n  Pass 1 complete.")
    print(f"  Valid unique workflows : {valid_count}")
    print(f"  Duplicates removed     : {duplicate_count}")
    print(f"  Files skipped          : {skipped_count}  ({json_errors} JSON errors)")

    # ── Insert workflows ───────────────────────────────────────────────────────
    print(f"\nInserting {valid_count} workflows into database ...")
    con.executemany(
        "INSERT INTO workflows"
        " (filename, source, category, node_count, external_node_count,"
        "  has_pii_params, nodes_hash, raw_json)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        wf_batch,
    )
    con.commit()
    wf_batch.clear()    # free memory

    # ── Build filename→id map for workflow_nodes ───────────────────────────────
    print("Building filename -> id map ...")
    filename_to_id: dict[str, int] = {
        row[0]: row[1]
        for row in con.execute("SELECT filename, id FROM workflows").fetchall()
    }

    # ── Second pass: extract workflow_nodes ───────────────────────────────────
    print(f"\nPass 2/2 — Extracting node instances ...")
    node_batch: list[tuple] = []
    pass2_errors = 0

    for idx, (json_path, src_name, src_dir) in enumerate(all_files, 1):
        rel = str(json_path.relative_to(WORKFLOWS_DIR))
        wf_id = filename_to_id.get(rel)
        if wf_id is None:
            continue    # was skipped or duplicate in pass 1

        if idx % 500 == 0:
            print(f"  [{idx:>6}/{total_files}]  node rows queued={len(node_batch)}", flush=True)

        try:
            data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            pass2_errors += 1
            continue

        for node in data.get("nodes", []):
            node_batch.append((
                wf_id,
                node.get("type", ""),
                node.get("name", ""),
                json.dumps(node.get("parameters", {}), ensure_ascii=False),
            ))

        # Flush in chunks of 50k to avoid holding too much in RAM
        if len(node_batch) >= 50_000:
            con.executemany(
                "INSERT INTO workflow_nodes"
                " (workflow_id, node_type, node_name, parameters_json)"
                " VALUES (?, ?, ?, ?)",
                node_batch,
            )
            con.commit()
            node_batch.clear()

    # ── Final flush ───────────────────────────────────────────────────────────
    if node_batch:
        con.executemany(
            "INSERT INTO workflow_nodes"
            " (workflow_id, node_type, node_name, parameters_json)"
            " VALUES (?, ?, ?, ?)",
            node_batch,
        )
        con.commit()
        node_batch.clear()

    total_node_rows = con.execute("SELECT COUNT(*) FROM workflow_nodes").fetchone()[0]
    print(f"\n  Pass 2 complete. Total node rows: {total_node_rows}")

    # ── Run summary queries ───────────────────────────────────────────────────
    print("\nRunning summary queries ...")

    q_total = con.execute(
        "SELECT COUNT(*) FROM workflows"
    ).fetchone()[0]

    q_source = con.execute(
        "SELECT source, COUNT(*) as count FROM workflows"
        " GROUP BY source ORDER BY count DESC"
    ).fetchall()

    q_pii = con.execute(
        "SELECT COUNT(*) as total,"
        "       SUM(has_pii_params) as with_pii,"
        "       ROUND(SUM(has_pii_params) * 100.0 / COUNT(*), 1) as pii_pct"
        " FROM workflows"
    ).fetchone()

    q_avg = con.execute(
        "SELECT ROUND(AVG(node_count), 1),"
        "       ROUND(AVG(external_node_count), 1),"
        "       MAX(node_count)"
        " FROM workflows"
    ).fetchone()

    q_types = con.execute(
        "SELECT node_type, COUNT(*) as frequency"
        " FROM workflow_nodes"
        " GROUP BY node_type"
        " ORDER BY frequency DESC"
        " LIMIT 25"
    ).fetchall()

    con.close()

    # ── Format summary ────────────────────────────────────────────────────────
    lines: list[str] = []

    def h(title: str) -> None:
        lines.append("")
        lines.append(title)
        lines.append("-" * len(title))

    lines.append("=" * 60)
    lines.append("PHASE 2 -- FINAL WORKFLOW DATASET SUMMARY  (v2)")
    lines.append("=" * 60)

    h("Collection stats")
    lines.append(f"  Total JSON files scanned  : {total_files}")
    lines.append(f"  Total unique workflows    : {q_total}")
    lines.append(f"  Duplicates removed        : {duplicate_count}")
    lines.append(f"  Files skipped (invalid)   : {skipped_count}"
                 f"  ({json_errors} JSON errors)")
    lines.append(f"  Total node instances      : {total_node_rows}")

    h("Source breakdown")
    for src, cnt in q_source:
        pct = 100 * cnt / q_total if q_total else 0
        lines.append(f"  {src:<42} {cnt:>6}  ({pct:.1f}%)")

    h("PII parameter exposure")
    lines.append(f"  Workflows with PII params : {q_pii[1]}  ({q_pii[2]}%)")
    lines.append(f"  Workflows without PII     : {q_pii[0] - q_pii[1]}"
                 f"  ({100 - q_pii[2]:.1f}%)")

    h("Workflow size")
    lines.append(f"  Average node count        : {q_avg[0]}")
    lines.append(f"  Average external nodes    : {q_avg[1]}")
    lines.append(f"  Max nodes (one workflow)  : {q_avg[2]}")

    h("Top 25 most common node types")
    for node_type, freq in q_types:
        lines.append(f"  {node_type:<52} {freq:>6}")

    if skip_log:
        h(f"Sample skipped / errored files  (first 30 of {len(skip_log)})")
        for entry in skip_log[:30]:
            lines.append(f"  {entry}")
        if len(skip_log) > 30:
            lines.append(f"  ... and {len(skip_log) - 30} more.")

    h("Output files")
    lines.append(f"  {DB_PATH.relative_to(PROJECT_ROOT)}"
                 "  (workflows + workflow_nodes tables)")
    lines.append(f"  {OUT_SUMMARY.relative_to(PROJECT_ROOT)}")

    summary_text = "\n".join(lines)
    OUT_SUMMARY.write_text(summary_text, encoding="utf-8")

    print()
    print(summary_text)
    print("\nPhase 2 complete.")


if __name__ == "__main__":
    main()
