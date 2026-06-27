"""
phase1b_operation_aware_registry.py — Operation-Aware Minimum Field Registry

Parses n8n node TypeScript source to extract operation- and resource-conditional
field requirements.  Builds a node_operations table in the SQLite database
recording which fields are required for each (node, operation, resource) tuple.

Key improvement over the flat Phase 1 registry:
  Phase 1  — pools ALL required fields regardless of operation context
  Phase 1b — resolves required fields per specific operation + resource combination

Output:
  data/ede_research.db           (node_operations table)
  data/registry/operation_aware_summary.txt
"""

import sys
import io
import re
import json
import sqlite3
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sqlite3
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "ede_research_v2.db"

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# ── Paths ─────────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
NODES_DIR    = PROJECT_ROOT / "data" / "n8n" / "packages" / "nodes-base" / "nodes"
OUT_SUMMARY  = PROJECT_ROOT / "data" / "registry" / "operation_aware_summary.txt"

# Key nodes for the detailed report
KEY_NODES = ["hubspot", "gmail", "slack", "telegram", "googlesheets"]

# Directories to skip (test files, generated code)
SKIP_DIRS = {"test", "tests", "__tests__", "node_modules", "__mocks__"}

# ── Regex patterns ────────────────────────────────────────────────────────────
FIELD_NAME_RE  = re.compile(r"""\bname\s*:\s*['"](\w+)['"]""")
REQUIRED_RE    = re.compile(r"""\brequired\s*:\s*true\b""")
OP_ARR_RE      = re.compile(r"""\boperation\s*:\s*\[([^\]]*)\]""")
RES_ARR_RE     = re.compile(r"""\bresource\s*:\s*\[([^\]]*)\]""")
VALUE_RE        = re.compile(r"""['"]([^'"]{1,80})['"]""")
PROPS_BLOCK_RE  = re.compile(r"""\bproperties\s*:\s*\[""")
INODE_ARRAY_RE  = re.compile(r"""INodeProperties\[\]\s*=\s*\[""")
INODE_SINGLE_RE = re.compile(r"""INodeProperties\s*=\s*\{""")


# ── String-aware brace/bracket extractors ────────────────────────────────────

def extract_brace_block(src: str, start: int) -> tuple[str, int]:
    """Extract from opening { to matching }."""
    depth = 0
    i = start
    in_str = False
    sc = ""
    while i < len(src):
        c = src[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == sc:
                in_str = False
        else:
            if c in ('"', "'", "`"):
                in_str = True
                sc = c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return src[start : i + 1], i
        i += 1
    return src[start:], len(src) - 1


def extract_bracket_block(src: str, start: int) -> tuple[str, int]:
    """Extract from opening [ to matching ]."""
    depth = 0
    i = start
    in_str = False
    sc = ""
    while i < len(src):
        c = src[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == sc:
                in_str = False
        else:
            if c in ('"', "'", "`"):
                in_str = True
                sc = c
            elif c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    return src[start : i + 1], i
        i += 1
    return src[start:], len(src) - 1


def iter_top_objects(block: str):
    """Yield the text of each top-level { ... } object inside block."""
    depth = 0
    start = -1
    in_str = False
    sc = ""
    i = 0
    while i < len(block):
        c = block[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == sc:
                in_str = False
        else:
            if c in ('"', "'", "`"):
                in_str = True
                sc = c
            elif c == "{":
                if depth == 0:
                    start = i
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0 and start >= 0:
                    yield block[start : i + 1]
                    start = -1
        i += 1


# ── Field parser ──────────────────────────────────────────────────────────────

def parse_field(obj_text: str) -> dict | None:
    """
    Parse a single field object text.
    Returns dict with keys: name, required, ops (list), ress (list)
    or None if this doesn't look like a field definition.
    """
    # Extract field name (look only near start to avoid nested 'name:' keys)
    nm = FIELD_NAME_RE.search(obj_text[:500])
    if not nm:
        return None
    field_name = nm.group(1)
    # Skip purely structural names that are not field identifiers
    if field_name in ("show", "hide", "values", "default"):
        return None

    is_required = bool(REQUIRED_RE.search(obj_text))
    ops: list[str] = []
    ress: list[str] = []

    # Extract displayOptions conditions
    do_idx = obj_text.find("displayOptions")
    if do_idx >= 0:
        br = obj_text.find("{", do_idx)
        if br >= 0:
            do_block, _ = extract_brace_block(obj_text, br)
            show_idx = do_block.find("show")
            if show_idx >= 0:
                sb = do_block.find("{", show_idx)
                if sb >= 0:
                    show_blk, _ = extract_brace_block(do_block, sb)
                    # operation: [...]
                    op_m = OP_ARR_RE.search(show_blk)
                    if op_m:
                        ops = VALUE_RE.findall(op_m.group(1))
                    # resource: [...]
                    res_m = RES_ARR_RE.search(show_blk)
                    if res_m:
                        ress = VALUE_RE.findall(res_m.group(1))

    return {"name": field_name, "required": is_required, "ops": ops, "ress": ress}


# ── Source block extractors (mirrors Phase 1 patterns) ───────────────────────

def extract_field_objects_from_source(source: str) -> list[dict]:
    """
    Extract all field definitions from a TypeScript source string.
    Handles:
      Pattern A: properties: [...] inline in a node file
      Pattern B: INodeProperties[] = [...]
      Pattern C: INodeProperties = { (single export)
    """
    fields: list[dict] = []
    seen_names: set[str] = set()   # rough dedup within a file

    # Pattern A: properties: [ ... ]
    for pm in PROPS_BLOCK_RE.finditer(source):
        bstart = source.find("[", pm.start())
        if bstart < 0:
            continue
        block, _ = extract_bracket_block(source, bstart)
        for obj_text in iter_top_objects(block):
            f = parse_field(obj_text)
            if f:
                fields.append(f)

    # Pattern B: INodeProperties[] = [ ... ]
    # Use pm.end()-1 (the opening '[' matched by the regex) rather than
    # source.find('[', pm.start()) which would find the '[' inside 'INodeProperties[]'.
    for pm in INODE_ARRAY_RE.finditer(source):
        bstart = pm.end() - 1
        block, _ = extract_bracket_block(source, bstart)
        for obj_text in iter_top_objects(block):
            f = parse_field(obj_text)
            if f:
                key = (f["name"], tuple(sorted(f["ops"])), tuple(sorted(f["ress"])))
                if key not in seen_names:
                    seen_names.add(key)
                    fields.append(f)

    # Pattern C: INodeProperties = { ... }  (single exported field object)
    # Use pm.end()-1 (the opening '{' matched by the regex).
    for pm in INODE_SINGLE_RE.finditer(source):
        bstart = pm.end() - 1
        obj_text, _ = extract_brace_block(source, bstart)
        f = parse_field(obj_text)
        if f:
            key = (f["name"], tuple(sorted(f["ops"])), tuple(sorted(f["ress"])))
            if key not in seen_names:
                seen_names.add(key)
                fields.append(f)

    return fields


# ── Node name derivation ──────────────────────────────────────────────────────

def _read_node_json(nj_path: Path) -> str | None:
    """Return the short node name from a *.node.json file, or None."""
    try:
        d = json.loads(nj_path.read_text(encoding="utf-8", errors="replace"))
        fqn = d.get("node", "")
        if fqn and "." in fqn:
            return fqn.rsplit(".", 1)[-1]
    except Exception:
        pass
    return None


def derive_node_name(ts_path: Path) -> str | None:
    """
    Resolve the canonical camelCase machine name for a TypeScript file.

    For *.node.ts files: first try the *.node.json with the SAME stem in the
    same directory (so HubspotTrigger.node.ts → HubspotTrigger.node.json →
    'hubspotTrigger', not Hubspot.node.json → 'hubspot').

    For companion files (e.g. DealDescription.ts): walk up directories and
    return the first *.node.json hit (alphabetically first, which is the
    action node for multi-node directories).

    Trigger nodes are included, each getting their own registry entry.
    Returns the short name or None if not resolvable.
    """
    # For *.node.ts files, prefer exact stem match to avoid trigger/action confusion
    if ts_path.name.endswith(".node.ts"):
        stem_base = ts_path.stem  # e.g. "HubspotTrigger.node" → stem = "HubspotTrigger.node"
        # ts_path.stem strips ONE extension: "HubspotTrigger.node.ts" → "HubspotTrigger.node"
        # strip the trailing ".node" to get the bare name
        bare = stem_base[:-5] if stem_base.endswith(".node") else stem_base
        exact_json = ts_path.parent / f"{bare}.node.json"
        if exact_json.exists():
            name = _read_node_json(exact_json)
            if name:
                return name

    # Walk up: companion files and unmatched .node.ts files inherit from parent directory
    for parent in [ts_path.parent, ts_path.parent.parent, ts_path.parent.parent.parent]:
        if parent == NODES_DIR or not parent.is_dir():
            break
        for nj in sorted(parent.glob("*.node.json")):
            name = _read_node_json(nj)
            if name:
                return name
    return None


def is_trigger_node_name(node_name: str) -> bool:
    """Return True if the node name indicates a trigger."""
    return node_name.lower().endswith("trigger")


# ── Find all TS files to parse ────────────────────────────────────────────────

def find_ts_files() -> list[Path]:
    """
    Find all non-test TypeScript files in the nodes directory.
    Excludes test directories and trigger nodes.
    """
    all_ts: list[Path] = []
    for p in NODES_DIR.rglob("*.ts"):
        # Skip test directories and files
        if any(part.lower() in SKIP_DIRS for part in p.parts):
            continue
        # Skip test files by filename convention
        if ".test." in p.name or ".spec." in p.name:
            continue
        all_ts.append(p)
    return all_ts


# ── Build operation-aware registry ───────────────────────────────────────────

def build_op_registry(ts_files: list[Path]) -> dict:
    """
    Parse all TS files and build:
      {node_name: {(op, res): {'required': set, 'optional': set}}}

    op and res can be '*' to mean "any".
    """
    registry: dict[str, dict] = defaultdict(lambda: defaultdict(
        lambda: {"required": set(), "optional": set()}
    ))

    skipped = 0
    parsed  = 0

    for i, ts_path in enumerate(ts_files):
        if (i + 1) % 500 == 0:
            print(f"  [{i+1:>4}/{len(ts_files)}] parsed={parsed} skipped={skipped}")

        node_name = derive_node_name(ts_path)
        if node_name is None:
            skipped += 1
            continue

        try:
            source = ts_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            skipped += 1
            continue

        fields = extract_field_objects_from_source(source)
        if not fields:
            continue

        parsed += 1
        node_entry = registry[node_name]

        for f in fields:
            # Build (op, res) → field_name mapping
            # '*' means "applies to any value"
            ops_list  = f["ops"]  if f["ops"]  else ["*"]
            ress_list = f["ress"] if f["ress"] else ["*"]

            for op in ops_list:
                for res in ress_list:
                    key = (op.lower(), res.lower())
                    if f["required"]:
                        node_entry[key]["required"].add(f["name"])
                    else:
                        node_entry[key]["optional"].add(f["name"])

    print(f"  Done: {parsed} files parsed, {skipped} skipped")
    return dict(registry)


# ── Database operations ───────────────────────────────────────────────────────

def setup_table(con: sqlite3.Connection) -> None:
    """Clear and recreate the node_operations table using the shared DDL from db_setup."""
    con.execute("DELETE FROM node_operations")
    con.commit()
    print("  node_operations table cleared (schema preserved from db_setup)")


def insert_registry(con: sqlite3.Connection, registry: dict) -> int:
    """Insert all entries into node_operations, return row count."""
    rows: list[tuple] = []
    for node_name, combos in registry.items():
        is_trigger = 1 if is_trigger_node_name(node_name) else 0
        for (op, res), entry in combos.items():
            req_list = sorted(entry["required"])
            rows.append((
                node_name,
                op,
                res,
                json.dumps(req_list),
                "*",        # type_version — '*' means all versions
                is_trigger,
            ))

    BATCH = 2000
    for i in range(0, len(rows), BATCH):
        con.executemany(
            "INSERT INTO node_operations"
            " (node_name, operation, resource, required_fields, type_version, is_trigger)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            rows[i : i + BATCH],
        )
    con.commit()
    return len(rows)


# ── Summary report ────────────────────────────────────────────────────────────

def generate_summary(con: sqlite3.Connection, registry: dict) -> str:
    lines: list[str] = []
    w = lines.append

    # Header
    w("=" * 65)
    w("PHASE 1b -- OPERATION-AWARE REGISTRY SUMMARY")
    w("=" * 65)
    w("")

    # Overall stats
    total_nodes = len(registry)
    total_combos = sum(len(v) for v in registry.values())
    total_rows = con.execute("SELECT COUNT(*) FROM node_operations").fetchone()[0]

    w("Overall statistics")
    w("-" * 40)
    w(f"  Nodes with operation data  : {total_nodes}")
    w(f"  (op, res) combinations     : {total_combos}")
    w(f"  Rows in node_operations    : {total_rows}")
    w("")

    # Top 10 nodes by number of combinations
    w("Top 10 nodes by distinct (operation, resource) combinations")
    w("-" * 60)
    top10 = con.execute("""
        SELECT node_name,
               COUNT(*) as combos,
               SUM(json_array_length(required_fields)) as total_req
        FROM node_operations
        WHERE operation != '*' OR resource != '*'
        GROUP BY node_name
        ORDER BY combos DESC
        LIMIT 10
    """).fetchall()
    w(f"  {'Node':<30} {'Combos':>8}  {'TotalReqFields':>15}")
    w(f"  {'-'*30} {'-'*8}  {'-'*15}")
    for node_name, combos, total_req in top10:
        w(f"  {node_name:<30} {combos:>8}  {(total_req or 0):>15}")
    w("")

    # Detailed breakdown for key nodes
    w("Detailed breakdown for 5 key nodes")
    w("=" * 65)

    for node_name in KEY_NODES:
        rows = con.execute("""
            SELECT operation, resource, required_fields
            FROM node_operations
            WHERE node_name = ?
            ORDER BY operation, resource
        """, (node_name,)).fetchall()

        if not rows:
            w(f"\n{node_name.upper()} — no operation data found")
            continue

        w(f"\n{node_name.upper()}")
        w("-" * 50)
        w(f"  Total (op, res) entries: {len(rows)}")
        w("")

        for op, res, req_json in rows:
            req_fields = json.loads(req_json)
            label = f"operation={op}, resource={res}"
            w(f"  [{label}]")
            if req_fields:
                w(f"    Required : {', '.join(req_fields)}")
            else:
                w(f"    Required : (none)")
            w("")

    w("")
    w("Output files")
    w("-" * 40)
    w(f"  data/ede_research.db  (node_operations table)")
    w(f"  data/registry/operation_aware_summary.txt")

    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("Phase 1b — Operation-Aware Registry Builder")
    print("=" * 60)
    print(f"\nNodes directory : {NODES_DIR.relative_to(PROJECT_ROOT)}")

    # Connect to DB (uses shared schema from db_setup, applies migrations)
    assert DB_PATH.exists(), f"v2 DB not found: {DB_PATH}"
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA foreign_keys = ON")

    # Step 1: Find all TS files
    print("\nStep 1: Finding TypeScript files...")
    ts_files = find_ts_files()
    print(f"  Found {len(ts_files):,} TypeScript files to parse")

    # Step 2: Parse all files and build registry
    print("\nStep 2: Parsing files for operation-aware field conditions...")
    registry = build_op_registry(ts_files)
    total_nodes  = len(registry)
    total_combos = sum(len(v) for v in registry.values())
    print(f"  Nodes with data       : {total_nodes}")
    print(f"  (op, res) combinations: {total_combos:,}")

    # Step 3: Create table and insert
    print("\nStep 3: Setting up node_operations table...")
    setup_table(con)

    print("  Inserting rows...")
    total_inserted = insert_registry(con, registry)
    print(f"  Inserted {total_inserted:,} rows")

    # Step 4: Generate summary report
    print("\nStep 4: Generating summary report...")
    summary = generate_summary(con, registry)
    OUT_SUMMARY.write_text(summary, encoding="utf-8")
    print(f"  Saved: {OUT_SUMMARY.relative_to(PROJECT_ROOT)}")

    con.close()

    # Print the summary
    print()
    print(summary)
    print("\nPhase 1b complete.")


if __name__ == "__main__":
    main()
