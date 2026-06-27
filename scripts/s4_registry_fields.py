"""
Phase 1: Minimum Field Registry Builder  (v3 — token-based PII + confidence)

Parses n8n node TypeScript source files to build a ground-truth registry of
every field each node declares, whether required or optional, and whether the
field carries PII.

Changes in v3:
  - PII detection delegates to pii_taxonomy.detect_pii() — token-based, no false positives
  - Stores pii_confidence ('high'/'medium'/'low') in the nodes table
  - Node name derived from machine name in *.node.json (not directory)
  - Trigger nodes tagged is_trigger=1

Outputs:
  data/ede_research.db        — nodes table
  data/registry/registry_summary.txt
"""

import re
import json
import sys
import io
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sqlite3
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "ede_research_v2.db"
from pii_taxonomy import detect_pii

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NODES_DIR    = PROJECT_ROOT / "data" / "n8n" / "packages" / "nodes-base" / "nodes"
REGISTRY_DIR = PROJECT_ROOT / "data" / "registry"
REGISTRY_DIR.mkdir(parents=True, exist_ok=True)
OUT_SUMMARY  = REGISTRY_DIR / "registry_summary.txt"

_SKIP_DIRS = {"test", "__tests__", "__test__", "__schema__", "node_modules"}


# ── Low-level brace-block extractor ──────────────────────────────────────────

def _brace_blocks_from_array(source: str, start_pos: int) -> list[str]:
    depth = 1
    i = start_pos
    chars: list[str] = []
    while i < len(source) and depth > 0:
        ch = source[i]
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                break
        chars.append(ch)
        i += 1
    array_content = "".join(chars)
    blocks: list[str] = []
    brace_depth = 0
    block_start: int | None = None
    for idx, ch in enumerate(array_content):
        if ch == "{":
            if brace_depth == 0:
                block_start = idx
            brace_depth += 1
        elif ch == "}":
            brace_depth -= 1
            if brace_depth == 0 and block_start is not None:
                blocks.append(array_content[block_start: idx + 1])
                block_start = None
    return blocks


# ── Three extraction strategies ───────────────────────────────────────────────

def extract_properties_blocks(source: str) -> list[str]:
    blocks: list[str] = []
    for m in re.finditer(r"\bproperties\s*:\s*\[", source):
        blocks.extend(_brace_blocks_from_array(source, m.end()))
    return blocks


def extract_inode_array_blocks(source: str) -> list[str]:
    blocks: list[str] = []
    for m in re.finditer(r"INodeProperties\s*\[\s*\]\s*=\s*\[", source):
        blocks.extend(_brace_blocks_from_array(source, m.end()))
    return blocks


def extract_inode_single_blocks(source: str) -> list[str]:
    blocks: list[str] = []
    for m in re.finditer(r"INodeProperties\s*=\s*\{", source):
        brace_start = m.end() - 1
        depth = 0
        for i in range(brace_start, len(source)):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(source[brace_start: i + 1])
                    break
    return blocks


def extract_all_field_blocks(source: str) -> list[str]:
    seen: set[str] = set()
    combined: list[str] = []
    for block in (extract_properties_blocks(source)
                  + extract_inode_array_blocks(source)
                  + extract_inode_single_blocks(source)):
        key = block[:80]
        if key not in seen:
            seen.add(key)
            combined.append(block)
    return combined


# ── Field metadata extractor ──────────────────────────────────────────────────

RE_DISPLAY_NAME = re.compile(r"displayName\s*:\s*['\"]([^'\"]+)['\"]")
RE_NAME         = re.compile(r"(?<!\w)name\s*:\s*['\"]([^'\"]+)['\"]")
RE_TYPE         = re.compile(r"(?<!\w)type\s*:\s*['\"]([^'\"]+)['\"]")
RE_REQUIRED     = re.compile(r"(?<!\w)required\s*:\s*(true|false)")


def parse_block(block: str) -> dict | None:
    n_m = RE_NAME.search(block)
    if not n_m:
        return None
    dn_m  = RE_DISPLAY_NAME.search(block)
    t_m   = RE_TYPE.search(block)
    req_m = RE_REQUIRED.search(block)
    return {
        "display_name": dn_m.group(1)  if dn_m  else "",
        "name":         n_m.group(1),
        "type":         t_m.group(1)   if t_m   else "unknown",
        "required":     req_m.group(1) == "true" if req_m else False,
    }


# ── Node name resolution ──────────────────────────────────────────────────────

def derive_node_name(ts_path: Path, ts_source: str) -> str:
    """
    Resolve the canonical camelCase node identifier.

    Priority:
      1. Nearest *.node.json in directory tree — use 'node' field value
         (e.g. 'n8n-nodes-base.gmail' → 'gmail')
      2. 'name: ...' in the TypeScript source
      3. Filename stem fallback
    """
    search_dir = ts_path.parent
    while True:
        for json_path in sorted(search_dir.glob("*.node.json")):
            try:
                data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
                node_id = data.get("node", "")
                if "." in node_id:
                    return node_id.split(".")[-1]
            except Exception:
                pass
        if search_dir == NODES_DIR or search_dir.parent == NODES_DIR:
            break
        search_dir = search_dir.parent

    m = re.search(r"(?<!\w)name\s*:\s*['\"]([^'\"]+)['\"]", ts_source)
    if m:
        return m.group(1)
    return ts_path.stem.replace(".node", "")


def is_trigger_node(node_name: str, ts_source: str) -> bool:
    """Return True if this node is a trigger node."""
    name_lower = node_name.lower()
    if name_lower.endswith("trigger"):
        return True
    if re.search(r"group\s*:\s*\[[^\]]*['\"]trigger['\"]", ts_source, re.IGNORECASE):
        return True
    return False


# ── Companion file discovery ──────────────────────────────────────────────────

def find_companion_ts_files(ts_path: Path) -> list[Path]:
    search_root = ts_path.parent
    companions: list[Path] = []
    for f in search_root.rglob("*.ts"):
        if f == ts_path:
            continue
        if f.name.endswith(".node.ts"):
            continue
        if any(part in _SKIP_DIRS for part in f.parts):
            continue
        companions.append(f)
    return companions


# ── Main file processor ───────────────────────────────────────────────────────

def process_ts_file(ts_path: Path) -> tuple[str, list[dict], list[str]]:
    warnings: list[str] = []
    try:
        source = ts_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return "", [], [f"READ ERROR {ts_path}: {exc}"]

    node_name = derive_node_name(ts_path, source)
    blocks = extract_all_field_blocks(source)
    fields = [f for b in blocks if (f := parse_block(b))]

    if fields:
        return node_name, fields, warnings

    companions = find_companion_ts_files(ts_path)
    if not companions:
        warnings.append(f"NO PROPERTIES BLOCK (no companions): {ts_path}")
        return node_name, [], warnings

    seen_names: set[str] = set()
    for comp_path in sorted(companions):
        try:
            comp_source = comp_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            warnings.append(f"COMPANION READ ERROR {comp_path}: {exc}")
            continue
        for block in extract_all_field_blocks(comp_source):
            parsed = parse_block(block)
            if parsed and parsed["name"] not in seen_names:
                seen_names.add(parsed["name"])
                fields.append(parsed)

    if not fields:
        warnings.append(f"NO PROPERTIES BLOCK (companions empty): {ts_path}")

    return node_name, fields, warnings


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 60)
    print("Phase 1 — Minimum Field Registry Builder  (v3)")
    print("=" * 60)

    if not NODES_DIR.exists():
        print(f"ERROR: nodes directory not found: {NODES_DIR}")
        sys.exit(1)

    ts_files = sorted(NODES_DIR.rglob("*.node.ts"))
    print(f"\nFound {len(ts_files)} .node.ts files")

    all_records:   list[dict]         = []
    node_registry: dict[str, list]    = defaultdict(list)
    seen_node_fields: set[tuple]      = set()
    all_warnings:  list[str]          = []
    nodes_parsed  = 0
    nodes_skipped = 0

    for idx, ts_path in enumerate(ts_files, 1):
        rel = ts_path.relative_to(PROJECT_ROOT)
        print(f"  [{idx:>4}/{len(ts_files)}] {rel}", end="\r", flush=True)

        node_name, fields, warnings = process_ts_file(ts_path)
        all_warnings.extend(warnings)

        if not node_name or not fields:
            nodes_skipped += 1
            continue

        nodes_parsed += 1

        try:
            source_for_trigger = ts_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            source_for_trigger = ""
        node_is_trigger = is_trigger_node(node_name, source_for_trigger)

        for field in fields:
            dedup_key = (node_name, field["name"])
            if dedup_key in seen_node_fields:
                continue
            seen_node_fields.add(dedup_key)

            pii_match = detect_pii(field["name"])

            record = {
                "node_name":      node_name,
                "source_file":    str(rel),
                "field_name":     field["name"],
                "display_name":   field["display_name"],
                "field_type":     field["type"],
                "required":       field["required"],
                "is_pii":         pii_match.is_pii,
                "pii_category":   pii_match.category,
                "pii_confidence": pii_match.confidence,
                "type_version":   "*",
                "is_trigger":     int(node_is_trigger),
            }
            all_records.append(record)
            node_registry[node_name].append({
                **field,
                "is_pii":         pii_match.is_pii,
                "pii_category":   pii_match.category,
                "pii_confidence": pii_match.confidence,
            })

    print()
    print(f"\nParsed  {nodes_parsed} nodes  (with fields)")
    print(f"Skipped {nodes_skipped} nodes  (no fields found after all strategies)")
    print(f"Total field records: {len(all_records)}")

    print(f"\nOpening database -> {DB_PATH.relative_to(PROJECT_ROOT)}")
    assert DB_PATH.exists(), f"v2 DB not found: {DB_PATH}"
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("DELETE FROM nodes")
    con.commit()

    rows = [
        (
            r["node_name"],
            r["field_name"],
            1 if r["required"] else 0,
            r["field_type"],
            1 if r["is_pii"] else 0,
            r["pii_category"],
            r["pii_confidence"],
            r["type_version"],
            r["is_trigger"],
        )
        for r in all_records
    ]
    con.executemany(
        "INSERT INTO nodes"
        " (node_name, field_name, required, field_type, is_pii,"
        "  pii_category, pii_confidence, type_version, is_trigger)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    con.commit()
    con.close()
    print(f"  Inserted {len(rows)} rows into nodes table")

    # ── Statistics ────────────────────────────────────────────────────────────
    total_fields   = len(all_records)
    total_required = sum(1 for r in all_records if r["required"])
    total_optional = total_fields - total_required
    type_counts: dict[str, int] = defaultdict(int)
    for r in all_records:
        type_counts[r["field_type"]] += 1
    total_by_node = {n: len(f) for n, f in node_registry.items()}
    top_total    = sorted(total_by_node.items(), key=lambda x: x[1], reverse=True)[:10]
    req_by_node  = {n: sum(1 for f in flds if f["required"])
                    for n, flds in node_registry.items()}
    top_required = sorted(req_by_node.items(), key=lambda x: x[1], reverse=True)[:10]
    pii_records  = [r for r in all_records if r["is_pii"]]
    total_pii    = len(pii_records)
    pii_by_conf: dict[str, int] = defaultdict(int)
    for r in pii_records:
        pii_by_conf[r["pii_confidence"]] += 1
    pii_cat_counts: dict[str, int] = defaultdict(int)
    for r in pii_records:
        pii_cat_counts[r["pii_category"]] += 1
    pii_by_node: dict[str, int] = defaultdict(int)
    for r in pii_records:
        pii_by_node[r["node_name"]] += 1
    top_pii_nodes = sorted(pii_by_node.items(), key=lambda x: x[1], reverse=True)[:10]
    trigger_count = sum(1 for r in all_records if r["is_trigger"])

    lines: list[str] = []

    def h(title: str) -> None:
        lines.append("")
        lines.append(title)
        lines.append("-" * len(title))

    lines.append("=" * 60)
    lines.append("PHASE 1 -- MINIMUM FIELD REGISTRY SUMMARY  (v3)")
    lines.append("=" * 60)
    h("Coverage")
    lines.append(f"  .node.ts files found:          {len(ts_files)}")
    lines.append(f"  Nodes parsed (with fields):    {nodes_parsed}")
    lines.append(f"  Nodes skipped (no fields):     {nodes_skipped}")
    lines.append(f"  Trigger node fields:           {trigger_count}")
    h("Field counts")
    lines.append(f"  Total field records:   {total_fields}")
    lines.append(f"  Required fields:       {total_required}  "
                 f"({100*total_required/max(total_fields,1):.1f}%)")
    lines.append(f"  Optional fields:       {total_optional}")
    h("Field type distribution")
    for ftype, cnt in sorted(type_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {ftype:<22} {cnt:>5}")
    h("Top 10 nodes by total fields")
    for name, cnt in top_total:
        lines.append(f"  {name:<38} {cnt:>4} fields")
    h("Top 10 nodes by required fields")
    for name, cnt in top_required:
        lines.append(f"  {name:<38} {cnt:>4} required")
    h("PII field detection  (v3 — token-based)")
    pii_pct = 100 * total_pii / max(total_fields, 1)
    lines.append(f"  Total PII fields:              {total_pii}  ({pii_pct:.1f}%)")
    lines.append(f"  PII confidence breakdown:")
    for conf in ["high", "medium", "low"]:
        cnt = pii_by_conf.get(conf, 0)
        lines.append(f"    {conf:<8}  {cnt:>5}")
    h("PII by category")
    for cat, cnt in sorted(pii_cat_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {cat:<20} {cnt:>4}")
    h("Top 10 nodes with most PII fields")
    for name, cnt in top_pii_nodes:
        lines.append(f"  {name:<38} {cnt:>3} PII")
    h(f"Warnings ({len(all_warnings)} total)")
    for w in all_warnings[:60]:
        lines.append(f"  {w}")
    if len(all_warnings) > 60:
        lines.append(f"  ... and {len(all_warnings)-60} more.")
    h("Output files")
    lines.append(f"  {DB_PATH.relative_to(PROJECT_ROOT)}  (nodes table)")
    lines.append(f"  {OUT_SUMMARY.relative_to(PROJECT_ROOT)}")

    summary_text = "\n".join(lines)
    OUT_SUMMARY.write_text(summary_text, encoding="utf-8")
    print(f"Writing summary -> {OUT_SUMMARY.relative_to(PROJECT_ROOT)}")
    print()
    print(summary_text)
    print("\nPhase 1 complete.")


if __name__ == "__main__":
    main()
