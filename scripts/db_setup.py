"""
db_setup.py — Create (or recreate) the EDE research SQLite database.

Creates data/ede_research.db with five tables:
  nodes              — Phase 1: minimum field registry
  workflows          — Phase 2: collected workflow metadata
  workflow_nodes     — Phase 2: individual node instances per workflow
  node_operations    — Phase 1b: operation/resource-conditional required fields
  exposure_findings  — Phase 3: EDE measurement results

v2 schema additions:
  nodes              → pii_confidence TEXT, type_version TEXT, is_trigger INTEGER
  exposure_findings  → node_scope TEXT, pii_via_expression INTEGER,
                       pii_high_unnecessary INTEGER, pii_medium_unnecessary INTEGER,
                       pii_low_unnecessary INTEGER

Safe to re-run: CREATE TABLE IF NOT EXISTS preserves existing data.
Pass --reset to DROP and recreate all tables from scratch.
"""

import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH      = PROJECT_ROOT / "data" / "ede_research.db"

# ── DDL statements ────────────────────────────────────────────────────────────

TABLES: dict[str, str] = {

    "nodes": """
        CREATE TABLE IF NOT EXISTS nodes (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            node_name      TEXT    NOT NULL,
            field_name     TEXT    NOT NULL,
            required       INTEGER NOT NULL DEFAULT 0,
            field_type     TEXT    NOT NULL DEFAULT 'unknown',
            is_pii         INTEGER NOT NULL DEFAULT 0,
            pii_category   TEXT    NOT NULL DEFAULT '',
            pii_confidence TEXT    NOT NULL DEFAULT '',
            type_version   TEXT    NOT NULL DEFAULT '*',
            is_trigger     INTEGER NOT NULL DEFAULT 0
        )
    """,

    "workflows": """
        CREATE TABLE IF NOT EXISTS workflows (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            filename             TEXT    UNIQUE NOT NULL,
            source               TEXT    NOT NULL DEFAULT '',
            category             TEXT    NOT NULL DEFAULT '',
            node_count           INTEGER NOT NULL DEFAULT 0,
            external_node_count  INTEGER NOT NULL DEFAULT 0,
            has_pii_params       INTEGER NOT NULL DEFAULT 0,
            nodes_hash           TEXT    NOT NULL DEFAULT '',
            raw_json             TEXT    NOT NULL DEFAULT ''
        )
    """,

    "workflow_nodes": """
        CREATE TABLE IF NOT EXISTS workflow_nodes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            workflow_id     INTEGER NOT NULL REFERENCES workflows(id),
            node_type       TEXT    NOT NULL,
            node_name       TEXT    NOT NULL,
            parameters_json TEXT    NOT NULL DEFAULT '{}'
        )
    """,

    "node_operations": """
        CREATE TABLE IF NOT EXISTS node_operations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            node_name       TEXT    NOT NULL,
            operation       TEXT    NOT NULL DEFAULT '*',
            resource        TEXT    NOT NULL DEFAULT '*',
            required_fields TEXT    NOT NULL DEFAULT '[]',
            type_version    TEXT    NOT NULL DEFAULT '*',
            is_trigger      INTEGER NOT NULL DEFAULT 0
        )
    """,

    "exposure_findings": """
        CREATE TABLE IF NOT EXISTS exposure_findings (
            id                       INTEGER PRIMARY KEY AUTOINCREMENT,
            workflow_id              INTEGER NOT NULL REFERENCES workflows(id),
            node_type                TEXT    NOT NULL,
            node_scope               TEXT    NOT NULL DEFAULT 'unknown',
            fields_passed            INTEGER NOT NULL DEFAULT 0,
            fields_required          INTEGER NOT NULL DEFAULT 0,
            fields_unnecessary       INTEGER NOT NULL DEFAULT 0,
            overexposure_ratio       REAL    NOT NULL DEFAULT 0.0,
            pii_fields_exposed       INTEGER NOT NULL DEFAULT 0,
            pii_fields_required      INTEGER NOT NULL DEFAULT 0,
            pii_fields_unnecessary   INTEGER NOT NULL DEFAULT 0,
            pii_high_unnecessary     INTEGER NOT NULL DEFAULT 0,
            pii_medium_unnecessary   INTEGER NOT NULL DEFAULT 0,
            pii_low_unnecessary      INTEGER NOT NULL DEFAULT 0,
            pii_via_expression       INTEGER NOT NULL DEFAULT 0
        )
    """,
}

INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS idx_nodes_node_name    ON nodes(node_name)",
    "CREATE INDEX IF NOT EXISTS idx_nodes_is_pii       ON nodes(is_pii)",
    "CREATE INDEX IF NOT EXISTS idx_nodes_version      ON nodes(node_name, type_version)",
    "CREATE INDEX IF NOT EXISTS idx_wf_hash            ON workflows(nodes_hash)",
    "CREATE INDEX IF NOT EXISTS idx_wf_source          ON workflows(source)",
    "CREATE INDEX IF NOT EXISTS idx_wf_nodes_wf_id    ON workflow_nodes(workflow_id)",
    "CREATE INDEX IF NOT EXISTS idx_wf_nodes_type      ON workflow_nodes(node_type)",
    "CREATE INDEX IF NOT EXISTS idx_nodeops_name       ON node_operations(node_name)",
    "CREATE INDEX IF NOT EXISTS idx_findings_wf_id     ON exposure_findings(workflow_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_type      ON exposure_findings(node_type)",
    "CREATE INDEX IF NOT EXISTS idx_findings_scope     ON exposure_findings(node_scope)",
]

# Columns added in v2 that may not exist in an existing DB.
# Format: (table, column_name, column_def)
_MIGRATION_COLUMNS: list[tuple[str, str, str]] = [
    ("nodes",             "pii_confidence",        "TEXT    NOT NULL DEFAULT ''"),
    ("nodes",             "type_version",          "TEXT    NOT NULL DEFAULT '*'"),
    ("nodes",             "is_trigger",            "INTEGER NOT NULL DEFAULT 0"),
    ("node_operations",   "type_version",          "TEXT    NOT NULL DEFAULT '*'"),
    ("node_operations",   "is_trigger",            "INTEGER NOT NULL DEFAULT 0"),
    ("exposure_findings", "node_scope",            "TEXT    NOT NULL DEFAULT 'unknown'"),
    ("exposure_findings", "pii_high_unnecessary",  "INTEGER NOT NULL DEFAULT 0"),
    ("exposure_findings", "pii_medium_unnecessary","INTEGER NOT NULL DEFAULT 0"),
    ("exposure_findings", "pii_low_unnecessary",   "INTEGER NOT NULL DEFAULT 0"),
    ("exposure_findings", "pii_via_expression",    "INTEGER NOT NULL DEFAULT 0"),
]


def _migrate_columns(con: sqlite3.Connection) -> None:
    """Add v2 columns to existing tables if they don't already exist."""
    for table, col, col_def in _MIGRATION_COLUMNS:
        existing = {row[1] for row in con.execute(f"PRAGMA table_info({table})")}
        if col not in existing:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_def}")
            print(f"    MIGRATED  {table}.{col}")
    con.commit()


def create_database(reset: bool = False) -> sqlite3.Connection:
    """Open (or create) the database, apply DDL, return connection."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA foreign_keys = ON")

    if reset:
        print("  [reset] Dropping existing tables...")
        for table in reversed(list(TABLES)):
            con.execute(f"DROP TABLE IF EXISTS {table}")
        con.commit()

    print("  Creating tables (if not exist)...")
    for table_name, ddl in TABLES.items():
        con.execute(ddl)
        print(f"    OK  {table_name}")

    _migrate_columns(con)

    print("  Creating indexes...")
    for idx_sql in INDEXES:
        con.execute(idx_sql)
    con.commit()

    return con


def print_schema(con: sqlite3.Connection) -> None:
    print("\nDatabase schema:")
    rows = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    for (tbl,) in rows:
        cols = con.execute(f"PRAGMA table_info({tbl})").fetchall()
        print(f"\n  {tbl}")
        for col in cols:
            pk_flag  = " [PK]"         if col[5] else ""
            nn_flag  = " NOT NULL"     if col[3] else ""
            def_flag = f" DEFAULT {col[4]}" if col[4] is not None else ""
            print(f"    {col[1]:<32} {col[2]}{pk_flag}{nn_flag}{def_flag}")


def main() -> None:
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

    reset = "--reset" in sys.argv
    print("=" * 50)
    print("EDE Research — Database Setup  (v2)")
    print("=" * 50)
    print(f"\nDatabase path: {DB_PATH.relative_to(PROJECT_ROOT)}")
    print(f"Mode: {'RESET (drop + recreate)' if reset else 'safe (create if not exists)'}\n")

    con = create_database(reset=reset)
    print_schema(con)
    con.close()

    size_kb = DB_PATH.stat().st_size / 1024
    print(f"\nDone. Database file: {size_kb:.1f} KB")


if __name__ == "__main__":
    main()
