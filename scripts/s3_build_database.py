import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH      = PROJECT_ROOT / "data" / "ede_research_v2.db"

# Verify old DB is not being touched
OLD_DB = PROJECT_ROOT / "data" / "ede_research.db"
assert OLD_DB.exists(), "Old DB missing - abort"

TABLES = {
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
            optional_fields TEXT    NOT NULL DEFAULT '[]',
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

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_nodes_node_name  ON nodes(node_name)",
    "CREATE INDEX IF NOT EXISTS idx_nodes_is_pii     ON nodes(is_pii)",
    "CREATE INDEX IF NOT EXISTS idx_wf_source        ON workflows(source)",
    "CREATE INDEX IF NOT EXISTS idx_wf_hash          ON workflows(nodes_hash)",
    "CREATE INDEX IF NOT EXISTS idx_wfn_workflow_id  ON workflow_nodes(workflow_id)",
    "CREATE INDEX IF NOT EXISTS idx_wfn_type         ON workflow_nodes(node_type)",
    "CREATE INDEX IF NOT EXISTS idx_nodeops_name     ON node_operations(node_name)",
    "CREATE INDEX IF NOT EXISTS idx_findings_wf_id   ON exposure_findings(workflow_id)",
    "CREATE INDEX IF NOT EXISTS idx_findings_type    ON exposure_findings(node_type)",
    "CREATE INDEX IF NOT EXISTS idx_findings_scope   ON exposure_findings(node_scope)",
]

print('=== CREATING FRESH DATABASE ===')
print(f'Path: {DB_PATH}')

if DB_PATH.exists():
    DB_PATH.unlink()
    print('Removed existing v2 database')

con = sqlite3.connect(DB_PATH)
con.execute("PRAGMA journal_mode = WAL")
con.execute("PRAGMA foreign_keys = ON")

for table_name, ddl in TABLES.items():
    con.execute(ddl)
    print(f'  Created table: {table_name}')

for idx in INDEXES:
    con.execute(idx)
con.commit()

print()
print('=== VERIFYING TABLES ===')
cur = con.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = [r[0] for r in cur.fetchall()]
for t in tables:
    cur.execute(f'SELECT COUNT(*) FROM {t}')
    print(f'  {t}: {cur.fetchone()[0]} rows (should be 0)')

con.close()
print()
print(f'Database size: {DB_PATH.stat().st_size} bytes')
print('=== FRESH DATABASE READY ===')
