"""
SQLite database helpers.

SQLite is a single file database (data/threat_intel.db) - perfect for a
student project: no server to install, and it supports real SQL, indexes
and foreign keys.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent / "models" / "schema.sql"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def get_connection(db_path: str) -> sqlite3.Connection:
    """Open a connection that returns rows as dict-like objects."""
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    conn.commit()


def drop_all(conn: sqlite3.Connection) -> None:
    """Remove every table so `init_db` can rebuild from scratch."""
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    conn.execute("PRAGMA foreign_keys = OFF")
    for t in tables:
        conn.execute(f'DROP TABLE IF EXISTS "{t}"')
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()


def set_meta(conn, key: str, value) -> None:
    conn.execute("INSERT INTO app_meta(key, value) VALUES (?, ?) "
                 "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, str(value)))


def get_meta(conn, key: str, default=None):
    row = conn.execute("SELECT value FROM app_meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def audit(conn, actor_role: str, action: str, target: str, detail: str = "") -> None:
    """Record every write so administrative changes are traceable."""
    conn.execute("INSERT INTO audit_log(actor_role, action, target, detail, created_at) VALUES (?,?,?,?,?)",
                 (actor_role, action, target, detail[:500], utc_now()))


# ---------------------------------------------------------------------------
# Flask integration: one connection per request, closed automatically.
# ---------------------------------------------------------------------------
def get_db():
    from flask import current_app, g

    if "db" not in g:
        g.db = get_connection(current_app.config["DATABASE_PATH"])
    return g.db


def close_db(_exc=None):
    from flask import g

    db = g.pop("db", None)
    if db is not None:
        db.close()
