"""Persistent knowledge base backed by SQLite."""

import logging
import sqlite3
from datetime import datetime, timedelta, timezone

log = logging.getLogger("fio-bot")

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alertname TEXT NOT NULL,
    instance TEXT,
    severity TEXT,
    category TEXT,
    summary TEXT,
    findings TEXT,
    github_issue_url TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    topic TEXT NOT NULL,
    note TEXT NOT NULL,
    author TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_investigations_alertname
    ON investigations(alertname);
CREATE INDEX IF NOT EXISTS idx_investigations_created
    ON investigations(created_at);
CREATE INDEX IF NOT EXISTS idx_notes_topic ON notes(topic);
"""


def init_db(db_path):
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    log.info("Knowledge base initialized at %s", db_path)
    return conn


def store_investigation(conn, alert_info, findings, github_issue_url=None):
    conn.execute(
        "INSERT INTO investigations"
        " (alertname, instance, severity, category, summary,"
        "  findings, github_issue_url, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            alert_info["alertname"],
            alert_info.get("instance"),
            alert_info.get("severity"),
            alert_info.get("category"),
            alert_info.get("summary"),
            findings,
            github_issue_url,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    log.info("Stored investigation for %s", alert_info["alertname"])


def get_past_investigations(conn, alertname, limit=5):
    rows = conn.execute(
        "SELECT alertname, instance, severity, category, summary,"
        " findings, github_issue_url, created_at"
        " FROM investigations WHERE alertname = ?"
        " ORDER BY created_at DESC LIMIT ?",
        (alertname, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def store_note(conn, topic, note, author=None):
    conn.execute(
        "INSERT INTO notes (topic, note, author, created_at)" " VALUES (?, ?, ?, ?)",
        (topic, note, author, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    log.info("Stored note for topic '%s'", topic)


def get_notes(conn, topic=None, limit=10):
    if topic:
        rows = conn.execute(
            "SELECT topic, note, author, created_at FROM notes"
            " WHERE topic = ? ORDER BY created_at DESC LIMIT ?",
            (topic, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT topic, note, author, created_at FROM notes"
            " ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def cleanup(conn, retention_days, max_rows):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()

    inv_deleted = conn.execute(
        "DELETE FROM investigations WHERE created_at < ?", (cutoff,)
    ).rowcount
    notes_deleted = conn.execute(
        "DELETE FROM notes WHERE created_at < ?", (cutoff,)
    ).rowcount

    total = conn.execute(
        "SELECT (SELECT COUNT(*) FROM investigations)" " + (SELECT COUNT(*) FROM notes)"
    ).fetchone()[0]

    overflow_deleted = 0
    if total > max_rows:
        excess = total - max_rows
        conn.execute(
            "DELETE FROM investigations WHERE id IN"
            " (SELECT id FROM investigations ORDER BY created_at ASC LIMIT ?)",
            (excess,),
        )
        overflow_deleted = excess

    if inv_deleted or notes_deleted or overflow_deleted:
        conn.commit()
        log.info(
            "Knowledge cleanup: %d investigations, %d notes expired,"
            " %d overflow pruned",
            inv_deleted,
            notes_deleted,
            overflow_deleted,
        )


def get_stats(conn):
    inv_count = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
    notes_count = conn.execute("SELECT COUNT(*) FROM notes").fetchone()[0]
    oldest = conn.execute("SELECT MIN(created_at) FROM investigations").fetchone()[0]
    newest = conn.execute("SELECT MAX(created_at) FROM investigations").fetchone()[0]
    top_alerts = conn.execute(
        "SELECT alertname, COUNT(*) as cnt FROM investigations"
        " GROUP BY alertname ORDER BY cnt DESC LIMIT 5"
    ).fetchall()
    return {
        "investigations": inv_count,
        "notes": notes_count,
        "oldest": oldest,
        "newest": newest,
        "top_alerts": [(r["alertname"], r["cnt"]) for r in top_alerts],
    }
