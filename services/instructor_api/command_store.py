"""Small durable command preferences; operational truth remains in source services."""

from __future__ import annotations
import json
import sqlite3
import time
from . import audit_store


def _db():
    conn = sqlite3.connect(audit_store.DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS command_documents (kind TEXT, owner TEXT, id TEXT, payload TEXT, updated_at REAL, PRIMARY KEY(kind,owner,id))"
    )
    return conn


def save(kind: str, owner: str, key: str, data: dict):
    with _db() as conn:
        conn.execute(
            "INSERT INTO command_documents VALUES(?,?,?,?,?) ON CONFLICT(kind,owner,id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at",
            (kind, owner, key, json.dumps(data), time.time()),
        )
    conn.close()


def get(kind: str, owner: str, key: str) -> dict | None:
    conn = _db()
    row = conn.execute(
        "SELECT payload FROM command_documents WHERE kind=? AND owner=? AND id=?",
        (kind, owner, key),
    ).fetchone()
    conn.close()
    return json.loads(row["payload"]) if row else None


def entries(kind: str, owner: str) -> list[dict]:
    conn = _db()
    rows = conn.execute(
        "SELECT id,payload,updated_at FROM command_documents WHERE kind=? AND owner=? ORDER BY updated_at DESC LIMIT 500",
        (kind, owner),
    ).fetchall()
    conn.close()
    return [
        {"id": r["id"], "updated_at": r["updated_at"], **json.loads(r["payload"])}
        for r in rows
    ]
