"""Durable SSE cursor and stable, signed replay pages, independent of the live bus."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from fastapi import HTTPException


def initialize(conn):
    conn.execute(
        "CREATE TABLE IF NOT EXISTS stream_journal(seq INTEGER PRIMARY KEY AUTOINCREMENT, topic TEXT NOT NULL, data TEXT NOT NULL, event_id TEXT UNIQUE, published_at REAL NOT NULL)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_journal_published ON stream_journal(published_at,seq)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS stream_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO stream_meta VALUES(?,?)",
        ("cursor_key", secrets.token_hex(32)),
    )
    conn.execute("INSERT OR IGNORE INTO stream_meta VALUES('revision','0')")
    # Upgrade retained historical events once, in their actual chronological order.
    if not conn.execute("SELECT 1 FROM stream_meta WHERE key='migrated'").fetchone():
        for row in conn.execute("SELECT * FROM events ORDER BY timestamp,event_id"):
            data = dict(row)
            append(
                conn,
                "detections"
                if data["event_type"]
                in {
                    "blue_detection_success",
                    "blue_block_success",
                    "unmatched_detection",
                }
                else "events",
                data,
                data["event_id"],
            )
        conn.execute("INSERT INTO stream_meta VALUES('migrated','1')")


def append(conn, topic, data, event_id=None):
    cursor = conn.execute(
        "INSERT OR IGNORE INTO stream_journal(topic,data,event_id,published_at) VALUES(?,?,?,?)",
        (topic, json.dumps(data), event_id, time.time()),
    )
    return cursor.lastrowid


def messages(conn, after, limit=512, cutoff=None):
    query = "SELECT seq,topic,data,published_at FROM stream_journal WHERE seq>?"
    params = [after]
    if cutoff is not None:
        query += " AND published_at<=?"
        params.append(cutoff)
    rows = conn.execute(query + " ORDER BY seq LIMIT ?", params + [limit]).fetchall()
    return [
        {"id": r["seq"], "topic": r["topic"], "data": json.loads(r["data"])}
        for r in rows
    ]


def bounds(conn):
    row = conn.execute("SELECT MIN(seq),MAX(seq) FROM stream_journal").fetchone()
    # sqlite_sequence survives a reset: IDs cannot refer to a different exercise later.
    last = conn.execute(
        "SELECT seq FROM sqlite_sequence WHERE name='stream_journal'"
    ).fetchone()
    return (row[0] or 0, last[0] if last else 0)


def encode_cursor(conn, value):
    raw = (
        base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    key = conn.execute(
        "SELECT value FROM stream_meta WHERE key='cursor_key'"
    ).fetchone()[0]
    return raw + "." + hmac.new(key.encode(), raw.encode(), hashlib.sha256).hexdigest()


def decode_cursor(conn, value):
    try:
        raw, signature = value.split(".")
        key = conn.execute(
            "SELECT value FROM stream_meta WHERE key='cursor_key'"
        ).fetchone()[0]
        if not hmac.compare_digest(
            signature, hmac.new(key.encode(), raw.encode(), hashlib.sha256).hexdigest()
        ):
            raise ValueError()
        return json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (ValueError, TypeError, KeyError):
        raise HTTPException(400, "Invalid replay cursor") from None


def revision(conn):
    return conn.execute(
        "SELECT value FROM stream_meta WHERE key='revision'"
    ).fetchone()[0]


def invalidate_history(conn):
    conn.execute(
        "UPDATE stream_meta SET value=CAST(value AS INTEGER)+1 WHERE key='revision'"
    )
