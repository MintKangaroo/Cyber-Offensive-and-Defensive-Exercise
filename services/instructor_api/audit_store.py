"""
Instructor API 전용 audit 저장소 (24번 문서 3절)
====================================================
config_service의 audit_log(patch/quarantine/killswitch 전용)와는 별개로,
scenario/event/score 액션을 append-only로 기록한다. 대시보드는 두 소스를
시간순으로 병합해서 보여준다(24번 문서 6절).
"""
import os
import sqlite3
import time
import uuid
from pathlib import Path

DB_PATH = Path(os.environ.get("DATA_DIR", str(Path(__file__).parent))) / "instructor_audit.db"  # 볼륨 영속(P0-3)


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    conn = _get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id TEXT PRIMARY KEY,
            timestamp REAL,
            actor TEXT,
            action TEXT,
            target TEXT,
            reason TEXT
        )
        """
    )
    conn.commit()
    conn.close()


_init_db()


def record(actor: str, action: str, target: str, reason: str) -> str:
    audit_id = str(uuid.uuid4())
    conn = _get_db()
    conn.execute(
        "INSERT INTO audit_log (audit_id, timestamp, actor, action, target, reason) VALUES (?, ?, ?, ?, ?, ?)",
        (audit_id, time.time(), actor, action, target, reason),
    )
    conn.commit()
    conn.close()
    return audit_id


def list_entries(limit: int = 200) -> list[dict]:
    conn = _get_db()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()]
    conn.close()
    return rows
