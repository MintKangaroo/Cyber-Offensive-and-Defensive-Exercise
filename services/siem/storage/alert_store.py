"""
Alert Store (M5.4)
=====================
Detection Engine이 생성한 Alert를 저장/조회. pydantic 비의존(순수 sqlite3)이라
가볍고 테스트하기 쉽다.
"""
from __future__ import annotations
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Optional


class AlertStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                rule_id TEXT,
                title TEXT,
                severity INTEGER,
                mitre TEXT,
                status TEXT DEFAULT 'open',
                timestamp REAL,
                detail TEXT,
                matched_event TEXT
            )
            """
        )
        conn.commit()
        conn.close()

    def save(self, rule_id: str, title: str, severity: int, mitre: list[str],
            timestamp: float, detail: str, matched_event: dict) -> str:
        alert_id = str(uuid.uuid4())
        conn = self._conn()
        conn.execute(
            "INSERT INTO alerts (id, rule_id, title, severity, mitre, timestamp, detail, matched_event) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (alert_id, rule_id, title, severity, json.dumps(mitre), timestamp, detail, json.dumps(matched_event)),
        )
        conn.commit()
        conn.close()
        return alert_id

    def list_alerts(self, status: Optional[str] = None, severity_min: Optional[int] = None,
                    limit: int = 100) -> list[dict]:
        conn = self._conn()
        conditions = []
        params: list = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity_min is not None:
            conditions.append("severity >= ?")
            params.append(severity_min)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?", params + [limit]
        ).fetchall()
        conn.close()
        # mitre/matched_event는 저장 시 json.dumps로 문자열화했으므로 읽을 때 되돌린다.
        # (안 그러면 소비자가 mitre 리스트 대신 '["T1234"]' 문자열을 받아 char 단위로
        #  순회하는 버그가 난다 — 예: AAR attack heatmap.)
        result = []
        for r in rows:
            d = dict(r)
            for field in ("mitre", "matched_event"):
                if isinstance(d.get(field), str):
                    try:
                        d[field] = json.loads(d[field])
                    except (json.JSONDecodeError, TypeError):
                        pass
            result.append(d)
        return result

    def update_status(self, alert_id: str, status: str) -> bool:
        conn = self._conn()
        cur = conn.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
        conn.commit()
        conn.close()
        return cur.rowcount > 0

    def stats_by_severity(self) -> dict[int, int]:
        conn = self._conn()
        rows = conn.execute("SELECT severity, COUNT(*) as c FROM alerts GROUP BY severity").fetchall()
        conn.close()
        return {r["severity"]: r["c"] for r in rows}

    def top_signatures(self, limit: int = 10) -> list[dict]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT rule_id, title, COUNT(*) as c FROM alerts GROUP BY rule_id ORDER BY c DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
