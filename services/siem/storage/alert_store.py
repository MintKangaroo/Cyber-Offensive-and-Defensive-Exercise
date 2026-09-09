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
        columns={r[1] for r in conn.execute('PRAGMA table_info(alerts)')}
        for field in ('team_id','scenario_id'):
            if field not in columns:conn.execute('ALTER TABLE alerts ADD COLUMN '+field+' TEXT')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_alert_scope ON alerts(team_id,scenario_id,timestamp)')
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
        conn.execute("UPDATE alerts SET team_id=?,scenario_id=? WHERE id=?", (matched_event.get("team_id"),matched_event.get("scenario_id"),alert_id))
        conn.commit()
        conn.close()
        return alert_id

    def list_alerts(self, status: Optional[str] = None, severity_min: Optional[int] = None,
                    limit: int = 100, team_id: str = "", scenario_id: str = "", offset: int = 0) -> list[dict]:
        conn = self._conn()
        conditions = []
        params: list = []
        for key,value in (("team_id",team_id),("scenario_id",scenario_id)):
            if value:conditions.append(key+" = ?");params.append(value)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity_min is not None:
            conditions.append("severity >= ?")
            params.append(severity_min)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        rows = conn.execute(
            f"SELECT * FROM alerts {where} ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?", params + [limit,max(0,offset)]
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

    def stats_by_severity(self, team_id="", scenario_id="") -> dict[int, int]:
        conn = self._conn()
        where,params=self._scope_where(team_id,scenario_id)
        rows = conn.execute("SELECT severity, COUNT(*) as c FROM alerts"+where+" GROUP BY severity",params).fetchall()
        conn.close()
        return {r["severity"]: r["c"] for r in rows}

    def top_signatures(self, limit: int = 10, team_id="", scenario_id="") -> list[dict]:
        conn = self._conn()
        where,params=self._scope_where(team_id,scenario_id)
        rows = conn.execute(
            "SELECT rule_id, title, COUNT(*) as c FROM alerts"+where+" GROUP BY rule_id ORDER BY c DESC LIMIT ?", params+[limit]
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get(self, alert_id: str) -> dict | None:
        conn=self._conn()
        row=conn.execute('SELECT * FROM alerts WHERE id=?',(alert_id,)).fetchone()
        conn.close()
        if not row:return None
        data=dict(row)
        data['matched_event']=json.loads(data['matched_event'] or '{}')
        data['mitre']=json.loads(data['mitre'] or '[]')
        return data

    @staticmethod
    def _scope_where(team_id,scenario_id):
        conditions=[];params=[]
        for key,value in (("team_id",team_id),("scenario_id",scenario_id)):
            if value:conditions.append(key+"=?");params.append(value)
        return (" WHERE "+" AND ".join(conditions) if conditions else ""), params
