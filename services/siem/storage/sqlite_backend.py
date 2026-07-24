"""
SQLite Storage Backend (22번 문서 3절, M5.1)
================================================
storage_interface.StorageBackend의 MVP 구현체. FTS5로 전문검색 지원.
운영 규모가 커지면 opensearch_backend.py(동일 인터페이스)로 교체 가능.
"""
from __future__ import annotations
import json
import sqlite3
import time as _time
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

import sys
sys.path.append(str(Path(__file__).parent.parent.parent.parent))
from shared.storage_interface import StorageBackend, SearchQuery  # noqa: E402
from shared.siem_schema import NormalizedEvent, NetEndpoint  # noqa: E402


class SqliteBackend(StorageBackend):
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._conn()
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp REAL,
                ingested_at REAL,
                source_type TEXT,
                source_ip TEXT,
                host TEXT,
                asset TEXT,
                severity INTEGER,
                category TEXT,
                action TEXT,
                signature TEXT,
                signature_id TEXT,
                mitre TEXT,
                trace_id TEXT,
                vuln_id TEXT,
                team_id TEXT,
                message TEXT,
                raw TEXT,
                tags TEXT
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
                message, raw, content='events', content_rowid='rowid'
            );
            CREATE INDEX IF NOT EXISTS idx_events_asset ON events(asset);
            CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source_type);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            """
        )
        conn.commit()
        conn.close()

    async def index(self, event: NormalizedEvent) -> None:
        conn = self._conn()
        self._insert(conn, event)
        conn.commit()
        conn.close()

    async def bulk_index(self, events: list[NormalizedEvent]) -> int:
        conn = self._conn()
        count = 0
        for e in events:
            if self._insert(conn, e):
                count += 1
        conn.commit()
        conn.close()
        return count

    def _insert(self, conn: sqlite3.Connection, event: NormalizedEvent) -> bool:
        existing = conn.execute(
            "SELECT 1 FROM events WHERE event_id=?", (event.event_id,)
        ).fetchone()
        if existing:
            return False  # 멱등(중복 event_id 무시)
        conn.execute(
            """
            INSERT INTO events (event_id, timestamp, ingested_at, source_type, source_ip, host,
                                asset, severity, category, action, signature, signature_id,
                                mitre, trace_id, vuln_id, team_id, message, raw, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id, event.timestamp.timestamp(), event.ingested_at.timestamp(),
                event.source_type, event.source_ip, event.host, event.asset, event.severity,
                event.category, event.action, event.signature, event.signature_id,
                json.dumps(event.mitre), event.trace_id, event.vuln_id, event.team_id,
                event.message, json.dumps(event.raw), json.dumps(event.tags),
            ),
        )
        rowid = conn.execute("SELECT rowid FROM events WHERE event_id=?", (event.event_id,)).fetchone()[0]
        conn.execute(
            "INSERT INTO events_fts (rowid, message, raw) VALUES (?, ?, ?)",
            (rowid, event.message, json.dumps(event.raw)),
        )
        return True

    def _row_to_event(self, row: sqlite3.Row) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=row["event_id"],
            timestamp=datetime.fromtimestamp(row["timestamp"], tz=timezone.utc),
            ingested_at=datetime.fromtimestamp(row["ingested_at"], tz=timezone.utc),
            source_type=row["source_type"],
            source_ip=row["source_ip"],
            host=row["host"],
            asset=row["asset"],
            severity=row["severity"],
            category=row["category"] or "uncategorized",
            action=row["action"],
            signature=row["signature"],
            signature_id=row["signature_id"],
            mitre=json.loads(row["mitre"] or "[]"),
            trace_id=row["trace_id"],
            vuln_id=row["vuln_id"],
            team_id=row["team_id"],
            message=row["message"] or "",
            raw=json.loads(row["raw"] or "{}"),
            tags=json.loads(row["tags"] or "[]"),
        )

    def _build_conditions(self, query: SearchQuery) -> tuple[list[str], list[Any]]:
        """WHERE 키워드 없이 조건절 리스트만 반환(호출부가 필요에 맞게 조합)."""
        conditions = []
        params: list[Any] = []
        if query.source_type:
            conditions.append("source_type = ?")
            params.append(query.source_type)
        if query.asset:
            conditions.append("asset = ?")
            params.append(query.asset)
        if query.severity_min is not None:
            conditions.append("severity >= ?")
            params.append(query.severity_min)
        if query.mitre:
            conditions.append("mitre LIKE ?")
            params.append(f"%{query.mitre}%")
        if query.time_from:
            conditions.append("timestamp >= ?")
            params.append(query.time_from.timestamp())
        if query.time_to:
            conditions.append("timestamp <= ?")
            params.append(query.time_to.timestamp())
        return conditions, params

    def _build_where(self, query: SearchQuery) -> tuple[str, list[Any]]:
        """일반 검색(FTS 미사용)용: 'WHERE ...' 절 완성형 반환."""
        conditions, params = self._build_conditions(query)
        where = (" WHERE " + " AND ".join(conditions)) if conditions else ""
        return where, params

    async def search(self, query: SearchQuery) -> list[NormalizedEvent]:
        conn = self._conn()

        if query.text:
            # FTS MATCH 조건 + 나머지 필터 조건을 모두 AND로 결합(WHERE 키워드는 한 번만)
            extra_conditions, extra_params = self._build_conditions(query)
            all_conditions = ["f.events_fts MATCH ?"] + [f"e.{c}" for c in extra_conditions]
            where_clause = " WHERE " + " AND ".join(all_conditions)
            sql = (
                "SELECT e.* FROM events e JOIN events_fts f ON e.rowid = f.rowid "
                f"{where_clause} ORDER BY e.timestamp DESC LIMIT ? OFFSET ?"
            )
            full_params = [query.text] + extra_params + [query.limit, query.offset]
        else:
            where, params = self._build_where(query)
            sql = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            full_params = params + [query.limit, query.offset]

        rows = conn.execute(sql, full_params).fetchall()
        conn.close()
        return [self._row_to_event(r) for r in rows]

    async def aggregate(self, field: str, query: SearchQuery) -> dict[str, int]:
        if field not in {"source_type", "asset", "severity", "category", "signature", "vuln_id", "team_id"}:
            raise ValueError(f"aggregate field not allowed: {field}")
        conn = self._conn()
        where, params = self._build_where(query)
        sql = f"SELECT {field} as k, COUNT(*) as c FROM events {where} GROUP BY {field}"
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return {str(r["k"]): r["c"] for r in rows}

    async def count(self, query: SearchQuery) -> int:
        conn = self._conn()
        where, params = self._build_where(query)
        row = conn.execute(f"SELECT COUNT(*) as c FROM events {where}", params).fetchone()
        conn.close()
        return row["c"]

    async def health(self) -> dict[str, Any]:
        conn = self._conn()
        total = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]
        by_source = conn.execute(
            "SELECT source_type, COUNT(*) as c, MAX(timestamp) as last FROM events GROUP BY source_type"
        ).fetchall()
        conn.close()
        return {
            "backend": "sqlite",
            "db_path": self.db_path,
            "total_events": total,
            "by_source": {
                r["source_type"]: {"count": r["c"], "last_seen": r["last"]} for r in by_source
            },
            "checked_at": _time.time(),
        }
