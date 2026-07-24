"""
Event Collector (제안서 3장/7장 대응)

- POST /events        : 트윈으로부터 이벤트 수신, event_id 기준 dedup, DB 저장
- GET  /events         : Dashboard의 Event Timeline용 조회
- WS   /ws             : Dashboard 실시간 스트림
- 저장 후 Scoring Engine에 비동기로 전달 (실패해도 이벤트 저장 자체는 성공 처리)
"""

import sqlite3
import json
import asyncio
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))  # repo root (shared/ 위치)
from shared.event_schema import Event  # noqa: E402

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "events.db"
SCORING_ENGINE_URL = "http://scoring_engine:8020"

app = FastAPI(title="Event Collector")

# Live Fire 대시보드(로컬 dev 5174 등)가 브라우저에서 직접 이 API로 fetch 하므로 CORS 필요.
# 로컬 개발/훈련 범위이므로 localhost 전 포트를 허용(운영에선 리버스프록시/명시 origin 권장).
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
app.add_middleware(
    CORSMiddleware, allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

_ws_clients: set[WebSocket] = set()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            event_type TEXT,
            timestamp REAL,
            actor TEXT,
            team_id TEXT,
            scenario_id TEXT,
            target_asset TEXT,
            vuln_id TEXT,
            phase TEXT,
            trace_id TEXT,
            matched_event_id TEXT,
            challenge_id TEXT,
            schema_version TEXT,
            metadata TEXT,
            received_at REAL DEFAULT (strftime('%s','now'))
        )
        """
    )
    # 기존 DB(v1.0)에 신규 컬럼이 없을 수 있으므로 방어적으로 추가(이미 있으면 무시)
    for col in ["trace_id", "matched_event_id", "challenge_id", "schema_version"]:
        try:
            conn.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
        except sqlite3.OperationalError:
            pass  # 컬럼이 이미 존재
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_trace_id ON events(trace_id)")
    conn.commit()
    conn.close()


init_db()


@app.on_event("startup")
async def startup():
    pass


@app.get("/health")
def health():
    return {"status": "ok", "service": "event_collector"}


@app.post("/events")
async def ingest_event(event: Event):
    conn = get_db()
    cur = conn.execute("SELECT 1 FROM events WHERE event_id = ?", (event.event_id,))
    is_duplicate = cur.fetchone() is not None

    if not is_duplicate:
        conn.execute(
            """
            INSERT INTO events (event_id, event_type, timestamp, actor, team_id,
                                 scenario_id, target_asset, vuln_id, phase,
                                 trace_id, matched_event_id, challenge_id, schema_version, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id, event.event_type.value, event.timestamp, event.actor,
                event.team_id, event.scenario_id, event.target_asset, event.vuln_id,
                event.phase.value if event.phase else None,
                event.trace_id, event.matched_event_id, event.challenge_id, event.schema_version,
                json.dumps(event.metadata),
            ),
        )
        conn.commit()
    conn.close()

    # Dashboard 실시간 스트림으로 브로드캐스트 (중복이어도 UI 갱신은 상관없음)
    await _broadcast(event)

    # Scoring Engine에 전달 (신규 이벤트일 때만; 실패해도 이벤트 저장은 이미 완료됨)
    if not is_duplicate:
        asyncio.create_task(_forward_to_scoring_engine(event))

    return {"stored": not is_duplicate, "duplicate": is_duplicate, "event_id": event.event_id}


def _lookup_matched_timestamp(matched_event_id: str) -> Optional[float]:
    """matched_event_id(원 공격 이벤트)의 timestamp를 조회. dwell time(04번 3절) 계산용."""
    conn = get_db()
    row = conn.execute("SELECT timestamp FROM events WHERE event_id = ?", (matched_event_id,)).fetchone()
    conn.close()
    return row["timestamp"] if row else None


async def _forward_to_scoring_engine(event: Event):
    payload = event.model_dump(mode="json")
    # dwell time 계산을 위해 원 공격 이벤트의 timestamp를 enrichment(04번 3절)
    if event.matched_event_id:
        matched_ts = _lookup_matched_timestamp(event.matched_event_id)
        if matched_ts is not None:
            payload.setdefault("metadata", {})["_matched_timestamp"] = matched_ts
        else:
            # 대응하는 공격 이벤트를 찾지 못함 -> 오탐/치팅 의심 신호(04번 1절 unmatched_detection)
            payload.setdefault("metadata", {})["_unmatched"] = True
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(f"{SCORING_ENGINE_URL}/score/ingest", json=payload)
    except httpx.HTTPError:
        pass  # Scoring Engine이 다운이어도 Event Collector는 계속 동작


async def _broadcast(event: Event):
    dead = set()
    for ws in _ws_clients:
        try:
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.send_json(event.model_dump(mode="json"))
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


@app.get("/events")
def list_events(limit: int = 100, target_asset: Optional[str] = None, team_id: Optional[str] = None):
    conn = get_db()
    query = "SELECT * FROM events"
    conditions = []
    params = []
    if target_asset:
        conditions.append("target_asset = ?")
        params.append(target_asset)
    if team_id:
        conditions.append("team_id = ?")
        params.append(team_id)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = [dict(r) for r in conn.execute(query, params).fetchall()]
    conn.close()
    return {"events": rows}


@app.get("/replay/events")
def replay_events(scenario_id: str = "default", time_from: Optional[float] = None,
                  time_to: Optional[float] = None, team_id: Optional[str] = None):
    """훈련 종료 후 리플레이(07번 문서 1절)용 시간순 전체 이벤트."""
    conn = get_db()
    query = "SELECT * FROM events WHERE scenario_id = ?"
    params: list = [scenario_id]
    if time_from is not None:
        query += " AND timestamp >= ?"
        params.append(time_from)
    if time_to is not None:
        query += " AND timestamp <= ?"
        params.append(time_to)
    if team_id:
        query += " AND team_id = ?"
        params.append(team_id)
    query += " ORDER BY timestamp ASC"
    rows = [dict(r) for r in conn.execute(query, params).fetchall()]
    conn.close()
    return {"scenario_id": scenario_id, "count": len(rows), "events": rows}


@app.websocket("/ws")
async def event_stream(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()  # 클라이언트로부터의 ping 등 무시
    except WebSocketDisconnect:
        _ws_clients.discard(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8010)
