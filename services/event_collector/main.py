"""
Event Collector (제안서 3장/7장 대응)

- POST /events        : 트윈으로부터 이벤트 수신, event_id 기준 dedup, DB 저장
- GET  /events         : Dashboard의 Event Timeline용 조회
- WS   /ws             : Dashboard 실시간 스트림
- 저장 후 Scoring Engine에 비동기로 전달 (실패해도 이벤트 저장 자체는 성공 처리)
"""

import os
import sqlite3
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

import time
import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Header, Request, Cookie
from fastapi.responses import StreamingResponse
from starlette.websockets import WebSocketState

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))  # repo root (shared/ 위치)
from shared.event_schema import Event  # noqa: E402
from shared.lifespan import on_startup, on_shutdown  # noqa: E402

APP_DIR = Path(__file__).parent
DB_PATH = Path(os.environ.get("DATA_DIR", str(APP_DIR))) / "events.db"  # 볼륨 마운트로 영속(P0-3)
SCORING_ENGINE_URL = os.environ.get("SCORING_ENGINE_URL", "http://scoring_engine:8020")
OBSERVER_DELAY_SEC = float(os.environ.get("OBSERVER_DELAY_SEC", "30"))

from shared.rbac import require_role  # noqa: E402
from shared.service_auth import require_service_token, service_headers  # noqa: E402
from shared.sse_bus import SSEBus, visible_to, LIVE_TOPICS  # noqa: E402

# 단일 상황판 허브(P0-4). 모든 토픽을 이 버스로 흘려 EventSource 하나로 구독한다.
bus = SSEBus(buffer_size=2000)


def _topic_for(event: Event) -> str:
    """이벤트 → SSE 토픽 매핑. detections(탐지/차단) 는 별도 토픽으로 분리."""
    et = event.event_type.value
    if et in ("blue_detection_success", "blue_block_success", "unmatched_detection"):
        return "detections"
    return "events"


def _claims_from(authorization: str, cookie: str | None) -> tuple[str, str]:
    """Authorization/쿠키 → (role, match_id). 시크릿 미설정(dev)이면 (instructor, '')."""
    secret = os.environ.get("AUTH_JWT_SECRET", "").strip()
    tok = (authorization or "").replace("Bearer ", "").strip() or (cookie or "")
    if not secret or tok.count(".") != 2:
        return "instructor", ""   # dev 또는 비-JWT → 전체 열람(dev 편의, 운영은 gateway 게이트)
    try:
        import jwt
        c = jwt.decode(tok, secret, algorithms=["HS256"])
        if c.get("type") not in (None, "access"):
            return "observer", ""
        return c.get("role", "observer"), str(c.get("match_id", "") or "")
    except Exception:
        return "observer", ""   # 무효 토큰 → 가장 제한적(관전자·지연)

app = FastAPI(title="Event Collector")

# Live Fire 대시보드(로컬 dev 5174 등)가 브라우저에서 직접 이 API로 fetch 하므로 CORS 필요.
# 로컬 개발/훈련 범위이므로 localhost 전 포트를 허용(운영에선 리버스프록시/명시 origin 권장).
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
app.add_middleware(
    CORSMiddleware, allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|(\d{1,3}\.){3}\d{1,3}|[\w-]+\.ts\.net)(:\d+)?",
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

_ws_clients: set[WebSocket] = set()


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    # 동시성/내구성(감사 3.7): WAL로 read-while-write 허용, busy_timeout으로 락 경합 대기.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


# --- ingest 쓰기 최적화 (U-3 포화점 병목 해소 → 그룹 커밋) -----------------------
# 1차(75→450 EPS): 요청마다 커넥션 open+PRAGMA 하던 것을 단일 워커 executor의 영속
# 커넥션으로 옮기고 async 루프 블로킹을 제거했다. 워커가 하나뿐이라 커넥션은 항상 같은
# 스레드에서만 쓰여 락이 불필요하다.
# 2차(≥600 EPS 병목): 남은 천장은 "이벤트당 commit". 단일 writer가 초당 낼 수 있는 커밋
# 수가 유한하므로, 이벤트마다 트랜잭션을 열고 fsync 하면 그 커밋 레이트가 곧 처리량 상한이
# 된다. → **그룹 커밋**: 큐에 쌓인 이벤트를 한 트랜잭션(INSERT 여러 건 + commit 1회)으로
# 모은다. 저부하에선 큐가 비어 배치 크기 1(추가 지연 0), 고부하에선 writer가 커밋하는 동안
# 쌓인 이벤트를 다음 배치로 한꺼번에 흘려 커밋 1회에 N건을 처리한다(자기조정 group commit).
# 내구성·중복검사·응답 시맨틱은 그대로: 각 요청은 자기 이벤트가 포함된 배치가 commit 된
# 뒤에야 stored 결과를 받는다.
_write_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="evt-writer")
_writer_conn: Optional[sqlite3.Connection] = None
_INGEST_BATCH_MAX = int(os.environ.get("INGEST_BATCH_MAX_SIZE", "256"))
# (event, Future[bool]) 큐 — 배치 라이터 루프가 소비. startup 에서 러닝 루프에 바인딩되게
# 생성한다(모듈 로드 시점에 만들면 uvicorn 이 만드는 실제 서빙 루프와 다른 루프에 묶일 수
# 있어 put/get 이 어긋난다).
_ingest_queue: "Optional[asyncio.Queue[tuple[Event, asyncio.Future]]]" = None


def _get_ingest_queue() -> "asyncio.Queue[tuple[Event, asyncio.Future]]":
    global _ingest_queue
    if _ingest_queue is None:
        _ingest_queue = asyncio.Queue()
    return _ingest_queue


def _writer_connection() -> sqlite3.Connection:
    global _writer_conn
    if _writer_conn is None:
        _writer_conn = sqlite3.connect(DB_PATH, timeout=5.0)  # writer 스레드 전용
        _writer_conn.row_factory = sqlite3.Row
        _writer_conn.execute("PRAGMA journal_mode=WAL")
        _writer_conn.execute("PRAGMA synchronous=NORMAL")
        _writer_conn.execute("PRAGMA busy_timeout=5000")
    return _writer_conn


def _persist_batch(events: "list[Event]") -> "list[bool]":
    """이벤트 배치를 단일 트랜잭션(INSERT OR IGNORE 여러 건 + commit 1회)으로 저장한다.
    writer executor(단일 스레드)에서만 호출되므로 직렬화가 보장돼 락이 불필요하다.
    반환: 입력 순서에 정렬된 신규 저장 여부 리스트.

    중복검사는 `INSERT OR IGNORE`(PRIMARY KEY event_id 충돌 시 무시)로 SQLite(C) 안에서
    한 번에 처리한다 — 이벤트당 SELECT+INSERT 2회 왕복을 1회로 줄여 단일 writer 스레드의
    CPU 부담을 낮춘다(0.75 CPU 캡·고 EPS에서 병목 완화). 같은 배치 안의 중복 event_id 도
    같은 커넥션의 미커밋 INSERT 가 제약검사에 보이므로 두 번째는 무시된다(별도 seen 집합 불필요).
    신규 저장 여부는 각 INSERT 직후 cursor.rowcount(삽입=1, 무시=0)로 판정한다.

    배치 전체가 한 트랜잭션이라 commit 실패 시 전부 롤백되고 예외가 호출측(각 요청)으로
    전파된다 — 기존 커밋-당-이벤트와 동일하게 부분 성공을 만들지 않는다."""
    conn = _writer_connection()
    results: list[bool] = []
    wrote = False
    for event in events:
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO events (event_id, event_type, timestamp, actor, team_id,
                                 scenario_id, target_asset, vuln_id, phase,
                                 trace_id, matched_event_id, challenge_id, schema_version, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id, event.event_type.value, event.timestamp, event.actor,
                event.team_id, event.scenario_id, event.target_asset, event.vuln_id,
                event.phase.value if event.phase else None,
                event.trace_id, event.matched_event_id, event.challenge_id,
                event.schema_version, json.dumps(event.metadata),
            ),
        )
        is_new = cur.rowcount == 1   # OR IGNORE 로 충돌 무시 시 rowcount=0
        wrote = wrote or is_new
        results.append(is_new)
    if wrote:
        conn.commit()  # 배치당 커밋 1회 = 그룹 커밋
    return results


async def _batch_writer_loop():
    """ingest 큐를 소비해 그룹 커밋으로 흘리는 배치 라이터.

    첫 항목을 블로킹 대기한 뒤, 큐에 이미 쌓인 것들을 get_nowait 로 배치 상한까지 흡수한다.
    저부하: 큐가 비어 배치=1(지연 0). 고부하: writer 가 이전 배치를 commit 하는 동안 새
    이벤트가 큐에 쌓이므로 다음 배치가 커져 커밋 1회에 N건 → 처리량이 커밋 레이트에 묶이지
    않는다. 인위적 타이머 지연 없이 부하에 따라 배치 크기가 자기조정된다."""
    loop = asyncio.get_running_loop()
    queue = _get_ingest_queue()
    while True:
        first = await queue.get()
        batch = [first]
        while len(batch) < _INGEST_BATCH_MAX:
            try:
                batch.append(queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        events = [e for e, _ in batch]
        try:
            results = await loop.run_in_executor(_write_executor, _persist_batch, events)
        except Exception as exc:  # 커밋 실패 등 → 배치 전 요청에 예외 전파(부분성공 없음)
            for _, fut in batch:
                if not fut.done():
                    fut.set_exception(exc)
            continue
        _METRICS["ingest_batches"] += 1
        _METRICS["ingest_committed"] += sum(1 for r in results if r)
        _METRICS["ingest_batch_max_observed"] = max(
            _METRICS["ingest_batch_max_observed"], len(batch)
        )
        for (_, fut), is_new in zip(batch, results):
            if not fut.done():
                fut.set_result(is_new)


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
    # 감사 3.5: scoring 전달 실패용 로컬 스풀(DLQ). scoring_engine이 죽어도 이벤트를 잃지 않고
    # 복구되면 재전달한다.
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scoring_dlq (
            event_id TEXT PRIMARY KEY,
            payload TEXT,
            attempts INTEGER DEFAULT 0,
            last_error TEXT,
            created_at REAL DEFAULT (strftime('%s','now'))
        )
        """
    )
    conn.commit()
    conn.close()


# 감사 3.5: 전달 신뢰성 메트릭(예외 삼킴 대신 계측). /metrics로 노출.
_METRICS = {
    "forwarded_ok": 0,       # scoring 즉시 전달 성공
    "forward_retries": 0,    # 즉시 전달 재시도 횟수
    "dlq_spooled": 0,        # 즉시 전달 최종 실패 → DLQ 적재
    "dlq_redelivered": 0,    # DLQ에서 재전달 성공
    "dlq_drop": 0,           # (예약) 영구 실패로 폐기
    "ingest_batches": 0,          # 그룹 커밋 배치 수(=커밋 횟수)
    "ingest_committed": 0,        # 배치로 신규 저장된 이벤트 수
    "ingest_batch_max_observed": 0,  # 관측된 최대 배치 크기(그룹 커밋 효과 지표)
}
_FORWARD_ATTEMPTS = int(os.environ.get("SCORING_FORWARD_ATTEMPTS", "3"))
_DLQ_DRAIN_INTERVAL = float(os.environ.get("SCORING_DLQ_DRAIN_SEC", "10"))
# 감사 4.8: events.db 보존 정책 — 오래된 이벤트를 주기적으로 정리(무한 증가 방지). 0이면 비활성.
_EVENTS_RETENTION_DAYS = float(os.environ.get("EVENTS_RETENTION_DAYS", "0"))


def _prune_old_events() -> int:
    if _EVENTS_RETENTION_DAYS <= 0:
        return 0
    cutoff = time.time() - _EVENTS_RETENTION_DAYS * 86400
    conn = get_db()
    try:
        cur = conn.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
        conn.commit()
        return cur.rowcount or 0
    finally:
        conn.close()


init_db()


_background_tasks: "list[asyncio.Task]" = []


@on_startup(app)
async def startup():
    # 그룹 커밋 배치 라이터 기동(ingest 큐 소비 → 배치 커밋).
    _background_tasks.append(asyncio.create_task(_batch_writer_loop()))
    # 감사 3.5: DLQ 드레인 루프 기동(scoring 복구 시 스풀 이벤트 재전달).
    _background_tasks.append(asyncio.create_task(_dlq_drain_loop()))


@on_shutdown(app)
async def shutdown():
    # 무한 루프 백그라운드 태스크 + 진행 중 포워딩 태스크를 취소해 lifespan 종료가 매달리지
    # 않게 한다(미취소 시 컨테이너 stop 이 graceful timeout→SIGKILL 까지 지연).
    pending = list(_background_tasks) + list(_forward_tasks)
    for task in pending:
        task.cancel()
    for task in pending:
        try:
            await task
        except BaseException:  # CancelledError 포함 — 취소 정리 중 예외는 무시
            pass
    _background_tasks.clear()
    # 공유 httpx 클라이언트(연결 풀)를 닫는다 — 미닫으면 종료가 지연된다.
    global _scoring_client
    if _scoring_client is not None:
        try:
            await _scoring_client.aclose()
        except Exception:
            pass
        _scoring_client = None


@app.get("/metrics")
def metrics():
    """감사 3.5: 이벤트 전달 신뢰성 지표. 드롭/스풀/재전달 카운터 + DLQ 잔량."""
    conn = get_db()
    try:
        pending = conn.execute("SELECT COUNT(*) FROM scoring_dlq").fetchone()[0]
    except Exception:
        pending = None
    conn.close()
    return {"service": "event_collector", **_METRICS, "dlq_pending": pending}


@app.get("/health")
def health():
    return {"status": "ok", "service": "event_collector"}


@app.post("/events")
async def ingest_event(event: Event, authorization: str = Header(default="")):
    # 감사 3.1: 내부 S2S(트윈·서비스) 전용. 무토큰 주입 차단(참가자망서 이벤트 위조 방지).
    require_service_token(authorization)
    # 쓰기를 배치 라이터 큐로 넘긴다 → 이벤트 루프는 블록되지 않고, 자기 이벤트가 포함된
    # 배치가 commit 되면 future 로 stored 결과를 받는다(그룹 커밋으로 ≥600 EPS 병목 해소).
    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()
    await _get_ingest_queue().put((event, fut))
    is_new = await fut
    is_duplicate = not is_new

    # Dashboard 실시간 스트림으로 브로드캐스트 (중복이어도 UI 갱신은 상관없음)
    await _broadcast(event)
    # SSE 허브 발행(P0-4). 관전자 지연 필터는 구독측 visible_to 가 timestamp 로 처리.
    payload = event.model_dump(mode="json")
    payload.setdefault("match_id", event.metadata.get("match_id", "") if event.metadata else "")
    bus.publish(_topic_for(event), payload)

    # Scoring Engine에 전달 (신규 이벤트일 때만; 실패해도 이벤트 저장은 이미 완료됨)
    if not is_duplicate:
        task = asyncio.create_task(_forward_to_scoring_engine(event))
        _forward_tasks.add(task)               # 종료 시 취소할 수 있게 추적
        task.add_done_callback(_forward_tasks.discard)

    return {"stored": not is_duplicate, "duplicate": is_duplicate, "event_id": event.event_id}


def _lookup_matched_timestamp(matched_event_id: str) -> Optional[float]:
    """matched_event_id(원 공격 이벤트)의 timestamp를 조회. dwell time(04번 3절) 계산용."""
    conn = get_db()
    row = conn.execute("SELECT timestamp FROM events WHERE event_id = ?", (matched_event_id,)).fetchone()
    conn.close()
    return row["timestamp"] if row else None


# scoring 포워딩 최적화(U-3 100 EPS 절벽 해소): ① 호출마다 httpx.AsyncClient를 새로 만들면
# 연결 처닝·fd 고갈이 난다 → 연결 풀을 갖춘 공유 클라이언트를 재사용. ② fire-and-forget
# 포워딩이 scoring 지연 시 무제한 누적되지 않도록 세마포어로 동시성을 제한(초과분은 대기).
_scoring_client: Optional[httpx.AsyncClient] = None
_forward_sem = asyncio.Semaphore(int(os.environ.get("FORWARD_MAX_CONCURRENCY", "64")))
# fire-and-forget 포워딩 태스크를 추적해 종료 시 취소한다(미취소·미닫힌 httpx 클라이언트가
# lifespan 종료를 지연시켜 컨테이너 stop 이 매달리는 것을 막는다).
_forward_tasks: "set[asyncio.Task]" = set()


def _get_scoring_client() -> httpx.AsyncClient:
    global _scoring_client
    if _scoring_client is None:
        _scoring_client = httpx.AsyncClient(
            timeout=2.0,
            limits=httpx.Limits(max_connections=64, max_keepalive_connections=32),
        )
    return _scoring_client


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
    # 감사 3.5: 재시도 후에도 실패하면 예외를 삼키지 않고 DLQ에 스풀한다(무손실).
    async with _forward_sem:   # 동시 포워딩 상한(scoring 지연 시 무제한 태스크 누적 방지)
        ok, err = await _try_forward_once_with_retries(payload, event)
    if not ok:
        _spool_to_dlq(event.event_id, payload, err)


async def _post_scoring(payload: dict) -> tuple[bool, Optional[str]]:
    """scoring /score/ingest 1회 전송. (성공?, 오류문자열) 반환. 200이고 awarded면 scores push."""
    try:
        client = _get_scoring_client()  # 공유 커넥션 풀 재사용(호출마다 새 클라이언트 금지)
        r = await client.post(f"{SCORING_ENGINE_URL}/score/ingest", json=payload,
                              headers=service_headers())  # 감사 3.1: S2S 토큰
        if r.status_code == 200:
            res = r.json()
            if res.get("awarded"):
                bus.publish("scores", {
                    "team_id": payload.get("team_id"), "actor": payload.get("actor"),
                    "category": res.get("category"), "points": res.get("points"),
                    "scenario_id": payload.get("scenario_id"),
                    "match_id": (payload.get("metadata") or {}).get("match_id", ""),
                    "timestamp": time.time(),
                })
            return True, None
        return False, f"HTTP {r.status_code}"
    except httpx.HTTPError as e:
        return False, type(e).__name__


async def _try_forward_once_with_retries(payload: dict, event=None) -> tuple[bool, Optional[str]]:
    last_err = None
    for attempt in range(_FORWARD_ATTEMPTS):
        ok, err = await _post_scoring(payload)
        if ok:
            _METRICS["forwarded_ok"] += 1
            return True, None
        last_err = err
        _METRICS["forward_retries"] += 1
        await asyncio.sleep(min(0.2 * (2 ** attempt), 1.0))  # 지수 백오프(상한 1s)
    return False, last_err


def _spool_to_dlq(event_id: str, payload: dict, err: Optional[str]) -> None:
    conn = get_db()
    conn.execute(
        "INSERT INTO scoring_dlq (event_id, payload, attempts, last_error) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(event_id) DO UPDATE SET attempts=attempts+1, last_error=excluded.last_error",
        (event_id, json.dumps(payload), _FORWARD_ATTEMPTS, err or "unknown"),
    )
    conn.commit(); conn.close()
    _METRICS["dlq_spooled"] += 1


async def _dlq_drain_loop():
    """감사 3.5: 주기적으로 DLQ를 재전달. scoring_engine 복구 시 스풀된 이벤트를 0건 유실로 흘려보낸다."""
    while True:
        await asyncio.sleep(_DLQ_DRAIN_INTERVAL)
        try:
            _prune_old_events()  # 감사 4.8: events.db 보존 정책 적용
            conn = get_db()
            rows = conn.execute(
                "SELECT event_id, payload FROM scoring_dlq ORDER BY created_at ASC LIMIT 100"
            ).fetchall()
            conn.close()
            for row in rows:
                ok, _ = await _post_scoring(json.loads(row["payload"]))
                if ok:
                    conn = get_db()
                    conn.execute("DELETE FROM scoring_dlq WHERE event_id=?", (row["event_id"],))
                    conn.commit(); conn.close()
                    _METRICS["dlq_redelivered"] += 1
        except Exception:
            # 드레인 루프는 절대 죽지 않는다(다음 주기에 재시도).
            pass


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


@app.get("/events/delayed")
def list_events_delayed(delay_sec: float = 30.0, limit: int = 100,
                        scenario_id: Optional[str] = None):
    """관전자용 지연 이벤트 스트림(P3) — 최소 delay_sec 만큼 지난 이벤트만 노출한다.
    관전자가 실시간 정보를 팀에 흘리지 못하게(공개정보 지연 표시). scenario_id로 매치 스코프 가능."""
    import time as _t
    cutoff = _t.time() - max(0.0, delay_sec)
    conn = get_db()
    query = "SELECT * FROM events WHERE timestamp <= ?"
    params: list = [cutoff]
    if scenario_id:
        query += " AND scenario_id = ?"
        params.append(scenario_id)
    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = [dict(r) for r in conn.execute(query, params).fetchall()]
    conn.close()
    return {"events": rows, "delay_sec": delay_sec}


@app.get("/replay/events")
def replay_events(scenario_id: str = "default", time_from: Optional[float] = None,
                  time_to: Optional[float] = None, team_id: Optional[str] = None,
                  limit: Optional[int] = None):
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
    # Optional bounded history for command clients. Existing unbounded contract remains.
    truncated = False
    if limit is not None:
        limit = max(1, min(limit, 50000))
        query += " ORDER BY timestamp DESC, event_id DESC LIMIT ?"
        params.append(limit + 1)
    else:
        query += " ORDER BY timestamp ASC, event_id ASC"
    rows = [dict(r) for r in conn.execute(query, params).fetchall()]
    conn.close()
    if limit is not None:
        truncated = len(rows) > limit
        rows = list(reversed(rows[:limit]))
    return {"scenario_id": scenario_id, "count": len(rows), "events": rows, "truncated": truncated}


@app.websocket("/ws")
async def event_stream(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()  # 클라이언트로부터의 ping 등 무시
    except WebSocketDisconnect:
        _ws_clients.discard(websocket)




def _sse_frame(m) -> str:
    return f"id: {m.id}\nevent: {m.topic}\ndata: {json.dumps(m.data)}\n\n"


@app.get("/stream")
async def stream(request: Request, topics: str = "", last_event_id: str = "",
                 authorization: str = Header(default=""),
                 cr_token: str | None = Cookie(default=None),
                 last_event_id_hdr: str = Header(default="", alias="Last-Event-ID")):
    """상황판 실시간 구독(P0-4, SSE). 폴링을 대체한다.
    - topics: 콤마 목록(events,detections,scores,safety,phase_clock). 비면 전체.
    - Last-Event-ID(헤더 또는 쿼리): 재연결 시 놓친 메시지 리플레이.
    - 역할·매치·관전자 지연은 visible_to 로 필터."""
    role, match_id = _claims_from(authorization, cr_token)
    tset = {t.strip() for t in topics.split(",") if t.strip()} or None
    try:
        last_id = int(last_event_id_hdr or last_event_id or 0)
    except ValueError:
        last_id = 0

    async def gen():
        yield "retry: 3000\n\n"   # EventSource 자동 재연결 간격(ms)
        now = time.time()
        # 1) 리플레이(놓친 이벤트)
        for m in bus.replay(last_id, tset):
            if visible_to(m, role, match_id, now, OBSERVER_DELAY_SEC):
                yield _sse_frame(m)
        yield f": subscribed role={role} topics={sorted(tset) if tset else 'all'}\n\n"
        # 2) 라이브 구독
        with bus.subscription(maxsize=1000) as q:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    m = await asyncio.wait_for(q.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"   # 하트비트(프록시 타임아웃·재연결 방지)
                    continue
                if tset is not None and m.topic not in tset:
                    continue
                if visible_to(m, role, match_id, time.time(), OBSERVER_DELAY_SEC):
                    yield _sse_frame(m)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/internal/publish")
async def internal_publish(request: Request, authorization: str = Header(default="")):
    """S2S 발행(safety/phase_clock 등). range_control·scenario_engine 이 상황판에 밀어넣는 통로."""
    require_role(authorization, {"instructor"})
    body = await request.json()
    topic = body.get("topic", "events")
    data = body.get("data", {})
    data.setdefault("timestamp", time.time())
    seq = bus.publish(topic, data)
    return {"published": seq, "topic": topic, "subscribers": bus.subscribers}


@app.post("/admin/reset")
def admin_reset(authorization: str = Header(default="")):
    """훈련 초기화 — event_collector 상태를 비운다(instructor 인증). range_control이 오케스트레이션."""
    require_role(authorization, {"instructor"})
    conn = get_db()
    cleared = {}
    for t in ['events']:
        try:
            cleared[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
            conn.execute(f"DELETE FROM {t}")
        except Exception:
            cleared[t] = "n/a"
    conn.commit(); conn.close()
    return {"service": "event_collector", "cleared": cleared}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8010)
