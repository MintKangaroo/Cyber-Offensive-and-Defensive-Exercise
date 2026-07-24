"""
EDR Backend (Falcon의 'Cloud Console'에 대응)
================================================
에이전트 텔레메트리 수신 -> diff로 프로세스 시작/종료 감지 -> 행위기반 IOC 탐지 ->
알림 생성. Isolate Host는 Config Service의 quarantine 엔드포인트를 호출.

실행: uvicorn services.edr.api.main:app --port 8080
"""
from __future__ import annotations
import os
import re
import sys
import time
import sqlite3
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from starlette.websockets import WebSocketState
from pydantic import BaseModel
import httpx

# shared.rbac 임포트를 위해 /app(리포 루트)을 경로에 추가(WORKDIR가 서비스 api 디렉토리라서 필요).
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from shared.rbac import require_role, require_read  # noqa: E402

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "edr.db"
CONFIG_SERVICE_URL = os.environ.get("CONFIG_SERVICE_URL", "http://config_service:8030")
INSTRUCTOR_TOKEN = os.environ.get("INSTRUCTOR_TOKEN", "")
STALE_HOST_SEC = 30   # 이 시간 이상 스냅샷이 없으면 offline 처리

app = FastAPI(title="EDR Backend")

# EDR 콘솔(Vite dev, 기본 localhost:5173)이 브라우저에서 직접 이 API로 fetch 하려면
# CORS가 필요하다. 없으면 브라우저가 preflight/응답을 차단해 호스트/알림/프로세스 트리가
# 안 뜨고 Isolate/Kill 버튼도 무동작. 로컬 개발/훈련 범위라 localhost 전 포트 허용.
app.add_middleware(
    CORSMiddleware, allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

_ws_clients: set[WebSocket] = set()

# 주의: 예전에는 프로세스 '이름'(uvicorn/python3)으로 보호 대상을 판별했으나,
# 공격자가 "python3 -c '<reverse shell>'" 형태로 악성 프로세스를 띄우면 이름이 똑같아서
# kill이 막히는 결함이 있었다(20번 문서 5절의 의도를 무력화). 그래서 이제는 각 호스트의
# '진짜 서버 프로세스 pid'를 에이전트가 직접 보고하게 하고(hosts.server_pid), 그 pid만
# 절대 보호한다. 이름 기반 체크는 참고용 2차 방어로만 남긴다.
PROTECTED_PROCESS_NAMES = {"uvicorn", "python", "python3", "gunicorn"}  # 2차 방어(경고용), 1차는 server_pid


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS hosts (
            asset TEXT PRIMARY KEY, last_seen REAL, process_count INTEGER, server_pid INTEGER
        );
        CREATE TABLE IF NOT EXISTS processes_current (
            asset TEXT, pid INTEGER, ppid INTEGER, name TEXT, cmdline TEXT,
            create_time REAL, username TEXT, connections TEXT,
            PRIMARY KEY (asset, pid)
        );
        CREATE TABLE IF NOT EXISTS process_events (
            id TEXT PRIMARY KEY, asset TEXT, pid INTEGER, ppid INTEGER, name TEXT,
            cmdline TEXT, event_type TEXT, timestamp REAL
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY, asset TEXT, rule_id TEXT, rule_name TEXT,
            severity TEXT, pid INTEGER, cmdline TEXT, timestamp REAL, detail TEXT
        );
        CREATE TABLE IF NOT EXISTS flagged_pids (
            asset TEXT, pid INTEGER, reason TEXT, flagged_at REAL,
            PRIMARY KEY (asset, pid)
        );
        CREATE TABLE IF NOT EXISTS kill_commands (
            id TEXT PRIMARY KEY, asset TEXT, pid INTEGER, reason TEXT,
            status TEXT,               -- pending | done | failed | rejected
            requested_at REAL, completed_at REAL, result_detail TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            audit_id TEXT PRIMARY KEY, timestamp REAL, actor TEXT,
            action TEXT, target TEXT, reason TEXT
        );
        """
    )
    # 기존 DB(server_pid 컬럼 없던 버전)에도 무중단 마이그레이션
    try:
        conn.execute("ALTER TABLE hosts ADD COLUMN server_pid INTEGER")
    except sqlite3.OperationalError:
        pass
    conn.commit()
    conn.close()


init_db()


# ---------------------------------------------------------------------------
# 탐지 규칙 (20번 문서 4.2절)
# ---------------------------------------------------------------------------

SUSPICIOUS_SHELL_NAMES = {"sh", "bash", "nc", "ncat", "netcat", "dash"}
WEB_SERVER_NAMES = {"uvicorn", "python", "python3", "gunicorn"}
REVERSE_SHELL_PATTERNS = [
    re.compile(r"bash\s+-i"), re.compile(r"/dev/tcp/"), re.compile(r"nc\s+-e"),
    re.compile(r"python[23]?\s+-c.*socket"), re.compile(r"0<&\d+.*1>&\d+"),
]
EGRESS_ALLOWLIST_PORTS = {8010, 8020, 8030, 8060, 8080}  # event_collector/scoring/config/patch/edr


def _evaluate_rules(asset: str, proc: dict, parent_name: Optional[str]) -> list[dict]:
    alerts = []
    name = (proc.get("name") or "").lower()
    cmdline = proc.get("cmdline") or ""

    # EDR-001: 웹서버 프로세스가 쉘류 자식 프로세스 생성
    if parent_name and parent_name.lower() in WEB_SERVER_NAMES and name in SUSPICIOUS_SHELL_NAMES:
        alerts.append({
            "rule_id": "EDR-001", "rule_name": "Web server spawning shell",
            "severity": "critical", "detail": f"parent={parent_name} child={name} cmdline={cmdline}",
        })

    # EDR-002: 리버스쉘 유사 커맨드라인 패턴
    for pattern in REVERSE_SHELL_PATTERNS:
        if pattern.search(cmdline):
            alerts.append({
                "rule_id": "EDR-002", "rule_name": "Suspicious reverse-shell-like command line",
                "severity": "critical", "detail": f"cmdline={cmdline} matched={pattern.pattern}",
            })
            break

    # EDR-003: allowlist 밖 outbound 연결
    for conn in proc.get("connections", []):
        raddr = conn.get("raddr")
        if raddr and conn.get("status") == "ESTABLISHED":
            try:
                port = int(raddr.split(":")[-1])
            except ValueError:
                continue
            if port not in EGRESS_ALLOWLIST_PORTS and port not in (80, 443):
                alerts.append({
                    "rule_id": "EDR-003", "rule_name": "Unexpected outbound connection",
                    "severity": "high", "detail": f"pid={proc['pid']} name={name} raddr={raddr}",
                })

    return alerts


# ---------------------------------------------------------------------------
# 텔레메트리 수신
# ---------------------------------------------------------------------------

class ProcessInfo(BaseModel):
    pid: int
    ppid: int
    name: str
    cmdline: str
    create_time: float
    username: Optional[str] = None
    connections: list[dict] = []


class SnapshotIngest(BaseModel):
    asset: str
    timestamp: float
    server_pid: Optional[int] = None   # 에이전트가 자기 자신(os.getpid())을 보고 -> 유일한 kill 보호대상
    processes: list[ProcessInfo]


@app.get("/health")
def health():
    return {"status": "ok", "service": "edr_backend"}


@app.post("/edr/ingest")
async def ingest(snapshot: SnapshotIngest):
    conn = get_db()

    prev_pids = {
        r["pid"]: dict(r) for r in
        conn.execute("SELECT * FROM processes_current WHERE asset=?", (snapshot.asset,)).fetchall()
    }
    current_pids = {p.pid: p for p in snapshot.processes}
    name_by_pid = {p.pid: p.name for p in snapshot.processes}

    new_alerts = []

    # 신규 프로세스(process_started) + 규칙 평가
    for pid, proc in current_pids.items():
        if pid not in prev_pids:
            conn.execute(
                "INSERT INTO process_events (id, asset, pid, ppid, name, cmdline, event_type, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, 'process_started', ?)",
                (str(uuid.uuid4()), snapshot.asset, pid, proc.ppid, proc.name, proc.cmdline, snapshot.timestamp),
            )
            parent_name = name_by_pid.get(proc.ppid)
            for a in _evaluate_rules(snapshot.asset, proc.model_dump(), parent_name):
                alert_id = str(uuid.uuid4())
                conn.execute(
                    "INSERT INTO alerts (id, asset, rule_id, rule_name, severity, pid, cmdline, timestamp, detail) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (alert_id, snapshot.asset, a["rule_id"], a["rule_name"], a["severity"],
                     pid, proc.cmdline, snapshot.timestamp, a["detail"]),
                )
                # 알림이 뜬 프로세스는 kill 화이트리스트에 자동 등록(20번 문서 5절 - 임의 kill 금지, 탐지된 것만)
                conn.execute(
                    "INSERT OR REPLACE INTO flagged_pids (asset, pid, reason, flagged_at) VALUES (?, ?, ?, ?)",
                    (snapshot.asset, pid, a["rule_id"], snapshot.timestamp),
                )
                new_alerts.append({**a, "asset": snapshot.asset, "pid": pid, "id": alert_id})

    # 소멸된 프로세스(process_ended)
    for pid in prev_pids:
        if pid not in current_pids:
            prev = prev_pids[pid]
            conn.execute(
                "INSERT INTO process_events (id, asset, pid, ppid, name, cmdline, event_type, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?, 'process_ended', ?)",
                (str(uuid.uuid4()), snapshot.asset, pid, prev["ppid"], prev["name"], prev["cmdline"], snapshot.timestamp),
            )

    # 현재 스냅샷으로 갱신
    conn.execute("DELETE FROM processes_current WHERE asset=?", (snapshot.asset,))
    for p in snapshot.processes:
        conn.execute(
            "INSERT INTO processes_current (asset, pid, ppid, name, cmdline, create_time, username, connections) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (snapshot.asset, p.pid, p.ppid, p.name, p.cmdline, p.create_time, p.username, str(p.connections)),
        )
    conn.execute(
        "INSERT INTO hosts (asset, last_seen, process_count, server_pid) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(asset) DO UPDATE SET last_seen=excluded.last_seen, process_count=excluded.process_count, "
        "server_pid=COALESCE(excluded.server_pid, hosts.server_pid)",
        (snapshot.asset, snapshot.timestamp, len(snapshot.processes), snapshot.server_pid),
    )
    conn.commit()
    conn.close()

    for a in new_alerts:
        await _broadcast({"type": "alert", **a})

    return {"processed": len(snapshot.processes), "new_alerts": len(new_alerts)}


async def _broadcast(payload: dict) -> None:
    dead = set()
    for ws in _ws_clients:
        try:
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.send_json(payload)
        except Exception:
            dead.add(ws)
    _ws_clients.difference_update(dead)


# ---------------------------------------------------------------------------
# 조회 API
# ---------------------------------------------------------------------------

@app.get("/edr/hosts")
def list_hosts(authorization: str = Header(default="")):
    require_read(authorization)  # 관전자 read 게이트(OBSERVER_READ_ENFORCE 시 유효)
    conn = get_db()
    rows = conn.execute("SELECT * FROM hosts").fetchall()
    conn.close()
    now = time.time()
    result = []
    for r in rows:
        status = "online" if (now - r["last_seen"]) < STALE_HOST_SEC else "offline"
        result.append({"asset": r["asset"], "status": status, "last_seen": r["last_seen"],
                       "process_count": r["process_count"]})
    return {"hosts": result}


@app.get("/edr/hosts/{asset}/processes")
def get_processes(asset: str, authorization: str = Header(default="")):
    require_read(authorization)  # 관전자 read 게이트
    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM processes_current WHERE asset=?", (asset,)
    ).fetchall()]
    conn.close()
    # 부모-자식 트리 구성
    by_pid = {r["pid"]: {**r, "children": []} for r in rows}
    roots = []
    for r in rows:
        parent = by_pid.get(r["ppid"])
        if parent:
            parent["children"].append(by_pid[r["pid"]])
        else:
            roots.append(by_pid[r["pid"]])
    return {"asset": asset, "process_tree": roots}


@app.get("/edr/hosts/{asset}/timeline")
def get_timeline(asset: str, limit: int = 200, authorization: str = Header(default="")):
    require_read(authorization)  # 관전자 read 게이트
    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM process_events WHERE asset=? ORDER BY timestamp DESC LIMIT ?", (asset, limit)
    ).fetchall()]
    conn.close()
    return {"asset": asset, "events": rows}


@app.get("/edr/alerts")
def get_alerts(asset: Optional[str] = None, limit: int = 100, authorization: str = Header(default="")):
    require_read(authorization)  # 관전자 read 게이트
    conn = get_db()
    if asset:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM alerts WHERE asset=? ORDER BY timestamp DESC LIMIT ?", (asset, limit)
        ).fetchall()]
    else:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()]
    conn.close()
    return {"alerts": rows}


# ---------------------------------------------------------------------------
# 대응 액션 (Isolate / Kill) — 20번 문서 5·6절 안전장치 적용
# ---------------------------------------------------------------------------

class IsolateRequest(BaseModel):
    reason: str


class KillRequest(BaseModel):
    reason: str


def _audit(actor: str, action: str, target: str, reason: str) -> None:
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_log (audit_id, timestamp, actor, action, target, reason) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), time.time(), actor, action, target, reason),
    )
    conn.commit()
    conn.close()


@app.post("/edr/hosts/{asset}/isolate")
async def isolate_host(asset: str, req: IsolateRequest, authorization: str = Header(default="")):
    """Config Service의 quarantine을 호출(20번 문서 6절 - 새 메커니즘 만들지 않고 재사용).
    방어 액션이므로 instructor 또는 blue 역할만 허용(RBAC). 이전엔 헤더를 받고도 검증하지 않아
    누구나 호스트를 격리할 수 있는 갭이 있었다."""
    actor = require_role(authorization, {"instructor", "blue"}).actor
    if not req.reason.strip():
        raise HTTPException(400, "reason is required")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.post(
                f"{CONFIG_SERVICE_URL}/instructor/quarantine",
                json={"asset": asset, "quarantined": True, "reason": f"edr_console: {req.reason}"},
                headers={"Authorization": f"Bearer {INSTRUCTOR_TOKEN}"},
            )
            r.raise_for_status()
    except httpx.HTTPError as e:
        raise HTTPException(502, f"config_service call failed: {e}")
    _audit(actor, "isolate_host", asset, req.reason)
    return {"asset": asset, "isolated": True}


@app.post("/edr/hosts/{asset}/unisolate")
async def unisolate_host(asset: str, req: IsolateRequest, authorization: str = Header(default="")):
    actor = require_role(authorization, {"instructor", "blue"}).actor
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.post(
                f"{CONFIG_SERVICE_URL}/instructor/quarantine",
                json={"asset": asset, "quarantined": False, "reason": f"edr_console: {req.reason}"},
                headers={"Authorization": f"Bearer {INSTRUCTOR_TOKEN}"},
            )
            r.raise_for_status()
    except httpx.HTTPError as e:
        raise HTTPException(502, f"config_service call failed: {e}")
    _audit(actor, "unisolate_host", asset, req.reason)
    return {"asset": asset, "isolated": False}


@app.post("/edr/hosts/{asset}/process/{pid}/kill")
def kill_process(asset: str, pid: int, req: KillRequest, authorization: str = Header(default="")):
    """화이트리스트(자체 탐지로 flagged_pids에 등록된 pid)만 kill 허용.
    방어 액션이므로 instructor 또는 blue 역할만 허용(RBAC).
    1차 방어: hosts.server_pid(에이전트가 자기 자신을 보고한 pid)와 일치하면 무조건 거부
      -> 공격자가 'python3 -c 리버스쉘'처럼 서버와 같은 이름의 프로세스를 띄워도,
         진짜 서버 프로세스의 pid만 정확히 보호되므로 악성 프로세스는 정상적으로 kill 가능.
    2차 방어(참고용): 프로세스 이름이 PROTECTED_PROCESS_NAMES에 속하면 경고를 detail에 남김.
    실제 종료는 이 엔드포인트가 즉시 수행하지 않고 kill_commands 큐에 넣는다 - 종료 자체는
    해당 트윈 컨테이너 내부의 EDR Agent가 반드시 자기 프로세스 공간에서 os.kill()을 실행해야
    하므로(EDR Backend는 별도 프로세스라 트윈의 pid space에 직접 접근 불가), 에이전트가 이
    큐를 폴링해 실행하고 결과를 ack한다."""
    kill_actor = require_role(authorization, {"instructor", "blue"}).actor
    if not req.reason.strip():
        raise HTTPException(400, "reason is required")

    conn = get_db()
    flagged = conn.execute(
        "SELECT 1 FROM flagged_pids WHERE asset=? AND pid=?", (asset, pid)
    ).fetchone()
    proc = conn.execute(
        "SELECT name FROM processes_current WHERE asset=? AND pid=?", (asset, pid)
    ).fetchone()
    host = conn.execute("SELECT server_pid FROM hosts WHERE asset=?", (asset,)).fetchone()

    if not flagged:
        conn.close()
        raise HTTPException(400, f"pid {pid} is not a flagged/detected process; kill not permitted")

    if host and host["server_pid"] is not None and pid == host["server_pid"]:
        conn.close()
        raise HTTPException(403, f"pid {pid} is the protected server process for '{asset}'; cannot be killed")

    name_warning = None
    if proc and proc["name"].lower() in PROTECTED_PROCESS_NAMES:
        name_warning = (f"process name '{proc['name']}' matches a protected name pattern, but pid "
                        f"{pid} != server_pid({host['server_pid'] if host else None}); proceeding "
                        f"because this pid was independently flagged by detection rules")

    command_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO kill_commands (id, asset, pid, reason, status, requested_at, result_detail) "
        "VALUES (?, ?, ?, ?, 'pending', ?, ?)",
        (command_id, asset, pid, req.reason, time.time(), name_warning),
    )
    conn.commit()
    conn.close()

    _audit(kill_actor, "kill_process_requested", f"{asset}:{pid}", req.reason)
    return {"command_id": command_id, "asset": asset, "pid": pid, "status": "pending",
           "warning": name_warning}


@app.get("/edr/hosts/{asset}/kill-commands/pending")
def get_pending_kill_commands(asset: str):
    """EDR Agent(트윈 내부)가 주기적으로 폴링하는 엔드포인트. pending 상태만 반환."""
    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM kill_commands WHERE asset=? AND status='pending'", (asset,)
    ).fetchall()]
    conn.close()
    return {"commands": rows}


class KillAck(BaseModel):
    status: str          # done | failed
    result_detail: str = ""


@app.post("/edr/kill-commands/{command_id}/ack")
def ack_kill_command(command_id: str, ack: KillAck):
    """EDR Agent가 실제 os.kill() 실행 결과를 보고. status는 done(성공) 또는 failed."""
    if ack.status not in ("done", "failed"):
        raise HTTPException(400, "status must be 'done' or 'failed'")
    conn = get_db()
    row = conn.execute("SELECT asset, pid FROM kill_commands WHERE id=?", (command_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "command not found")
    conn.execute(
        "UPDATE kill_commands SET status=?, completed_at=?, result_detail=? WHERE id=?",
        (ack.status, time.time(), ack.result_detail, command_id),
    )
    conn.commit()
    conn.close()
    _audit("edr_agent", f"kill_process_{ack.status}", f"{row['asset']}:{row['pid']}", ack.result_detail)
    return {"command_id": command_id, "status": ack.status}


@app.get("/edr/hosts/{asset}/kill-commands")
def list_kill_commands(asset: str, limit: int = 50):
    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM kill_commands WHERE asset=? ORDER BY requested_at DESC LIMIT ?", (asset, limit)
    ).fetchall()]
    conn.close()
    return {"asset": asset, "commands": rows}


@app.get("/edr/audit")
def get_audit(limit: int = 200, authorization: str = Header(default="")):
    require_read(authorization)  # 관전자 read 게이트
    conn = get_db()
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()]
    conn.close()
    return {"entries": rows}


@app.websocket("/edr/ws")
async def edr_stream(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _ws_clients.discard(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
