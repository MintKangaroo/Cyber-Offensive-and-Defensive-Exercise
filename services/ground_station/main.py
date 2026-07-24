"""
Ground Station Digital Twin (위성 지상국 디지털 트윈)
------------------------------------------------------
Live Fire Cyber Range 훈련용 모의 서비스. 실제 위성/지상국 시스템이 아니며
모든 데이터는 더미(dummy)입니다.

취약점 목록(shared/vuln_catalog.json 의 ground_station 항목과 대응):
  GS-001 SQL Injection            (/api/telemetry)
  GS-002 Hardcoded Creds/Weak JWT (/api/login)
  GS-003 IDOR                     (/api/mission-plan/{id})
  GS-004 Path Traversal           (/api/download)
  GS-005 Debug Config Exposure    (/api/debug/config)

각 취약점은 환경변수 PATCH_GS_00X=true 로 개별 패치(비활성화) 가능하며,
Patch Verification Manager의 safe probe가 이 상태를 판정합니다.
"""

import os
import sqlite3
import base64
import pickle
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt  # PyJWT

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))  # repo root (shared/ 위치)
from shared.event_client import emit_event  # noqa: E402
from shared.event_schema import Event, EventType, RedPhase  # noqa: E402
from shared.config_client import ConfigClient  # noqa: E402
from shared.edr_agent import start_edr_agent  # noqa: E402
from shared.siem_access_log import make_siem_access_middleware  # noqa: E402

GS_ROUTE_VULN_MAP = {
    "/api/telemetry": "GS-001",
    "/api/login": "GS-002",
    "/api/mission-plan": "GS-003",
    "/api/download": "GS-004",
    "/api/debug/config": "GS-005",
}

ASSET_NAME = "ground_station"

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "ground_station.db"
FILES_DIR = APP_DIR / "files"
FILES_DIR.mkdir(exist_ok=True)

# --- 패치 상태: Config Service 폴링(무중단 토글) + 환경변수 폴백(부팅 직후/Config Service 다운 시) ---
_config = ConfigClient(asset=ASSET_NAME)


def _flag_key_to_vuln_id(flag_key: str) -> str:
    """'PATCH_GS_001' -> 'GS-001' (Config Service의 vuln_id 표기와 맞춤)."""
    rest = flag_key.removeprefix("PATCH_")
    return rest.replace("_", "-", 1)


def patched(flag_key: str) -> bool:
    vuln_id = _flag_key_to_vuln_id(flag_key)
    return _config.is_patched(vuln_id, env_fallback_key=flag_key)


JWT_SECRET = "supersecret123"  # GS-002: 훈련용 취약 시크릿 (패치 시 os.urandom 기반으로 교체 필요)

app = FastAPI(title="Ground Station Digital Twin (TRAINING ONLY)")


@app.on_event("startup")
async def _start_edr_agent():
    start_edr_agent(asset_name=ASSET_NAME)


@app.middleware("http")
async def quarantine_and_killswitch_guard(request: Request, call_next):
    """EDR 콘솔의 '호스트 격리' 또는 교관의 킬스위치가 활성화되면 /health를 제외한
    모든 요청을 503으로 차단한다(호스트 격리/훈련 강제정지 시뮬레이션)."""
    if request.url.path != "/health":
        if _config.is_killswitch_active():
            return JSONResponse(status_code=503, content={"detail": "training halted by instructor killswitch"})
        if _config.is_quarantined():
            return JSONResponse(status_code=503, content={"detail": f"{ASSET_NAME} is quarantined by EDR console"})
    return await call_next(request)


app.middleware("http")(make_siem_access_middleware(ASSET_NAME, GS_ROUTE_VULN_MAP))


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY,
            sensor_id TEXT,
            value REAL,
            ts INTEGER
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        );
        CREATE TABLE IF NOT EXISTS mission_plans (
            id INTEGER PRIMARY KEY,
            owner TEXT,
            title TEXT,
            classified_flag TEXT
        );
        """
    )
    conn.execute("DELETE FROM telemetry")
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM mission_plans")
    conn.executemany(
        "INSERT INTO telemetry (sensor_id, value, ts) VALUES (?, ?, ?)",
        [("SOL-PANEL-1", 87.3, int(time.time())),
         ("SOL-PANEL-2", 91.1, int(time.time())),
         ("GYRO-X", 0.002, int(time.time()))],
    )
    conn.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [("admin", "admin123", "admin"),          # GS-002 더미 하드코딩 계정
         ("operator1", "Op3rat0r!2024", "operator")],
    )
    conn.executemany(
        "INSERT INTO mission_plans (owner, title, classified_flag) VALUES (?, ?, ?)",
        [("operator1", "KMS-1 재진입 궤도 조정", "mission_plan.flag{dummy-orbit-adjust}"),
         ("admin", "지상국 백업 안테나 전환 계획", "mission_plan.flag{dummy-antenna-switch}")],
    )
    conn.commit()
    conn.close()

    # GS-004 path traversal 시연용 더미 파일
    (FILES_DIR / "telemetry_report.txt").write_text("2026-07-10 telemetry nominal\n")
    secret_dir = APP_DIR / "secret"
    secret_dir.mkdir(exist_ok=True)
    (secret_dir / "satellite_key_dummy.txt").write_text("DUMMY_PRIVATE_KEY_NOT_REAL_0xFA23...\n")


init_db()


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/health")
def health():
    return {"status": "ok", "service": "ground_station"}


# ---------------------------------------------------------------------------
# GS-001: SQL Injection
# ---------------------------------------------------------------------------
@app.get("/api/telemetry")
def get_telemetry(sensor_id: str = Query(...), x_team_id: str = Header(default="default")):
    conn = get_db()
    if patched("PATCH_GS_001"):
        cur = conn.execute(
            "SELECT id, sensor_id, value, ts FROM telemetry WHERE sensor_id = ?",
            (sensor_id,),
        )
    else:
        # 취약 지점: 문자열 결합 쿼리 (훈련 목적, 실제 프로덕션에 절대 사용 금지)
        query = f"SELECT id, sensor_id, value, ts FROM telemetry WHERE sensor_id = '{sensor_id}'"
        try:
            cur = conn.execute(query)
        except sqlite3.OperationalError as e:
            conn.close()
            raise HTTPException(400, f"query error: {e}")
        if "'" in sensor_id or "union" in sensor_id.lower():
            emit_event(
                event_id=Event.make_id(x_team_id, ASSET_NAME, "GS-001", str(time.time())),
                event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
                vuln_id="GS-001", phase=RedPhase.initial_access, team_id=x_team_id,
                trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
                metadata={"sensor_id_input": sensor_id},
            )
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"patched": patched("PATCH_GS_001"), "results": rows}


# ---------------------------------------------------------------------------
# GS-002: Hardcoded Credentials / Weak JWT
# ---------------------------------------------------------------------------
@app.post("/api/login")
def login(req: LoginRequest, x_team_id: str = Header(default="default")):
    conn = get_db()
    if patched("PATCH_GS_002"):
        # 패치 후: 기본 계정 제거 + 강한 랜덤 시크릿 사용 가정
        cur = conn.execute(
            "SELECT * FROM users WHERE username=? AND password=? AND username != 'admin'",
            (req.username, req.password),
        )
    else:
        cur = conn.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (req.username, req.password),
        )
    user = cur.fetchone()
    conn.close()
    if not user:
        raise HTTPException(401, "invalid credentials")
    if not patched("PATCH_GS_002") and req.username == "admin":
        emit_event(
            event_id=Event.make_id(x_team_id, ASSET_NAME, "GS-002", str(time.time())),
            event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
            vuln_id="GS-002", phase=RedPhase.initial_access, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
            challenge_id="WEB-002",   # crossover 시나리오/레퍼런스 문제 연동
            metadata={"username": req.username},
        )
    secret = os.environ.get("GS_JWT_SECRET", JWT_SECRET) if patched("PATCH_GS_002") else JWT_SECRET
    token = jwt.encode({"sub": user["username"], "role": user["role"], "exp": int(time.time()) + 3600}, secret, algorithm="HS256")
    return {"token": token, "patched": patched("PATCH_GS_002")}


# ---------------------------------------------------------------------------
# GS-003: IDOR
# ---------------------------------------------------------------------------
@app.get("/api/mission-plan/{plan_id}")
def get_mission_plan(plan_id: int, authorization: str = Header(default=""), x_team_id: str = Header(default="default")):
    conn = get_db()
    cur = conn.execute("SELECT * FROM mission_plans WHERE id=?", (plan_id,))
    plan = cur.fetchone()
    conn.close()
    if not plan:
        raise HTTPException(404, "not found")

    if patched("PATCH_GS_003"):
        # 패치 후: 토큰의 sub == owner 검증
        try:
            token = authorization.replace("Bearer ", "")
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except Exception:
            raise HTTPException(401, "unauthorized")
        if payload["sub"] != plan["owner"] and payload["role"] != "admin":
            raise HTTPException(403, "forbidden: not owner")
    else:
        # IDOR: 소유권 검증 없이 통과 -> 기밀 임무계획(flag) 획득으로 간주
        emit_event(
            event_id=Event.make_id(x_team_id, ASSET_NAME, "GS-003", str(plan_id)),
            event_type=EventType.flag_exfiltrated, actor="red", target_asset=ASSET_NAME,
            vuln_id="GS-003", phase=RedPhase.data_exfiltration, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
            metadata={"plan_id": plan_id, "flag": plan["classified_flag"]},
        )

    return {"patched": patched("PATCH_GS_003"), "plan": dict(plan)}


# ---------------------------------------------------------------------------
# GS-004: Path Traversal
# ---------------------------------------------------------------------------
@app.get("/api/download")
def download_file(file: str = Query(...), x_team_id: str = Header(default="default")):
    if patched("PATCH_GS_004"):
        # 패치 후: 파일명만 허용, 경로 구분자 차단 + base dir 고정
        safe_name = os.path.basename(file)
        target = (FILES_DIR / safe_name).resolve()
        if not str(target).startswith(str(FILES_DIR.resolve())):
            raise HTTPException(400, "invalid file")
    else:
        # 취약 지점: 사용자 입력을 그대로 경로에 결합
        target = (FILES_DIR / file).resolve()
        if ".." in file:
            emit_event(
                event_id=Event.make_id(x_team_id, ASSET_NAME, "GS-004", file),
                event_type=EventType.flag_exfiltrated, actor="red", target_asset=ASSET_NAME,
                vuln_id="GS-004", phase=RedPhase.data_exfiltration, team_id=x_team_id,
                trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
                metadata={"requested_path": file},
            )

    if not target.exists() or not target.is_file():
        raise HTTPException(404, "file not found")
    return {"patched": patched("PATCH_GS_004"), "path": str(target), "content": target.read_text(errors="replace")}


# ---------------------------------------------------------------------------
# GS-005: Debug Config Exposure
# ---------------------------------------------------------------------------
@app.get("/api/debug/config")
def debug_config(x_team_id: str = Header(default="default")):
    if patched("PATCH_GS_005"):
        raise HTTPException(404, "not found")  # 패치 후: 라우트 자체가 비활성화된 것처럼 동작
    emit_event(
        event_id=Event.make_id(x_team_id, ASSET_NAME, "GS-005", str(time.time())),
        event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
        vuln_id="GS-005", phase=RedPhase.privilege_escalation, team_id=x_team_id,
        trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
        metadata={"exposed": ["env", "jwt_secret"]},
    )
    return {
        "patched": False,
        "env": dict(os.environ),
        "jwt_secret": JWT_SECRET,
        "db_path": str(DB_PATH),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
