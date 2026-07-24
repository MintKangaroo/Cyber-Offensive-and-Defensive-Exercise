"""
Power Plant / SCADA Digital Twin (발전소·SCADA 디지털 트윈)
------------------------------------------------------------
Live Fire Cyber Range 훈련용 모의 서비스. 실제 SCADA/PLC 시스템이 아니며
모든 제어값은 시뮬레이션 상의 더미 레지스터입니다. 실제 산업제어 장비와
연결되지 않습니다.

취약점 목록(shared/vuln_catalog.json 의 power_plant 항목과 대응):
  PP-001 Unauthenticated PLC Write     (/api/plc/write)
  PP-002 Default HMI Credentials       (/api/hmi/login)
  PP-003 Diagnostics Command Injection (/api/diagnostics/ping)
  PP-004 Insecure Deserialization      (/api/historian/export)
  PP-005 Safety Override Bypass        (/api/safety/override)
  PP-006 Unauthorized Modbus Write     (/api/modbus/write-register) — 보호 레지스터 미인가 쓰기(ICS)
  PP-007 Unsigned Firmware Update       (/api/plc/firmware-update)   — 서명 검증 없는 펌웨어 설치
"""

import os
import base64
import pickle
import ipaddress
import subprocess
import shlex
import time
from pathlib import Path
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))  # repo root (shared/ 위치)
from shared.event_client import emit_event  # noqa: E402
from shared.event_schema import Event, EventType, RedPhase  # noqa: E402
from shared.config_client import ConfigClient  # noqa: E402
from shared.edr_agent import start_edr_agent  # noqa: E402
from shared.siem_access_log import make_siem_access_middleware  # noqa: E402

PP_ROUTE_VULN_MAP = {
    "/api/plc/write": "PP-001",
    "/api/hmi/login": "PP-002",
    "/api/diagnostics/ping": "PP-003",
    "/api/historian/export": "PP-004",
    "/api/safety/override": "PP-005",
    "/api/modbus/write-register": "PP-006",
    "/api/plc/firmware-update": "PP-007",
}

ASSET_NAME = "power_plant"

_config = ConfigClient(asset=ASSET_NAME)


def _flag_key_to_vuln_id(flag_key: str) -> str:
    """'PATCH_PP_001' -> 'PP-001' (Config Service의 vuln_id 표기와 맞춤)."""
    rest = flag_key.removeprefix("PATCH_")
    return rest.replace("_", "-", 1)


app = FastAPI(title="Power Plant SCADA Digital Twin (TRAINING ONLY)")


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


app.middleware("http")(make_siem_access_middleware(ASSET_NAME, PP_ROUTE_VULN_MAP))


def patched(flag_key: str) -> bool:
    vuln_id = _flag_key_to_vuln_id(flag_key)
    return _config.is_patched(vuln_id, env_fallback_key=flag_key)


# 더미 PLC 레지스터 상태 (실제 장비와 무관한 시뮬레이션 값)
plc_registers = {"TURBINE_RPM": 3000, "COOLANT_FLOW": 100, "SAFETY_INTERLOCK": True}
safety_override_state = {"override": False, "approved_by": None}

HMI_ACCOUNTS = {"operator": "operator", "engineer": "Eng!neer_2024"}  # PP-002 기본계정


class PLCWrite(BaseModel):
    register: str
    value: object


class HMILogin(BaseModel):
    username: str
    password: str


class DiagPing(BaseModel):
    host: str


class HistorianExport(BaseModel):
    payload_b64: str  # 클라이언트가 보낸 base64 직렬화 데이터


class SafetyOverride(BaseModel):
    override: bool
    approver_token: str | None = None


@app.get("/health")
def health():
    return {"status": "ok", "service": "power_plant"}


# ---------------------------------------------------------------------------
# PP-001: Unauthenticated PLC Register Write
# ---------------------------------------------------------------------------
@app.post("/api/plc/write")
def plc_write(req: PLCWrite, authorization: str = Header(default=""), x_team_id: str = Header(default="default")):
    if patched("PATCH_PP_001"):
        if authorization != "Bearer engineering-station-token":
            raise HTTPException(401, "unauthorized: engineering workstation token required")
    else:
        emit_event(
            event_id=Event.make_id(x_team_id, ASSET_NAME, "PP-001", req.register, str(time.time())),
            event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
            vuln_id="PP-001", phase=RedPhase.lateral_movement, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
            metadata={"register": req.register, "value": req.value},
        )
    if req.register not in plc_registers:
        raise HTTPException(400, "unknown register")
    plc_registers[req.register] = req.value
    return {"patched": patched("PATCH_PP_001"), "registers": plc_registers}


@app.get("/api/plc/read")
def plc_read():
    return plc_registers


# ---------------------------------------------------------------------------
# PP-002: Default HMI Credentials
# ---------------------------------------------------------------------------
@app.post("/api/hmi/login")
def hmi_login(req: HMILogin, x_team_id: str = Header(default="default")):
    if patched("PATCH_PP_002") and req.username in HMI_ACCOUNTS and HMI_ACCOUNTS[req.username] in ("operator", "engineer"):
        # 패치 후: 기본 비밀번호와 동일하면 강제 거부(초기 변경 안 된 계정으로 간주)
        raise HTTPException(403, "default password not allowed, must be changed on first login")
    if HMI_ACCOUNTS.get(req.username) == req.password:
        if not patched("PATCH_PP_002"):
            emit_event(
                event_id=Event.make_id(x_team_id, ASSET_NAME, "PP-002", req.username, str(time.time())),
                event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
                vuln_id="PP-002", phase=RedPhase.initial_access, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
                metadata={"username": req.username},
            )
        return {"patched": patched("PATCH_PP_002"), "status": "login_success", "role": req.username}
    raise HTTPException(401, "invalid credentials")


# ---------------------------------------------------------------------------
# PP-003: Diagnostics Command Injection
# ---------------------------------------------------------------------------
@app.post("/api/diagnostics/ping")
def diagnostics_ping(req: DiagPing, x_team_id: str = Header(default="default")):
    if patched("PATCH_PP_003"):
        # 패치 후: IP 형식 검증 + 배열 인자 + shell=False
        try:
            ipaddress.ip_address(req.host)
        except ValueError:
            raise HTTPException(400, "invalid host: must be a valid IP address")
        result = subprocess.run(
            ["ping", "-c", "1", req.host], capture_output=True, text=True, timeout=3, shell=False
        )
        return {"patched": True, "output": result.stdout or result.stderr}
    else:
        # 취약 지점: 사용자 입력을 쉘 명령 문자열에 그대로 결합 (훈련용, 실제 시스템 명령 실행 금지 목적상 shlex로 위험도 낮춤)
        # 실제 취약 서비스에서는 os.system(f"ping -c 1 {req.host}") 형태로 나타남
        if any(ch in req.host for ch in [";", "|", "&", "$", "`"]):
            emit_event(
                event_id=Event.make_id(x_team_id, ASSET_NAME, "PP-003", req.host, str(time.time())),
                event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
                vuln_id="PP-003", phase=RedPhase.privilege_escalation, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
                metadata={"host_input": req.host},
            )
        cmd = f"ping -c 1 {req.host}"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
        except Exception as e:
            return {"patched": False, "error": str(e)}
        return {"patched": False, "output": result.stdout or result.stderr, "note": "command injection possible via ; | & $()"}


# ---------------------------------------------------------------------------
# PP-004: Historian Insecure Deserialization
# ---------------------------------------------------------------------------
@app.post("/api/historian/export")
def historian_export(req: HistorianExport, x_team_id: str = Header(default="default")):
    raw = base64.b64decode(req.payload_b64)
    if patched("PATCH_PP_004"):
        raise HTTPException(400, "pickle deserialization disabled; use /api/historian/export-json instead")
    # 취약 지점: 신뢰되지 않은 입력을 pickle로 역직렬화 -> 임의 코드 실행 가능 (CWE-502)
    try:
        obj = pickle.loads(raw)
    except Exception as e:
        raise HTTPException(400, f"deserialize error: {e}")
    emit_event(
        event_id=Event.make_id(x_team_id, ASSET_NAME, "PP-004", str(time.time())),
        event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
        vuln_id="PP-004", phase=RedPhase.privilege_escalation, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
        metadata={"payload_size": len(raw)},
    )
    return {"patched": False, "deserialized_repr": repr(obj)}


@app.post("/api/historian/export-json")
def historian_export_json(data: dict):
    # 안전한 대체 엔드포인트: JSON만 허용
    return {"patched": True, "data": data}


# ---------------------------------------------------------------------------
# PP-005: Safety Monitor Override Bypass
# ---------------------------------------------------------------------------
@app.post("/api/safety/override")
def safety_override(req: SafetyOverride, x_team_id: str = Header(default="default")):
    if patched("PATCH_PP_005"):
        # 패치 후: 2인 승인 토큰 필요
        if req.approver_token != "supervisor-2nd-approval-token":
            raise HTTPException(403, "requires 2-person (4-eyes) approval token")
    elif req.override:
        emit_event(
            event_id=Event.make_id(x_team_id, ASSET_NAME, "PP-005", str(time.time())),
            event_type=EventType.red_objective_success, actor="red", target_asset=ASSET_NAME,
            vuln_id="PP-005", phase=RedPhase.objective, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
            metadata={"note": "safety interlock disabled without approval"},
        )
    safety_override_state["override"] = req.override
    safety_override_state["approved_by"] = req.approver_token
    plc_registers["SAFETY_INTERLOCK"] = not req.override
    return {"patched": patched("PATCH_PP_005"), "state": safety_override_state}


# ---------------------------------------------------------------------------
# PP-006: Unauthorized Modbus Register Write (보호 레지스터 미인가 쓰기, ICS)
# ---------------------------------------------------------------------------
# 실제 Modbus 장비와 무관한 시뮬레이션. 안전 관련 보호 레지스터.
modbus_registers = {"EMERGENCY_SHUTDOWN": False, "FEEDWATER_VALVE": 50, "RELAY_TRIP": False}
PROTECTED_REGISTERS = {"EMERGENCY_SHUTDOWN", "RELAY_TRIP"}


class ModbusWrite(BaseModel):
    register: str
    value: object
    unit_id: int = 1


@app.post("/api/modbus/write-register")
def modbus_write(req: ModbusWrite, authorization: str = Header(default=""), x_team_id: str = Header(default="default")):
    if req.register not in modbus_registers:
        raise HTTPException(400, "unknown modbus register")
    if patched("PATCH_PP_006"):
        # 패치 후: 엔지니어링 워크스테이션 인증 + 보호 레지스터는 별도 승인 없이는 쓰기 금지
        if authorization != "Bearer engineering-station-token":
            raise HTTPException(401, "unauthorized: engineering workstation token required")
        if req.register in PROTECTED_REGISTERS:
            raise HTTPException(403, "protected safety register: change control approval required")
    else:
        # 취약 지점: 인증 없이 Modbus write function code로 보호 레지스터까지 조작 가능
        if req.register in PROTECTED_REGISTERS:
            emit_event(
                event_id=Event.make_id(x_team_id, ASSET_NAME, "PP-006", req.register, str(time.time())),
                event_type=EventType.red_objective_success, actor="red", target_asset=ASSET_NAME,
                vuln_id="PP-006", phase=RedPhase.objective, team_id=x_team_id,
                trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
                metadata={"register": req.register, "value": req.value, "note": "protected safety register written without auth"},
            )
    modbus_registers[req.register] = req.value
    return {"patched": patched("PATCH_PP_006"), "registers": modbus_registers}


# ---------------------------------------------------------------------------
# PP-007: Unsigned Firmware Update (서명 검증 없는 펌웨어 설치)
# ---------------------------------------------------------------------------
class FirmwareUpdate(BaseModel):
    version: str
    firmware_b64: str
    signature: str | None = None


@app.post("/api/plc/firmware-update")
def firmware_update(req: FirmwareUpdate, x_team_id: str = Header(default="default")):
    blob = base64.b64decode(req.firmware_b64) if req.firmware_b64 else b""
    if patched("PATCH_PP_007"):
        # 패치 후: 벤더 서명 검증(간이) — 유효 서명 없으면 거부
        if req.signature != "vendor-signed-" + req.version:
            raise HTTPException(403, "firmware signature verification failed")
        return {"patched": True, "status": "firmware verified & staged", "version": req.version}
    # 취약 지점: 서명 검증 없이 임의 펌웨어 설치 -> 악성 펌웨어 주입 가능(ICS T0857)
    emit_event(
        event_id=Event.make_id(x_team_id, ASSET_NAME, "PP-007", req.version, str(time.time())),
        event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
        vuln_id="PP-007", phase=RedPhase.objective, team_id=x_team_id,
        trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
        metadata={"version": req.version, "firmware_size": len(blob)},
    )
    return {"patched": False, "status": "firmware flashed (no signature check)", "version": req.version}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
