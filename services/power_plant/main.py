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
from shared.lifespan import on_startup  # noqa: E402
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
# 감사 3.3: 팀 귀속은 배포 env(TEAM_ID)로 서버측 결정. 공격자 제어 헤더(X-Team-Id) 미신뢰.
TEAM_ID = os.environ.get("TEAM_ID", "default")

_config = ConfigClient(asset=ASSET_NAME)


def _flag_key_to_vuln_id(flag_key: str) -> str:
    """'PATCH_PP_001' -> 'PP-001' (Config Service의 vuln_id 표기와 맞춤)."""
    rest = flag_key.removeprefix("PATCH_")
    return rest.replace("_", "-", 1)


app = FastAPI(title="Power Plant SCADA Digital Twin (TRAINING ONLY)")


@on_startup(app)
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

# ---------------------------------------------------------------------------
# 실제 Modbus/TCP 리스너(P1-1) — 트윈이 진짜 Modbus 를 말한다(mbpoll/pymodbus/metasploit 대응).
# 홀딩 레지스터 0=TURBINE_RPM, 1=COOLANT_FLOW / 코일 0=SAFETY_INTERLOCK.
# Modbus 는 설계상 무인증(ICS insecure-by-design) → 미인가 쓰기는 PP-006 이벤트로 발행.
# ---------------------------------------------------------------------------
from shared.ics.modbus import ModbusBank, serve as _modbus_serve  # noqa: E402
from shared.ics.safety import SafetyProfile, evaluate as _safety_eval  # noqa: E402
from shared.ics.anomaly import IcsBaseline, RegBand, classify_write as _classify  # noqa: E402
from shared.siem_access_log import get_siem_logger as _get_siem_logger  # noqa: E402
import json as _json  # noqa: E402
import asyncio as _asyncio  # noqa: E402

_siem_log = _get_siem_logger(ASSET_NAME)  # Modbus 활동을 SIEM 으로 흘려 Blue 탐지 가능하게

_MODBUS_HOLDING = {0: "TURBINE_RPM", 1: "COOLANT_FLOW"}
# ICS 이상탐지 베이스라인(Blue/SIEM 신호) — 운전 밴드 + 보호 + 안전 코일.
_ICS_BASE = IcsBaseline(name=ASSET_NAME,
                        registers={0: RegBand("TURBINE_RPM", 2800, 3600, protected=True),
                                   1: RegBand("COOLANT_FLOW", 80, 120)},
                        safety_coils={0})
# 안전 프로파일(SIS): 터빈 과속(>4500) / 냉각수 저유량(<50). 인터록 코일 0.
_SAFETY = SafetyProfile(name=ASSET_NAME,
                        limits={0: {"name": "TURBINE_RPM", "max": 4500},
                                1: {"name": "COOLANT_FLOW", "min": 50}},
                        interlock_coil=0)
_modbus_bank = ModbusBank(holding=[0] * 16, coils=[False] * 16)
_modbus_bank.holding[0] = int(plc_registers["TURBINE_RPM"])
_modbus_bank.holding[1] = int(plc_registers["COOLANT_FLOW"])
_modbus_bank.coils[0] = bool(plc_registers["SAFETY_INTERLOCK"])
_modbus_server = None

# ---------------------------------------------------------------------------
# 실 DNP3 아웃스테이션(§5 실 프로토콜 확장) — 전력 SCADA의 표준 프로토콜.
# analog_inputs = [RPM명령, 실제RPM, 냉각수온, 손상%] (읽기 텔레메트리),
# binary_outputs[0] = SAFETY_INTERLOCK. DNP3 DIRECT_OPERATE로 인터록을 끄는 건 미인가 제어
# (SIS 무력화)이므로 PP-006 이벤트를 발행하고 Modbus 코일과 동일 물리에 연동한다.
# Modbus 와 마찬가지로 DNP3 도 insecure-by-design(무인증) 을 의도적으로 재현한다.
from shared.ics.dnp3 import Dnp3Outstation, serve as _dnp3_serve  # noqa: E402
_dnp3_server = None


def _on_dnp3_operate(index: int, latch_on: bool) -> None:
    """DNP3 바이너리 출력 조작 콜백. index 0 = 안전 인터록."""
    if index == 0:
        _modbus_bank.coils[0] = latch_on   # 공유 물리(SIS)에 반영
        try:
            anomaly = None
            _siem_log.info(_json.dumps({
                "ts": time.time(), "asset": ASSET_NAME, "protocol": "dnp3",
                "endpoint": "/dnp3/direct_operate/interlock", "method": "DNP3",
                "status": 200, "vuln_id": "PP-006",
                "note": f"binary_output[0] latch={'ON' if latch_on else 'OFF'}"}))
            emit_event(
                event_id=Event.make_id("dnp3", ASSET_NAME, "PP-006", str(time.time())),
                event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
                vuln_id="PP-006", phase=RedPhase.initial_access, team_id="default",
                trace_id=Event.session_trace_id("dnp3", ASSET_NAME),
                metadata={"protocol": "dnp3", "control": "safety_interlock",
                          "latch_on": latch_on, "fc": "direct_operate",
                          "ics_technique": "T0855" if not latch_on else None,
                          "severity": "high" if not latch_on else "info"})
        except Exception:
            pass


_dnp3_os = Dnp3Outstation(analog_inputs=[0, 0, 0, 0, 0, 0, 0, 0],
                          binary_outputs=[False] * 8, address=4,
                          on_operate=_on_dnp3_operate)

# 연속 물리 시뮬(P1-1 심화): HR2=ACTUAL_RPM, HR3=COOLANT_TEMP (읽기전용 텔레메트리).
# 명령(HR0)·유량(HR1)에 따라 동역학적으로 반응 — 공격자는 즉시반영이 아닌 프로세스 응답을 읽어야.
from shared.ics.process_sim import ProcessState, ProcessParams, step as _proc_step, has_failed as _has_failed, in_danger as _in_danger  # noqa: E402
_PROC_PARAMS = ProcessParams(slew_rpm_per_s=400, nominal_rpm=3000, ambient_temp=40, k_heat=0.02, k_cool=0.5)
_proc_state = ProcessState(actual_rpm=float(_modbus_bank.holding[0]), coolant_temp=40.0)
_proc_failed = False
_modbus_bank.holding[2] = int(_proc_state.actual_rpm)   # ACTUAL_RPM
_modbus_bank.holding[3] = int(_proc_state.coolant_temp)  # COOLANT_TEMP
_modbus_bank.holding[4] = 0                              # DAMAGE(%)


@on_startup(app)
async def _start_process_sim():
    async def _loop():
        global _proc_state, _proc_failed
        _prev_dmg = _proc_state.damage
        while True:
            cmd = float(_modbus_bank.holding[0]); flow = float(_modbus_bank.holding[1])
            interlock = bool(_modbus_bank.coils[0])
            _proc_state = _proc_step(_proc_state, cmd, flow, dt=0.5, p=_PROC_PARAMS,
                                     interlock_engaged=interlock)
            _modbus_bank.holding[2] = int(_proc_state.actual_rpm)
            _modbus_bank.holding[3] = int(_proc_state.coolant_temp)
            _modbus_bank.holding[4] = int(_proc_state.damage)
            # DNP3 아날로그 입력을 동일 텔레메트리로 동기화(실 SCADA 마스터가 읽는 값).
            _dnp3_os.analog_inputs[0] = int(cmd)
            _dnp3_os.analog_inputs[1] = int(_proc_state.actual_rpm)
            _dnp3_os.analog_inputs[2] = int(_proc_state.coolant_temp)
            _dnp3_os.analog_inputs[3] = int(_proc_state.damage)
            _dnp3_os.binary_outputs[0] = interlock
            # 파국 에지(지속 과속+SIS 무력화 → 물리적 파괴). 1회만 발행.
            if _has_failed(_proc_state, _PROC_PARAMS) and not _proc_failed:
                _proc_failed = True
                try:
                    emit_event(
                        event_id=Event.make_id("physics", ASSET_NAME, "SAFETY", "FAILURE", str(time.time())),
                        event_type=EventType.asset_compromised, actor="red", target_asset=ASSET_NAME,
                        vuln_id="PP-006", phase=RedPhase.lateral_movement, team_id="default",
                        trace_id=Event.session_trace_id("physics", ASSET_NAME),
                        metadata={"protocol": "modbus", "safety_impact": "catastrophic_failure",
                                  "cause": "sustained_overspeed_sis_disabled",
                                  "actual_rpm": int(_proc_state.actual_rpm),
                                  "coolant_temp": int(_proc_state.coolant_temp), "severity": "critical"})
                except Exception:
                    pass
            elif interlock and _proc_state.damage == 0:
                _proc_failed = False   # 정상 복귀 시 재무장(다음 훈련)
            # 회복 에지: 손상 자산이 확보돼 0 으로 회복 → asset_recovered(Blue 복구 크레딧)
            if _prev_dmg > 0 and _proc_state.damage == 0:
                try:
                    emit_event(
                        event_id=Event.make_id("physics", ASSET_NAME, "RECOVERED", str(time.time())),
                        event_type=EventType.asset_recovered, actor="blue", target_asset=ASSET_NAME,
                        vuln_id="PP-006", phase=RedPhase.lateral_movement, team_id="default",
                        trace_id=Event.session_trace_id("physics", ASSET_NAME),
                        metadata={"protocol": "modbus", "note": "asset secured and recovered"})
                except Exception:
                    pass
            _prev_dmg = _proc_state.damage
            await _asyncio.sleep(0.5)
    _asyncio.create_task(_loop())


def _sync_bank_from_registers() -> None:
    """HTTP 경로로 바뀐 상태를 Modbus 뱅크에 반영(양 경로 일관성)."""
    try:
        _modbus_bank.holding[0] = int(plc_registers.get("TURBINE_RPM", 0))
        _modbus_bank.holding[1] = int(plc_registers.get("COOLANT_FLOW", 0))
        _modbus_bank.coils[0] = bool(plc_registers.get("SAFETY_INTERLOCK", False))
    except (ValueError, TypeError):
        pass


def _on_modbus_write(kind: str, addr: int, vals: list) -> None:
    """Modbus 쓰기 콜백 — 물리 상태 반영 + 미인가 쓰기 이벤트(PP-006)."""
    if kind == "holding":
        for i, v in enumerate(vals):
            name = _MODBUS_HOLDING.get(addr + i)
            if name:
                plc_registers[name] = int(v)
        target = _MODBUS_HOLDING.get(addr, f"HR{addr}")
    else:  # coil
        if addr == 0:
            plc_registers["SAFETY_INTERLOCK"] = bool(vals[0])
        target = "SAFETY_INTERLOCK" if addr == 0 else f"COIL{addr}"
    # ICS 이상탐지 분류(MITRE ICS) — Blue/SIEM 이 이 신호로 탐지.
    anomaly = _classify(_ICS_BASE, kind, addr, vals)
    # Modbus 활동을 SIEM access 로그로 발행 → 탐지 규칙(ICS-*)이 매칭 → blue_detection_success.
    try:
        _siem_log.info(_json.dumps({
            "ts": time.time(), "asset": ASSET_NAME, "method": "MODBUS",
            "endpoint": f"/modbus/{'interlock' if kind == 'coil' else 'register'}/{target}",
            "status": 200, "vuln_id": "PP-006", "team_id": "default",
            "trace_id": Event.session_trace_id("modbus", ASSET_NAME),
            "ics_technique": anomaly["technique"] if anomaly else None,
            "ics_severity": anomaly["severity"] if anomaly else None, "register": target,
        }))
    except Exception:
        pass
    if not patched("PATCH_PP_006"):
        try:
            md = {"protocol": "modbus", "register": target, "values": vals, "fc_kind": kind}
            if anomaly:
                md.update({"ics_technique": anomaly["technique"], "ics_severity": anomaly["severity"],
                           "ics_reason": anomaly["reason"]})
            emit_event(
                event_id=Event.make_id("modbus", ASSET_NAME, "PP-006", target, str(time.time())),
                event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
                vuln_id="PP-006", phase=RedPhase.lateral_movement, team_id="default",
                trace_id=Event.session_trace_id("modbus", ASSET_NAME),
                metadata=md,
            )
        except Exception:
            pass

    # 물리 안전 결과(P1-1 심화): 위험 상태 + 인터록 해제 → 실제 임팩트(asset_compromised).
    try:
        breaches = _safety_eval(_SAFETY, _modbus_bank.holding, _modbus_bank.coils)
        for b in breaches:
            if not b["contained"]:   # 억제 실패 = 물리 임팩트
                emit_event(
                    event_id=Event.make_id("modbus", ASSET_NAME, "SAFETY", b["register"], str(time.time())),
                    event_type=EventType.asset_compromised, actor="red", target_asset=ASSET_NAME,
                    vuln_id="PP-006", phase=RedPhase.lateral_movement, team_id="default",
                    trace_id=Event.session_trace_id("modbus", ASSET_NAME),
                    metadata={"protocol": "modbus", "safety_impact": b["condition"],
                              "register": b["register"], "value": b["value"],
                              "limit": b["limit"], "severity": b["severity"]},
                )
    except Exception:
        pass

    # Blue 방어 액션(P1-1): 위험 중 안전 인터록 재무장(coil0→ON) → 방어 성공(blue_block_success).
    # SIS 를 되살리면 다음 tick 부터 트립이 걸려 파국을 막는다. Red 의 T0878 무력화와 대칭.
    try:
        if kind == "coil" and addr == 0 and vals and bool(vals[0]) \
                and not _proc_failed and _in_danger(_proc_state, _PROC_PARAMS):
            emit_event(
                event_id=Event.make_id("blue", ASSET_NAME, "SIS-REARM", str(time.time())),
                event_type=EventType.blue_block_success, actor="blue", target_asset=ASSET_NAME,
                vuln_id="PP-006", phase=RedPhase.lateral_movement, team_id="default",
                trace_id=Event.session_trace_id("modbus", ASSET_NAME),
                metadata={"protocol": "modbus", "defense": "safety_interlock_rearmed",
                          "actual_rpm": int(_proc_state.actual_rpm),
                          "damage": int(_proc_state.damage)},
            )
    except Exception:
        pass


_modbus_bank.on_write = _on_modbus_write


@on_startup(app)
async def _start_modbus():
    global _modbus_server
    if os.environ.get("MODBUS_ENABLED", "1") != "1":
        return
    port = int(os.environ.get("MODBUS_PORT", "502"))
    try:
        _modbus_server = await _modbus_serve(_modbus_bank, "0.0.0.0", port)
    except OSError:
        pass  # 502 바인딩 실패(권한/포트 점유) 시 HTTP 트윈은 계속 동작


@on_startup(app)
async def _start_dnp3():
    """실 DNP3/TCP 아웃스테이션 기동(§5 실 프로토콜 확장). 기본 포트 20000."""
    global _dnp3_server
    if os.environ.get("DNP3_ENABLED", "1") != "1":
        return
    port = int(os.environ.get("DNP3_PORT", "20000"))
    try:
        _dnp3_server = await _dnp3_serve(_dnp3_os, "0.0.0.0", port)
    except OSError:
        pass  # 바인딩 실패 시 HTTP 트윈은 계속 동작

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
def plc_write(req: PLCWrite, authorization: str = Header(default="")):
    if patched("PATCH_PP_001"):
        if authorization != "Bearer engineering-station-token":
            raise HTTPException(401, "unauthorized: engineering workstation token required")
    else:
        emit_event(
            event_id=Event.make_id(TEAM_ID, ASSET_NAME, "PP-001", req.register, str(time.time())),
            event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
            vuln_id="PP-001", phase=RedPhase.lateral_movement, team_id=TEAM_ID,
            trace_id=Event.session_trace_id(TEAM_ID, ASSET_NAME),
            metadata={"register": req.register, "value": req.value},
        )
    if req.register not in plc_registers:
        raise HTTPException(400, "unknown register")
    plc_registers[req.register] = req.value
    _sync_bank_from_registers()   # Modbus 뱅크와 일관성 유지(P1-1)
    return {"patched": patched("PATCH_PP_001"), "registers": plc_registers}


@app.get("/api/plc/read")
def plc_read():
    return plc_registers


# ---------------------------------------------------------------------------
# PP-002: Default HMI Credentials
# ---------------------------------------------------------------------------
@app.post("/api/hmi/login")
def hmi_login(req: HMILogin):
    if patched("PATCH_PP_002") and req.username in HMI_ACCOUNTS and HMI_ACCOUNTS[req.username] in ("operator", "engineer"):
        # 패치 후: 기본 비밀번호와 동일하면 강제 거부(초기 변경 안 된 계정으로 간주)
        raise HTTPException(403, "default password not allowed, must be changed on first login")
    if HMI_ACCOUNTS.get(req.username) == req.password:
        if not patched("PATCH_PP_002"):
            emit_event(
                event_id=Event.make_id(TEAM_ID, ASSET_NAME, "PP-002", req.username, str(time.time())),
                event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
                vuln_id="PP-002", phase=RedPhase.initial_access, team_id=TEAM_ID,
            trace_id=Event.session_trace_id(TEAM_ID, ASSET_NAME),
                metadata={"username": req.username},
            )
        return {"patched": patched("PATCH_PP_002"), "status": "login_success", "role": req.username}
    raise HTTPException(401, "invalid credentials")


# ---------------------------------------------------------------------------
# PP-003: Diagnostics Command Injection
# ---------------------------------------------------------------------------
@app.post("/api/diagnostics/ping")
def diagnostics_ping(req: DiagPing):
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
                event_id=Event.make_id(TEAM_ID, ASSET_NAME, "PP-003", req.host, str(time.time())),
                event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
                vuln_id="PP-003", phase=RedPhase.privilege_escalation, team_id=TEAM_ID,
            trace_id=Event.session_trace_id(TEAM_ID, ASSET_NAME),
                metadata={"host_input": req.host},
            )
        cmd = f"ping -c 1 {req.host}"
        try:
            # nosec B602 — PP-003 은 '의도된' 커맨드 인젝션 훈련 취약점이다(트윈). shell=True 는
            # 교육 목적의 취약점 그 자체이며 실제 결함이 아니다. bandit baseline 은 라인 밀림에
            # 취약해(DNP3 배선 추가로 재발) 라인과 함께 이동하는 nosec 로 명시 억제한다.
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)  # nosec B602
        except Exception as e:
            return {"patched": False, "error": str(e)}
        return {"patched": False, "output": result.stdout or result.stderr, "note": "command injection possible via ; | & $()"}


# ---------------------------------------------------------------------------
# PP-004: Historian Insecure Deserialization
# ---------------------------------------------------------------------------
@app.post("/api/historian/export")
def historian_export(req: HistorianExport):
    raw = base64.b64decode(req.payload_b64)
    if patched("PATCH_PP_004"):
        raise HTTPException(400, "pickle deserialization disabled; use /api/historian/export-json instead")
    # 취약 지점: 신뢰되지 않은 입력을 pickle로 역직렬화 -> 임의 코드 실행 가능 (CWE-502)
    try:
        obj = pickle.loads(raw)
    except Exception as e:
        raise HTTPException(400, f"deserialize error: {e}")
    emit_event(
        event_id=Event.make_id(TEAM_ID, ASSET_NAME, "PP-004", str(time.time())),
        event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
        vuln_id="PP-004", phase=RedPhase.privilege_escalation, team_id=TEAM_ID,
            trace_id=Event.session_trace_id(TEAM_ID, ASSET_NAME),
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
def safety_override(req: SafetyOverride):
    if patched("PATCH_PP_005"):
        # 패치 후: 2인 승인 토큰 필요
        if req.approver_token != "supervisor-2nd-approval-token":
            raise HTTPException(403, "requires 2-person (4-eyes) approval token")
    elif req.override:
        emit_event(
            event_id=Event.make_id(TEAM_ID, ASSET_NAME, "PP-005", str(time.time())),
            event_type=EventType.red_objective_success, actor="red", target_asset=ASSET_NAME,
            vuln_id="PP-005", phase=RedPhase.objective, team_id=TEAM_ID,
            trace_id=Event.session_trace_id(TEAM_ID, ASSET_NAME),
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
def modbus_write(req: ModbusWrite, authorization: str = Header(default="")):
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
                event_id=Event.make_id(TEAM_ID, ASSET_NAME, "PP-006", req.register, str(time.time())),
                event_type=EventType.red_objective_success, actor="red", target_asset=ASSET_NAME,
                vuln_id="PP-006", phase=RedPhase.objective, team_id=TEAM_ID,
                trace_id=Event.session_trace_id(TEAM_ID, ASSET_NAME),
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
def firmware_update(req: FirmwareUpdate):
    blob = base64.b64decode(req.firmware_b64) if req.firmware_b64 else b""
    if patched("PATCH_PP_007"):
        # 패치 후: 벤더 서명 검증(간이) — 유효 서명 없으면 거부
        if req.signature != "vendor-signed-" + req.version:
            raise HTTPException(403, "firmware signature verification failed")
        return {"patched": True, "status": "firmware verified & staged", "version": req.version}
    # 취약 지점: 서명 검증 없이 임의 펌웨어 설치 -> 악성 펌웨어 주입 가능(ICS T0857)
    emit_event(
        event_id=Event.make_id(TEAM_ID, ASSET_NAME, "PP-007", req.version, str(time.time())),
        event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
        vuln_id="PP-007", phase=RedPhase.objective, team_id=TEAM_ID,
        trace_id=Event.session_trace_id(TEAM_ID, ASSET_NAME),
        metadata={"version": req.version, "firmware_size": len(blob)},
    )
    return {"patched": False, "status": "firmware flashed (no signature check)", "version": req.version}


# ---------------------------------------------------------------------------
# 실 IEC 60870-5-104 / GOOSE (§5 실 프로토콜 확장, Tier-3) — 전력 원격제어·변전소 보호.
# 두 프로토콜 모두 무인증(insecure-by-design)이다. 전송은 트윈 관례(HTTP-sim)를 따르되,
# 실 인코더(shared/ics/iec104·goose)로 프레임을 만들어 자체 파서로 왕복 디코드한 명령
# 정보를 SIEM access 로그(raw.protocol=iec104|goose)로 흘려 Blue 탐지를 성립시킨다.
# ---------------------------------------------------------------------------
from shared.ics.iec104 import (build_asdu as _iec_asdu, build_i_apdu as _iec_apdu,  # noqa: E402
                               parse_apdu as _iec_parse, C_SC_NA_1)
from shared.ics.goose import (build_goose as _goose_build, parse_goose as _goose_parse)  # noqa: E402


class Iec104Command(BaseModel):
    ioa: int = 3000            # 정보객체 주소(예: 차단기 원격제어점)
    on: bool = False           # 단일명령 SCO 값(트립/투입)
    common_addr: int = 1


@app.post("/api/iec104/command")
def iec104_command(req: Iec104Command):
    """IEC 104 단일명령(C_SC_NA_1)으로 RTU/차단기 원격제어. 무인증 → 미인가 제어(그리드/SIS)."""
    sco = 0x01 if req.on else 0x00
    asdu = _iec_asdu(C_SC_NA_1, cot=6, common_addr=req.common_addr, ioa=req.ioa, info=bytes([sco]))
    apdu = _iec_apdu(asdu, send_seq=0, recv_seq=0)
    parsed = _iec_parse(apdu)
    try:
        _siem_log.info(_json.dumps({
            "ts": time.time(), "asset": ASSET_NAME, "method": "IEC104",
            "endpoint": "/iec104/c_sc_na/rtu", "status": 200, "vuln_id": "PP-006",
            "team_id": "default", "trace_id": Event.session_trace_id("iec104", ASSET_NAME),
            "protocol": "iec104", "type_id": parsed.type_id if parsed else C_SC_NA_1,
            "cot": parsed.cot if parsed else 6, "ioa": parsed.ioa if parsed else req.ioa,
            "ics_technique": "T0855", "apdu_len": len(apdu)}))
    except Exception:
        pass
    try:
        emit_event(
            event_id=Event.make_id("iec104", ASSET_NAME, "PP-006", str(req.ioa), str(time.time())),
            event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
            vuln_id="PP-006", phase=RedPhase.lateral_movement, team_id="default",
            trace_id=Event.session_trace_id("iec104", ASSET_NAME),
            metadata={"protocol": "iec104", "fc": "C_SC_NA_1(single_command)", "ioa": req.ioa,
                      "cot": 6, "command": "ON" if req.on else "OFF", "ics_technique": "T0855",
                      "note": "unauthenticated IEC-104 telecontrol command"})
    except Exception:
        pass
    return {"protocol": "iec104", "sent": "C_SC_NA_1", "ioa": req.ioa,
            "command": "ON" if req.on else "OFF", "apdu_hex": apdu.hex()}


class GooseTrip(BaseModel):
    gocb_ref: str = "IED1CFG/LLN0$GO$gcb01"
    dat_set: str = "IED1CFG/LLN0$Protection"
    st_num: int = 2            # stNum 증가 = 새 상태변경(트립) 이벤트 → 스푸핑 주입
    sq_num: int = 0
    trip: bool = True


@app.post("/api/goose/publish")
def goose_publish(req: GooseTrip):
    """스푸핑 GOOSE 트립 주입(변전소 보호). stNum 증가 = 새 트립 이벤트로 릴레이를 오작동시킴."""
    frame = _goose_build(req.gocb_ref, req.dat_set, req.st_num, req.sq_num, trip=req.trip)
    parsed = _goose_parse(frame) or {}
    try:
        _siem_log.info(_json.dumps({
            "ts": time.time(), "asset": ASSET_NAME, "method": "GOOSE",
            "endpoint": "/goose/protection/trip", "status": 200, "vuln_id": "PP-006",
            "team_id": "default", "trace_id": Event.session_trace_id("goose", ASSET_NAME),
            "protocol": "goose", "gocb_ref": parsed.get("gocbRef", req.gocb_ref),
            "st_num": parsed.get("stNum", req.st_num), "trip": parsed.get("trip", req.trip),
            "ics_technique": "T0855"}))
    except Exception:
        pass
    try:
        emit_event(
            event_id=Event.make_id("goose", ASSET_NAME, "PP-006", str(req.st_num), str(time.time())),
            event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
            vuln_id="PP-006", phase=RedPhase.lateral_movement, team_id="default",
            trace_id=Event.session_trace_id("goose", ASSET_NAME),
            metadata={"protocol": "goose", "gocb_ref": req.gocb_ref, "st_num": req.st_num,
                      "trip": req.trip, "ics_technique": "T0855",
                      "note": "spoofed GOOSE protection trip (stNum incremented)"})
    except Exception:
        pass
    return {"protocol": "goose", "gocb_ref": req.gocb_ref, "st_num": req.st_num,
            "trip": req.trip, "frame_hex": frame.hex()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
