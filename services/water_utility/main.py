"""
Water Utility Digital Twin (수도 시설 트윈)
===========================================
정수장 + 배수장 + 펌프 + 염소 투입 + 유량/압력 계측을 모사. SCADA/Modbus.
훈련용 시뮬레이션(더미 값) — 실제 정수 공정과 무관.

취약점:
  WTR-001 Chlorine Dosing Tamper  (POST /api/dosing/chlorine) — 염소 투입량 무단 변경(공중보건 임팩트)
  WTR-002 Pump Control Unauth     (POST /api/pump/control)    — 취수/배수 펌프 무단 기동/정지
  WTR-003 SCADA HMI Default Creds (POST /api/hmi/login)       — 기본 자격증명 로그인
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402

HMI_ACCOUNTS = {"operator": "operator", "scada": "scada123"}


def chlorine_dosing(patched, p, emit):
    if patched and p.get("authorization") != "Bearer plant-operator-token":
        deny(401, "dosing setpoint change requires operator auth")
    ppm = p.get("ppm")
    if not patched:
        emit({"ppm": ppm, "note": "chlorine dosing setpoint changed without auth"})
    return {"chlorine_ppm": ppm, "status": "dosing setpoint applied"}


def pump_control(patched, p, emit):
    if patched and p.get("authorization") != "Bearer plant-operator-token":
        deny(401, "pump control requires operator auth")
    if not patched:
        emit({"pump": p.get("pump", "INTAKE-1"), "action": p.get("action"),
              "note": "unauthenticated pump start/stop"})
    return {"pump": p.get("pump", "INTAKE-1"), "action": p.get("action", "stop"), "status": "command sent"}


def hmi_login(patched, p, emit):
    u, pw = p.get("username", ""), p.get("password", "")
    if patched and u in HMI_ACCOUNTS and HMI_ACCOUNTS[u] == pw:
        deny(403, "default password must be changed on first login")
    if HMI_ACCOUNTS.get(u) == pw:
        if not patched:
            emit({"username": u, "note": "default HMI credentials"})
        return {"status": "login_success", "role": u}
    return deny(401, "invalid credentials")



def wtr_setpoint(patched, p, emit):
    if patched and p.get("authorization") != "Bearer scada-op":
        deny(401, "reservoir setpoint change requires operator auth")
    if not patched:
        emit({"note": "unauthenticated reservoir level setpoint tamper"})
    return {"status": "ok", "vuln": "WTR-004"}

def wtr_report_ssrf(patched, p, emit):
    if patched and p.get("authorization") != "Bearer report-svc":
        deny(400, "fetch URL blocked (allowlist)")
    if not patched:
        emit({"note": "report fetch SSRF to internal metadata"})
    return {"status": "ok", "vuln": "WTR-005"}


VULNS = [
    Vuln("WTR-001", "/api/dosing/chlorine", "POST", "Chlorine dosing tamper",
         "red_objective_success", "objective", chlorine_dosing),
    Vuln("WTR-002", "/api/pump/control", "POST", "Pump control unauth",
         "red_attack_started", "lateral_movement", pump_control),
    Vuln("WTR-003", "/api/hmi/login", "POST", "SCADA HMI default creds",
         "red_attack_started", "initial_access", hmi_login),
    Vuln("WTR-004", "/api/tank/setpoint", "POST", "Reservoir setpoint tamper",
         "red_objective_success", "objective", wtr_setpoint),
    Vuln("WTR-005", "/api/report/fetch", "POST", "Report fetch SSRF",
         "red_attack_started", "lateral_movement", wtr_report_ssrf),
]

app = make_ics_twin("water_utility", "Water Treatment SCADA Twin", VULNS)

# ---------------------------------------------------------------------------
# 실제 Modbus/TCP 리스너(P1-1) — 두 번째 ICS 트윈도 진짜 Modbus 를 말한다.
# 홀딩 0=CHLORINE_PPM(투입 설정), 1=INTAKE_PUMP_RATE / 코일 0=SAFETY_INTERLOCK(과투입 보호).
# 안전: 염소 >4ppm + 인터록 해제 → 화학 과투입(공중보건 임팩트, asset_compromised).
# ---------------------------------------------------------------------------
import os as _os  # noqa: E402
import time as _time  # noqa: E402
from shared.ics.modbus import ModbusBank, serve as _modbus_serve  # noqa: E402
from shared.ics.safety import SafetyProfile, evaluate as _safety_eval  # noqa: E402
from shared.ics.anomaly import IcsBaseline, RegBand, classify_write as _wu_classify  # noqa: E402
from shared.event_client import emit_event as _emit  # noqa: E402
from shared.event_schema import Event, EventType, RedPhase  # noqa: E402

_ASSET = "water_utility"
_MB_HOLDING = {0: "CHLORINE_PPM", 1: "INTAKE_PUMP_RATE"}
_WU_SAFETY = SafetyProfile(name=_ASSET,
                           limits={0: {"name": "CHLORINE_PPM", "max": 4},      # 안전 상한 4ppm
                                   1: {"name": "INTAKE_PUMP_RATE", "max": 100}},
                           interlock_coil=0)
_wu_bank = ModbusBank(holding=[2, 60] + [0] * 14, coils=[True] + [False] * 15)  # 2ppm/60%, 인터록 ON
_wu_server = None
_WU_ICS_BASE = IcsBaseline(name=_ASSET,
                           registers={0: RegBand("CHLORINE_PPM", 0, 4, protected=True),
                                      1: RegBand("INTAKE_PUMP_RATE", 0, 100)},
                           safety_coils={0})


def _wu_on_write(kind: str, addr: int, vals: list) -> None:
    target = (_MB_HOLDING.get(addr, f"HR{addr}") if kind == "holding"
              else ("SAFETY_INTERLOCK" if addr == 0 else f"COIL{addr}"))
    anomaly = _wu_classify(_WU_ICS_BASE, kind, addr, vals)
    md = {"protocol": "modbus", "register": target, "values": vals, "fc_kind": kind}
    if anomaly:
        md.update({"ics_technique": anomaly["technique"], "ics_severity": anomaly["severity"],
                   "ics_reason": anomaly["reason"]})
    try:
        _emit(event_id=Event.make_id("modbus", _ASSET, "WTR-001", target, str(_time.time())),
              event_type=EventType.red_objective_success, actor="red", target_asset=_ASSET,
              vuln_id="WTR-001", phase=RedPhase.objective, team_id="default",
              trace_id=Event.session_trace_id("modbus", _ASSET),
              metadata=md)
    except Exception:
        pass
    # 물리 안전: 염소 과투입 + 인터록 해제 → 공중보건 임팩트
    try:
        for b in _safety_eval(_WU_SAFETY, _wu_bank.holding, _wu_bank.coils):
            if not b["contained"]:
                _emit(event_id=Event.make_id("modbus", _ASSET, "SAFETY", b["register"], str(_time.time())),
                      event_type=EventType.asset_compromised, actor="red", target_asset=_ASSET,
                      vuln_id="WTR-001", phase=RedPhase.objective, team_id="default",
                      trace_id=Event.session_trace_id("modbus", _ASSET),
                      metadata={"protocol": "modbus", "safety_impact": b["condition"],
                                "register": b["register"], "value": b["value"],
                                "limit": b["limit"], "severity": b["severity"],
                                "impact": "chemical_overdose_public_health"})
    except Exception:
        pass


_wu_bank.on_write = _wu_on_write


@app.on_event("startup")
async def _start_wu_modbus():
    global _wu_server
    if _os.environ.get("MODBUS_ENABLED", "1") != "1":
        return
    try:
        _wu_server = await _modbus_serve(_wu_bank, "0.0.0.0", int(_os.environ.get("MODBUS_PORT", "502")))
    except OSError:
        pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8203)
