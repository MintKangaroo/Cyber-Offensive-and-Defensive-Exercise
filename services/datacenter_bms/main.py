"""
Data Center BMS Digital Twin (데이터센터 BMS 트윈)
==================================================
UPS + CRAC(정밀공조) + Generator + BMS + DCIM 을 모사.
훈련용 시뮬레이션(더미 값) — 실제 시설과 무관.

취약점:
  DCX-001 CRAC Setpoint Tamper   (POST /api/crac/setpoint)  — 냉방 설정치 변조(과열 유도)
  DCX-002 UPS Shutdown Unauth    (POST /api/ups/command)    — UPS 무단 셧다운 명령
  DCX-003 DCIM SSRF              (POST /api/dcim/fetch)     — DCIM 원격 URL 조회(SSRF)
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402


def _is_internal(url: str) -> bool:
    u = (url or "").lower()
    return (u.startswith("file://") or any(n in u for n in
            ("169.254.169.254", "localhost", "127.0.0.1", "10.", "192.168.", "internal", "metadata")))


def crac_setpoint(patched, p, emit):
    if patched and p.get("authorization") != "Bearer facility-ops-token":
        deny(401, "CRAC setpoint change requires facility ops auth")
    if not patched:
        emit({"unit": p.get("unit", "CRAC-3"), "temp_c": p.get("temp_c"),
              "note": "CRAC cooling setpoint tampered (overheat risk)"})
    return {"unit": p.get("unit", "CRAC-3"), "setpoint_c": p.get("temp_c"), "status": "setpoint applied"}


def ups_command(patched, p, emit):
    cmd = p.get("command", "")
    if patched and cmd not in ("STATUS", "SELFTEST"):
        deny(403, "UPS command requires privileged auth")
    if not patched:
        emit({"command": cmd, "note": "unauthenticated UPS shutdown/command"})
    return {"command": cmd, "status": "UPS command accepted"}


def dcim_fetch(patched, p, emit):
    url = p.get("url", "")
    internal = _is_internal(url)
    if patched and (internal or not url.startswith("https://")):
        deny(400, "target not allowed")
    if not patched and internal:
        emit({"url": url, "note": "DCIM SSRF reached internal/metadata resource"})
        return {"url": url, "internal_response": {"bmc_cred": "DUMMY_ADMIN", "note": "SSRF"}}
    return {"url": url, "title": "external asset metadata"}



def dcx_generator(patched, p, emit):
    if patched and p.get("approver_token") != "facilities-approval":
        deny(403, "generator control requires facilities approval")
    if not patched:
        emit({"note": "unauthenticated generator start/stop"})
    return {"status": "ok", "vuln": "DCX-004"}

def dcx_door(patched, p, emit):
    if patched and p.get("authorization") != "Bearer pacs-badge":
        deny(401, "door control requires badge auth")
    if not patched:
        emit({"note": "physical access control door unlock"})
    return {"status": "ok", "vuln": "DCX-005"}


VULNS = [
    Vuln("DCX-001", "/api/crac/setpoint", "POST", "CRAC setpoint tamper",
         "red_objective_success", "objective", crac_setpoint),
    Vuln("DCX-002", "/api/ups/command", "POST", "UPS shutdown unauth",
         "red_objective_success", "objective", ups_command),
    Vuln("DCX-003", "/api/dcim/fetch", "POST", "DCIM SSRF",
         "red_attack_started", "lateral_movement", dcim_fetch),
    Vuln("DCX-004", "/api/generator/control", "POST", "Generator start/stop",
         "red_objective_success", "objective", dcx_generator),
    Vuln("DCX-005", "/api/access/door", "POST", "Access control door unlock",
         "red_attack_started", "lateral_movement", dcx_door),
]

app = make_ics_twin("datacenter_bms", "Data Center UPS/CRAC/DCIM Twin", VULNS)

# 실제 Modbus/TCP(P1-1) — 랙 온도. HR0=RACK_TEMP(°C)·HR2=ACTUAL·HR4=DAMAGE. coil0=열 인터록.
# CRAC 설정 변조로 열 인터록 우회 + 과열(>35°C) 지속 → 열 폭주/장비 손상(asset_compromised).
from shared.ics.twin_modbus import attach_modbus_ics, ModbusIcsConfig  # noqa: E402
from shared.ics.safety import SafetyProfile  # noqa: E402
from shared.ics.anomaly import IcsBaseline, RegBand  # noqa: E402
from shared.ics.process_sim import ProcessParams  # noqa: E402
attach_modbus_ics(app, ModbusIcsConfig(
    asset="datacenter_bms", vuln_id="DCX-001", reg_names={0: "RACK_TEMP", 1: "CRAC_LOAD"},
    holding_init=[24, 50], coils_init=[True], cmd_reg=0, actual_reg=2, damage_reg=4, interlock_coil=0,
    safety=SafetyProfile(name="datacenter_bms", limits={0: {"name": "RACK_TEMP", "max": 35}}, interlock_coil=0),
    anomaly=IcsBaseline(name="datacenter_bms", registers={0: RegBand("RACK_TEMP", 18, 35, protected=True)}, safety_coils={0}),
    proc=ProcessParams(slew_rpm_per_s=2, nominal_rpm=0, k_heat=0.0, k_cool=0.0, redline_rpm=35,
                       crit_temp=1e9, damage_rpm_rate=2.0, damage_temp_rate=0.0, failure_threshold=100),
    impact="datacenter_thermal_runaway", defense_label="thermal_interlock_rearmed"))

# 실 IEC 61850 MMS/TCP(§5 실 프로토콜 확장) — 데이터센터 전력공급 변전소 IED(전력계통 보호).
# HTTP 목업(DCX-002 UPS 명령)은 앱계층을, 여기 실 MMS 는 COTP 연결+Initiate+Read(모선전압·
# 선로전류·차단기상태) 정찰을 담당. 미인증 MMS Read/Initiate → DCX-002 이벤트 + SIEM 기록.
from shared.ics.twin_iec61850 import attach_iec61850  # noqa: E402
attach_iec61850(app, asset="datacenter_bms", vuln_id="DCX-002")

# ---------------------------------------------------------------------------
# 실 BACnet/IP (§5 실 프로토콜 확장, Tier-3) — 빌딩 자동화(BMS/HVAC)의 사실상 표준.
# WriteProperty 로 CRAC 냉방 설정치(Analog Output present-value)를 무단 상향 → 과열 유도(DCX-001).
# 전송은 트윈 관례(HTTP-sim)를 따르되, 실 인코더(shared/ics/bacnet)로 APDU 를 만들어 자체
# 파서로 왕복 디코드한 정보를 SIEM access 로그(raw.protocol=bacnet)로 흘려 Blue 탐지를 성립시킨다.
# ---------------------------------------------------------------------------
import json as _json  # noqa: E402
import time as _time  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from shared.event_client import emit_event as _emit_event  # noqa: E402
from shared.event_schema import Event as _Event, EventType as _EventType, RedPhase as _RedPhase  # noqa: E402
from shared.siem_access_log import get_siem_logger as _get_siem_logger  # noqa: E402
from shared.ics.bacnet import (build_write_property as _bac_write, parse_apdu as _bac_parse,  # noqa: E402
                               OBJ_ANALOG_OUTPUT, PROP_PRESENT_VALUE)

_BAC_ASSET = "datacenter_bms"
_bac_siem = _get_siem_logger(_BAC_ASSET)


class BacnetWrite(BaseModel):
    instance: int = 3               # AO 인스턴스(예: CRAC-3 냉방 설정치)
    setpoint_c: float = 30.0        # 무단 상향된 냉방 설정치(과열 유도)
    priority: int = 8


@app.post("/api/bacnet/write-property")
def bacnet_write_property(req: BacnetWrite):
    """BACnet WriteProperty 로 CRAC 냉방 설정치(AO present-value) 무단 변조 → 과열 유도."""
    value = str(req.setpoint_c).encode()          # OctetString 값(합성 표현)
    frame = _bac_write(OBJ_ANALOG_OUTPUT, req.instance, value, prop=PROP_PRESENT_VALUE,
                       priority=req.priority)
    _bac_parse(frame)                             # 왕복 파싱(정직성: 자체 디섹션 가능 확인)
    try:
        _bac_siem.info(_json.dumps({
            "ts": _time.time(), "asset": _BAC_ASSET, "method": "BACNET",
            "endpoint": "/bacnet/writeproperty/AO", "status": 200, "vuln_id": "DCX-001",
            "team_id": "default", "trace_id": _Event.session_trace_id("bacnet", _BAC_ASSET),
            "protocol": "bacnet", "service": "WriteProperty",
            "object": f"AO:{req.instance}", "prop": "present-value",
            "setpoint_c": req.setpoint_c, "ics_technique": "T0836"}))
    except Exception:
        pass
    try:
        _emit_event(
            event_id=_Event.make_id("bacnet", _BAC_ASSET, "DCX-001", str(req.instance), str(_time.time())),
            event_type=_EventType.red_attack_started, actor="red", target_asset=_BAC_ASSET,
            vuln_id="DCX-001", phase=_RedPhase.lateral_movement, team_id="default",
            trace_id=_Event.session_trace_id("bacnet", _BAC_ASSET),
            metadata={"protocol": "bacnet", "service": "WriteProperty",
                      "object": f"AnalogOutput:{req.instance}", "setpoint_c": req.setpoint_c,
                      "priority": req.priority, "ics_technique": "T0836",
                      "note": "unauthenticated BACnet WriteProperty to cooling setpoint"})
    except Exception:
        pass
    return {"protocol": "bacnet", "service": "WriteProperty",
            "object": f"AnalogOutput:{req.instance}", "setpoint_c": req.setpoint_c,
            "frame_hex": frame.hex()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8207)
