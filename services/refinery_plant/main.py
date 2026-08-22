"""
Refinery / Petrochemical Plant Digital Twin (정유·석유화학 플랜트 트윈)
=====================================================================
DCS + SIS(Safety Instrumented System) + Tank Farm 을 모사. 프로토콜: OPC UA / Modbus / HART.
훈련용 시뮬레이션 — 실제 플랜트/장비와 무관하며 모든 값은 더미다.

취약점:
  REF-001 OPC UA Anonymous Read    (GET  /api/opcua/read)      — 미인증 DCS 태그 열람
  REF-002 SIS Safety Bypass        (POST /api/sis/bypass)      — 안전계장 트립 무단 우회(ICS)
  REF-003 HART Tank Gauge Spoof    (POST /api/tankfarm/gauge)  — 탱크 레벨 위조(오버필 유도)
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402

TAGS = {
    "ns=2;s=CDU.Furnace.TempC": 385.0,
    "ns=2;s=SIS.HH_Trip.Setpoint": 420.0,   # 안전 계장 트립 설정치(민감)
    "ns=2;s=TankFarm.T101.LevelPct": 63.2,
}


def opcua_read(patched, p, emit):
    if patched and p.get("token") != "opcua-signed-session":
        deny(401, "OPC UA anonymous access disabled; signed session required")
    node = p.get("node", "")
    if not patched:
        emit({"node": node, "note": "anonymous OPC UA read of DCS/SIS tags"})
    return {"node": node, "value": TAGS.get(node, "unknown-node"), "tags": TAGS}


def sis_bypass(patched, p, emit):
    if patched and p.get("approver_token") != "sis-4eyes-approval":
        deny(403, "SIS bypass requires 2-person (4-eyes) approval")
    if not patched:
        emit({"function": "SIS_HH_TRIP", "note": "safety instrumented trip bypassed without approval"})
    return {"sis_trip_enabled": False, "status": "safety interlock bypassed"}


def tank_gauge(patched, p, emit):
    if patched and p.get("authorization") != "Bearer engineering-station-token":
        deny(401, "HART write requires engineering workstation auth")
    if not patched:
        emit({"tank": p.get("tank", "T101"), "spoofed_level": p.get("level"), "note": "HART tank gauge spoofed"})
    return {"tank": p.get("tank", "T101"), "level_pct": p.get("level"), "status": "gauge updated"}



def ref_modbus_coil(patched, p, emit):
    if patched and p.get("authorization") != "Bearer eng-station":
        deny(401, "engineering workstation auth required for Modbus write")
    if not patched:
        emit({"note": "unauthenticated Modbus coil write to pump/valve"})
    return {"status": "ok", "vuln": "REF-004"}

def ref_historian_export(patched, p, emit):
    if patched and p.get("token") != "hist-signed":
        deny(403, "export path must be within allowlist")
    if not patched:
        emit({"note": "historian export path traversal (arbitrary file read)"})
    return {"status": "ok", "vuln": "REF-005"}


VULNS = [
    Vuln("REF-001", "/api/opcua/read", "GET", "OPC UA anonymous read",
         "red_attack_started", "initial_access", opcua_read),
    Vuln("REF-002", "/api/sis/bypass", "POST", "SIS safety bypass",
         "red_objective_success", "objective", sis_bypass),
    Vuln("REF-003", "/api/tankfarm/gauge", "POST", "HART tank gauge spoof",
         "red_attack_started", "lateral_movement", tank_gauge),
    Vuln("REF-004", "/api/modbus/coil-write", "POST", "Modbus coil write (pump/valve)",
         "red_objective_success", "objective", ref_modbus_coil),
    Vuln("REF-005", "/api/historian/export", "GET", "Historian export path traversal",
         "red_attack_started", "data_exfiltration", ref_historian_export),
]

app = make_ics_twin("refinery_plant", "Refinery/Petrochemical DCS/SIS Twin", VULNS)

# 실제 Modbus/TCP(P1-1) — 증류탑 압력 제어. HR0=압력설정(bar)·HR1=피드율·HR2=ACTUAL·HR4=DAMAGE.
# coil0=SIS(과압 릴리프 인터록). 인터록 해제 + 과압(>8bar) 지속 → 과압 폭발(asset_compromised).
from shared.ics.twin_modbus import attach_modbus_ics, ModbusIcsConfig  # noqa: E402
from shared.ics.safety import SafetyProfile  # noqa: E402
from shared.ics.anomaly import IcsBaseline, RegBand  # noqa: E402
from shared.ics.process_sim import ProcessParams  # noqa: E402

attach_modbus_ics(app, ModbusIcsConfig(
    asset="refinery_plant", vuln_id="REF-004",
    reg_names={0: "COLUMN_PRESSURE", 1: "FEED_RATE"},
    holding_init=[4, 50], coils_init=[True],
    cmd_reg=0, actual_reg=2, damage_reg=4, interlock_coil=0,
    safety=SafetyProfile(name="refinery_plant",
                         limits={0: {"name": "COLUMN_PRESSURE", "max": 8}}, interlock_coil=0),
    anomaly=IcsBaseline(name="refinery_plant",
                        registers={0: RegBand("COLUMN_PRESSURE", 3, 8, protected=True),
                                   1: RegBand("FEED_RATE", 0, 100)}, safety_coils={0}),
    proc=ProcessParams(slew_rpm_per_s=1, nominal_rpm=0, ambient_temp=0, k_heat=0.0, k_cool=0.0,
                       redline_rpm=8, crit_temp=1e9, damage_rpm_rate=2.0, damage_temp_rate=0.0,
                       failure_threshold=100),
    impact="overpressure_explosion"))

# 실 OPC UA/TCP(§5 실 프로토콜 확장) — DCS/SIS OPC UA 서버(포트 4840). HTTP 목업(REF-001)은
# 앱계층 태그 읽기를, 여기 실 OPC UA는 전송/보안채널 핸드셰이크(정찰·무단 접속)를 담당한다.
from shared.ics.twin_opcua import attach_opcua  # noqa: E402
attach_opcua(app, asset="refinery_plant", vuln_id="REF-001")
# 실 HART-IP(§5 실 프로토콜 확장) — Tank Farm 스마트 트랜스미터(포트 5094, env HART_PORT).
# REF-003 의 HTTP 모킹(/api/tankfarm/gauge)과 나란히, 진짜 HART-IP 로 동적변수를 노출한다.
# PV=탱크레벨(%), SV=온도(°C), TV=압력(bar). 무인증 HART 세션 개시 후 열람 자체가 미인가 접근.
from shared.ics.twin_hart import attach_hart  # noqa: E402

attach_hart(app, asset="refinery_plant", vuln_id="REF-003",
            device_vars={"pv": TAGS["ns=2;s=TankFarm.T101.LevelPct"], "pv_unit": 57,
                         "sv": 25.0, "sv_unit": 32, "tv": 1.2, "tv_unit": 220,
                         "loop_current": 12.0})

# ---------------------------------------------------------------------------
# 실 Foundation Fieldbus H1 (§5 실 프로토콜 확장, Tier-3) — 연속공정 필드버스.
# 정직한 경계: H1 은 IP 가 아닌 31.25kbps 시리얼 버스라 표준 pcap 링크타입이 없다. 여기서는
# 실 DLPDU(FrameControl+노드주소+DLSDU) '구조'만 실제로 인코딩하는 **합성 캡슐화**이며 실장비와
# 무관하다. DLPDU write 로 함수블록 파라미터(밸브/설정치)를 무단 변조 → SIEM access 로그
# (raw.protocol=ff_h1)로 흘려 Blue 탐지를 성립시킨다.
# ---------------------------------------------------------------------------
import json as _json  # noqa: E402
import time as _time  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from shared.event_client import emit_event as _emit_event  # noqa: E402
from shared.event_schema import Event as _Event, EventType as _EventType, RedPhase as _RedPhase  # noqa: E402
from shared.siem_access_log import get_siem_logger as _get_siem_logger  # noqa: E402
from shared.ics.ff_h1 import (build_dlsdu as _ff_dlsdu, build_dlpdu as _ff_dlpdu,  # noqa: E402
                              parse_dlpdu as _ff_parse, FC_DT, OP_WRITE)

_FF_ASSET = "refinery_plant"
_ff_siem = _get_siem_logger(_FF_ASSET)


class FfH1Write(BaseModel):
    block: str = "AI_CDU_Pressure"     # 함수블록(예: 증류탑 압력 AI/PID 루프)
    param: str = "SP"                  # 파라미터(설정치)
    value: str = "9.5"                 # 무단 설정치(과압 유도)
    dest: int = 0x14                   # H1 목적지 노드주소(더미)
    src: int = 0x02                    # H1 출발지 노드주소(더미)


@app.post("/api/ffh1/write")
def ffh1_write(req: FfH1Write):
    """FF-H1 DLPDU write 로 함수블록 파라미터 무단 변조(합성 캡슐화; 프로토콜 구조만 실제)."""
    dlsdu = _ff_dlsdu(OP_WRITE, req.block, req.param, req.value)
    frame = _ff_dlpdu(FC_DT, req.dest, req.src, dlsdu)
    parsed = _ff_parse(frame)
    try:
        _ff_siem.info(_json.dumps({
            "ts": _time.time(), "asset": _FF_ASSET, "method": "FF-H1",
            "endpoint": "/ffh1/dlpdu/write", "status": 200, "vuln_id": "REF-004",
            "team_id": "default", "trace_id": _Event.session_trace_id("ff_h1", _FF_ASSET),
            "protocol": "ff_h1", "op": "WRITE",
            "block": parsed.block if parsed else req.block,
            "param": parsed.param if parsed else req.param,
            "value": parsed.value if parsed else req.value, "ics_technique": "T0836",
            "note": "synthetic FF-H1 encapsulation (structure real, no physical bus)"}))
    except Exception:
        pass
    try:
        _emit_event(
            event_id=_Event.make_id("ff_h1", _FF_ASSET, "REF-004", req.block, str(_time.time())),
            event_type=_EventType.red_attack_started, actor="red", target_asset=_FF_ASSET,
            vuln_id="REF-004", phase=_RedPhase.lateral_movement, team_id="default",
            trace_id=_Event.session_trace_id("ff_h1", _FF_ASSET),
            metadata={"protocol": "ff_h1", "op": "WRITE", "block": req.block,
                      "param": req.param, "value": req.value, "ics_technique": "T0836",
                      "note": "unauthenticated FF-H1 fieldbus write (synthetic encapsulation)"})
    except Exception:
        pass
    return {"protocol": "ff_h1", "op": "WRITE", "block": req.block, "param": req.param,
            "value": req.value, "frame_hex": frame.hex(),
            "note": "synthetic fieldbus (구조만 실제, 실장비 무관)"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8201)
