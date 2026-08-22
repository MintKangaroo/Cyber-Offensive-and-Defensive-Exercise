"""
Smart Factory Digital Twin (스마트팩토리 트윈)
==============================================
PLC + Robot + MES + Conveyor 를 모사. 프로토콜: Profinet / S7 / OPC UA.
Vendor 예시: Siemens/Rockwell/Mitsubishi. 훈련용 시뮬레이션(더미 값).

취약점:
  FAC-001 PLC Program Download    (POST /api/plc/program-download) — 미인증 PLC 프로그램 다운로드(ICS)
  FAC-002 Robot Command Injection (POST /api/robot/exec)           — 로봇 컨트롤러 임의 명령
  FAC-003 MES Work-Order SQLi     (GET  /api/mes/workorder)        — MES 작업지시 SQL 인젝션
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402

WORKORDERS = {"1001": "Line-A Bracket x500", "1002": "Line-B Gearbox x120"}


def plc_program_download(patched, p, emit):
    if patched and p.get("authorization") != "Bearer engineering-station-token":
        deny(401, "PLC program download requires engineering workstation auth")
    if not patched:
        emit({"plc": p.get("plc", "S7-1500"), "block": p.get("block", "OB1"),
              "note": "unauthenticated PLC program (logic) download"})
    return {"plc": p.get("plc", "S7-1500"), "status": "program block downloaded to controller"}


def robot_exec(patched, p, emit):
    cmd = p.get("command", "")
    if patched and cmd not in ("HOME", "PAUSE", "STATUS"):
        deny(403, "robot command not in allowlist")
    if not patched:
        emit({"command": cmd, "note": "arbitrary robot controller command"})
    return {"command": cmd, "status": "executed on robot controller"}


def mes_workorder(patched, p, emit):
    wid = p.get("id", "")
    if patched:
        row = WORKORDERS.get(str(wid))
        return {"id": wid, "workorder": row} if row else deny(404, "not found")
    # 취약: id를 쿼리에 문자열 결합 -> ' OR '1'='1 로 전체 덤프
    if "'" in wid or "or" in wid.lower() or "union" in wid.lower():
        emit({"id_input": wid, "note": "MES work-order SQL injection"})
        return {"id": wid, "workorders": WORKORDERS, "note": "injection returned all rows"}
    return {"id": wid, "workorder": WORKORDERS.get(str(wid))}



def fac_robot_estop(patched, p, emit):
    if patched and p.get("approver_token") != "safety-plc-approval":
        deny(403, "robot E-stop override requires safety PLC approval")
    if not patched:
        emit({"note": "robot emergency-stop override without approval"})
    return {"status": "ok", "vuln": "FAC-004"}

def fac_recipe_sqli(patched, p, emit):
    if patched and p.get("authorization") != "Bearer mes-token":
        deny(404, "recipe not found (parameterized query)")
    if not patched:
        emit({"note": "MES recipe SQL injection"})
    return {"status": "ok", "vuln": "FAC-005"}


VULNS = [
    Vuln("FAC-001", "/api/plc/program-download", "POST", "PLC program download",
         "red_attack_started", "lateral_movement", plc_program_download),
    Vuln("FAC-002", "/api/robot/exec", "POST", "Robot command injection",
         "red_attack_started", "privilege_escalation", robot_exec),
    Vuln("FAC-003", "/api/mes/workorder", "GET", "MES work-order SQLi",
         "flag_exfiltrated", "data_exfiltration", mes_workorder),
    Vuln("FAC-004", "/api/robot/estop-override", "POST", "Robot E-stop override",
         "red_objective_success", "objective", fac_robot_estop),
    Vuln("FAC-005", "/api/recipe/get", "GET", "MES recipe SQL injection",
         "red_attack_started", "lateral_movement", fac_recipe_sqli),
]

app = make_ics_twin("smart_factory", "Smart Factory PLC/Robot/MES Twin", VULNS)

# 실제 Modbus/TCP(P1-1) — 로봇 속도. HR0=ROBOT_SPEED(%)·HR2=ACTUAL·HR4=DAMAGE. coil0=E-STOP.
# E-stop 우회 + 과속(>100%) 지속 → 로봇 충돌/부상(asset_compromised).
from shared.ics.twin_modbus import attach_modbus_ics, ModbusIcsConfig  # noqa: E402
from shared.ics.safety import SafetyProfile  # noqa: E402
from shared.ics.anomaly import IcsBaseline, RegBand  # noqa: E402
from shared.ics.process_sim import ProcessParams  # noqa: E402
attach_modbus_ics(app, ModbusIcsConfig(
    asset="smart_factory", vuln_id="FAC-004", reg_names={0: "ROBOT_SPEED", 1: "PAYLOAD"},
    holding_init=[60, 20], coils_init=[True], cmd_reg=0, actual_reg=2, damage_reg=4, interlock_coil=0,
    safety=SafetyProfile(name="smart_factory", limits={0: {"name": "ROBOT_SPEED", "max": 100}}, interlock_coil=0),
    anomaly=IcsBaseline(name="smart_factory", registers={0: RegBand("ROBOT_SPEED", 0, 100, protected=True)}, safety_coils={0}),
    proc=ProcessParams(slew_rpm_per_s=20, nominal_rpm=0, k_heat=0.0, k_cool=0.0, redline_rpm=100,
                       crit_temp=1e9, damage_rpm_rate=0.5, damage_temp_rate=0.0, failure_threshold=100),
    impact="robot_collision_injury", defense_label="estop_rearmed"))

# 실 S7comm/TCP(§5 실 프로토콜 확장) — Siemens S7 PLC. HTTP 목업(FAC-001 프로그램 다운로드)은
# 앱계층을, 여기 실 S7은 COTP 연결+Read Var(DB 워드) 정찰을 담당. DB1: 컨베이어속도·생산카운트·
# 로봇상태·라인온도 등(더미 PLC 메모리). 미인증 S7 Read → FAC-001 이벤트+SIEM.
from shared.ics.twin_s7 import attach_s7  # noqa: E402
attach_s7(app, asset="smart_factory", vuln_id="FAC-001",
          db_init=[60, 500, 1, 42, 0, 0, 0, 0])
# 실 Profinet DCP(audit §5) — 팩토리 자동화 발견 계층. S7(102)/Modbus(502)와 별개 포트 34964.
# DCP Identify/Get = 미인증 디바이스 발견(recon) → SIEM(protocol=profinet)+red 이벤트.
from shared.ics.twin_profinet import attach_profinet  # noqa: E402
from shared.ics.profinet import ProfinetDevice  # noqa: E402
attach_profinet(app, asset="smart_factory", vuln_id="FAC-001",
                device=ProfinetDevice(station_name="plc-line-a", vendor_id=0x002A,
                                      device_id=0x0301, ip="10.20.0.11",
                                      vendor_value="Siemens S7-1500 PN/IE"))

# ---------------------------------------------------------------------------
# 실 EtherNet/IP+CIP / MQTT+Sparkplug B (§5 실 프로토콜 확장, Tier-3) — 이산 제조 IIoT.
# 전송은 트윈 관례(HTTP-sim)를 따르되, 실 인코더(shared/ics/enip·mqtt_sparkplug)로 프레임을
# 만들어 자체 파서로 왕복 디코드한 명령 정보를 SIEM access 로그(raw.protocol=enip|mqtt)로 흘려
# Blue 탐지를 성립시킨다. 둘 다 무인증(insecure-by-design) 산업 이더넷/브로커 프로토콜이다.
# ---------------------------------------------------------------------------
import json as _json  # noqa: E402
import time as _time  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from shared.event_client import emit_event as _emit_event  # noqa: E402
from shared.event_schema import Event as _Event, EventType as _EventType, RedPhase as _RedPhase  # noqa: E402
from shared.siem_access_log import get_siem_logger as _get_siem_logger  # noqa: E402
from shared.ics.enip import (build_cip_request as _cip_req, build_sendrrdata as _enip_send,  # noqa: E402
                             parse_sendrrdata as _enip_parse, SVC_SET_ATTR_SINGLE)
from shared.ics.mqtt_sparkplug import (build_sparkplug_payload as _spb_payload,  # noqa: E402
                                       build_publish as _mqtt_publish, parse_publish as _mqtt_parse)

_FAC_ASSET = "smart_factory"
_fac_siem = _get_siem_logger(_FAC_ASSET)


class EnipCip(BaseModel):
    class_id: int = 0x28        # 드라이브/모션 관련 예시 CIP 클래스
    instance: int = 1
    attribute: int = 3          # 속도/설정 속성
    value: int = 150            # 무단 설정치(과속 유도)


@app.post("/api/enip/cip")
def enip_cip(req: EnipCip):
    """EtherNet/IP CIP SetAttributeSingle 로 드라이브/모션 속성 무단 쓰기(제어 조작)."""
    data = int(req.value).to_bytes(2, "little")
    cip = _cip_req(SVC_SET_ATTR_SINGLE, req.class_id, req.instance, req.attribute, data)
    frame = _enip_send(cip)
    parsed = _enip_parse(frame)
    try:
        _fac_siem.info(_json.dumps({
            "ts": _time.time(), "asset": _FAC_ASSET, "method": "ENIP",
            "endpoint": "/enip/cip/set_attr_single", "status": 200, "vuln_id": "FAC-004",
            "team_id": "default", "trace_id": _Event.session_trace_id("enip", _FAC_ASSET),
            "protocol": "enip", "service": "SetAttributeSingle",
            "class": parsed.class_id if parsed else req.class_id,
            "instance": parsed.instance if parsed else req.instance,
            "attribute": parsed.attribute if parsed else req.attribute, "ics_technique": "T0836"}))
    except Exception:
        pass
    try:
        _emit_event(
            event_id=_Event.make_id("enip", _FAC_ASSET, "FAC-004", str(req.class_id), str(_time.time())),
            event_type=_EventType.red_attack_started, actor="red", target_asset=_FAC_ASSET,
            vuln_id="FAC-004", phase=_RedPhase.lateral_movement, team_id="default",
            trace_id=_Event.session_trace_id("enip", _FAC_ASSET),
            metadata={"protocol": "enip", "service": "SetAttributeSingle",
                      "class": req.class_id, "instance": req.instance, "attribute": req.attribute,
                      "value": req.value, "ics_technique": "T0836",
                      "note": "unauthenticated EtherNet/IP CIP attribute write to drive"})
    except Exception:
        pass
    return {"protocol": "enip", "service": "SetAttributeSingle", "class": req.class_id,
            "instance": req.instance, "attribute": req.attribute, "value": req.value,
            "frame_hex": frame.hex()}


class MqttCommand(BaseModel):
    group: str = "Line-A"
    node: str = "robot-1"
    metric: str = "Robot/Speed"
    value: int = 150           # 무단 명령값(로봇 속도 등)


@app.post("/api/mqtt/command")
def mqtt_command(req: MqttCommand):
    """Sparkplug B DCMD PUBLISH 로 IIoT 디바이스에 무단 명령(로봇 속도 등) 하달."""
    topic = f"spBv1.0/{req.group}/DCMD/{req.node}"
    body = int(req.value).to_bytes(4, "big")
    payload = _spb_payload(req.metric, body)
    packet = _mqtt_publish(topic, payload)
    parsed = _mqtt_parse(packet)
    try:
        _fac_siem.info(_json.dumps({
            "ts": _time.time(), "asset": _FAC_ASSET, "method": "MQTT",
            "endpoint": "/mqtt/publish/DCMD", "status": 200, "vuln_id": "FAC-002",
            "team_id": "default", "trace_id": _Event.session_trace_id("mqtt", _FAC_ASSET),
            "protocol": "mqtt", "mqtt_type": "PUBLISH",
            "topic": parsed.topic if parsed else topic,
            "metric": parsed.metric if parsed else req.metric, "ics_technique": "T0855"}))
    except Exception:
        pass
    try:
        _emit_event(
            event_id=_Event.make_id("mqtt", _FAC_ASSET, "FAC-002", req.node, str(_time.time())),
            event_type=_EventType.red_attack_started, actor="red", target_asset=_FAC_ASSET,
            vuln_id="FAC-002", phase=_RedPhase.lateral_movement, team_id="default",
            trace_id=_Event.session_trace_id("mqtt", _FAC_ASSET),
            metadata={"protocol": "mqtt", "mqtt_type": "PUBLISH", "topic": topic,
                      "sparkplug": "DCMD", "metric": req.metric, "value": req.value,
                      "ics_technique": "T0855",
                      "note": "unauthenticated Sparkplug B DCMD command to IIoT device"})
    except Exception:
        pass
    return {"protocol": "mqtt", "mqtt_type": "PUBLISH", "topic": topic,
            "metric": req.metric, "value": req.value, "packet_hex": packet.hex()}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8202)
