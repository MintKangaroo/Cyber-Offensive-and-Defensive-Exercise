"""
ICS Modbus 탐지 파이프라인(P1-1 red→blue) 계약 고정.
트윈이 흘린 Modbus SIEM 로그 라인 → 파서 → DetectionEngine → 규칙 매칭(→ blue_detection_success).
실제 엔진·실제 트윈 파서를 통과시켜 탐지가 성립함을 못박는다(파일 테일러/HTTP push 는 인프라).
"""
import json
import time

from services.siem.detection.engine import Rule, DetectionEngine
from services.siem.parsers.twin import parse_twin_log_line


def _ics_rules():
    return [
        Rule(id="ICS-MODBUS-WRITE-PP", title="Modbus write PP", severity=4,
             mitre=["T0836", "T0855"], source_type="twin", kind="match", match={"vuln_id": "PP-006"}),
        Rule(id="ICS-MODBUS-WRITE-WU", title="Modbus write WU", severity=5,
             mitre=["T0836", "T0855"], source_type="twin", kind="match", match={"vuln_id": "WTR-001"}),
        Rule(id="ICS-SAFETY-INTERLOCK-SUPPRESS", title="Interlock suppress", severity=5,
             mitre=["T0878"], source_type="twin", kind="match", match={"raw.ics_technique": "~T0878"}),
    ]


def _event(**over):
    line = json.dumps({
        "ts": time.time(), "asset": "power_plant", "method": "MODBUS",
        "endpoint": "/modbus/register/TURBINE_RPM", "status": 200, "vuln_id": "PP-006",
        "team_id": "default", "trace_id": "tr-1",
        "ics_technique": "T0836 (Modify Parameter)", **over})
    ev = parse_twin_log_line(line)
    assert ev is not None
    return ev.model_dump(mode="json")


def _ids(alerts):
    return {a.rule_id for a in alerts}


def test_modbus_register_write_detected():
    alerts = DetectionEngine(_ics_rules()).evaluate(_event())
    assert "ICS-MODBUS-WRITE-PP" in _ids(alerts)


def test_interlock_suppression_detected_with_technique():
    ev = _event(endpoint="/modbus/interlock/SAFETY_INTERLOCK",
                ics_technique="T0878 (Suppression of Alarms/Interlock)")
    ids = _ids(DetectionEngine(_ics_rules()).evaluate(ev))
    assert "ICS-SAFETY-INTERLOCK-SUPPRESS" in ids and "ICS-MODBUS-WRITE-PP" in ids


def test_water_utility_modbus_detected():
    ev = _event(asset="water_utility", vuln_id="WTR-001", register="CHLORINE_PPM")
    assert "ICS-MODBUS-WRITE-WU" in _ids(DetectionEngine(_ics_rules()).evaluate(ev))


def test_detection_carries_trace_id_for_dwell_time():
    # blue_detection_success 의 matched_event_id = event.trace_id (dwell time 상관). 파서가 보존해야.
    ev = _event()
    assert ev["trace_id"] == "tr-1" and ev["vuln_id"] == "PP-006"


def test_benign_twin_event_not_ics_detected():
    ev = _event(vuln_id="PP-003", ics_technique=None, endpoint="/api/diag")
    assert not any(rid.startswith("ICS-") for rid in _ids(DetectionEngine(_ics_rules()).evaluate(ev)))
