"""
ICS Modbus 탐지 파이프라인(P1-1 red→blue) 계약 고정.
트윈이 흘린 Modbus SIEM 로그 라인 → 파서 → DetectionEngine → 규칙 매칭(→ blue_detection_success).
실제 엔진·실제 트윈 파서를 통과시켜 탐지가 성립함을 못박는다(파일 테일러/HTTP push 는 인프라).
"""
import glob
import json
import time
from pathlib import Path

import yaml

from services.siem.detection.engine import Rule, DetectionEngine
from services.siem.parsers.twin import parse_twin_log_line

_RULES_DIR = Path(__file__).resolve().parents[2] / "services" / "siem" / "detection" / "rules"


def _load_yaml_rules() -> list[Rule]:
    """실제 rules/*.yaml 을 로드해 규칙 파일 자체(스키마·raw.protocol 매칭)를 검증한다.
    api/main.py::_load_rules 와 동일한 매핑을 사용(글롭으로 모든 *.yaml 자동 수집)."""
    rules: list[Rule] = []
    for path in sorted(glob.glob(str(_RULES_DIR / "*.yaml"))):
        with open(path) as f:
            docs = yaml.safe_load(f) or []
        for d in docs:
            rules.append(Rule(
                id=d["id"], title=d["title"], severity=d["severity"],
                mitre=d.get("mitre", []), source_type=d.get("source_type"),
                kind=d.get("kind", "match"), match=d.get("match"),
                sequence_steps=d.get("sequence_steps"),
                sequence_group_by=d.get("sequence_group_by", "src.ip"),
                sequence_within_sec=d.get("sequence_within_sec", 300),
            ))
    return rules


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


# === §5 실 프로토콜 확장: 신규 6종 프로토콜 탐지 규칙 검증 ===
# 트윈이 raw.protocol=<값> 으로 흘린 access 로그가 rules/*.yaml 의 match 규칙을 발화시킴을 못박는다.
# (트윈 emit 은 형제 PR 소관 → 여기선 정규화 이벤트를 엔진에 직접 주입해 규칙 발화만 검증.)

def _proto_event(protocol: str, **over):
    """raw.protocol=<protocol> 인 트윈 access 로그 이벤트를 합성.
    parse_twin_log_line 은 원본 JSON 전체를 raw 로 보존하므로 raw.protocol == protocol."""
    line = json.dumps({
        "ts": time.time(), "asset": "grid_rtu", "method": "ICS",
        "endpoint": f"/{protocol}/cmd", "status": 200, "protocol": protocol,
        "src_ip": "10.9.9.9", "team_id": "default", "trace_id": "tr-proto", **over})
    ev = parse_twin_log_line(line)
    assert ev is not None
    dumped = ev.model_dump(mode="json")
    assert dumped["raw"]["protocol"] == protocol  # 계약: raw.protocol 경로가 실제로 존재
    return dumped


# (프로토콜 값, 발화해야 하는 규칙 id) — SHARED CONTRACT 의 정확한 철자 사용.
_PROTO_RULE = [
    ("iec104", "ICS-IEC104-SINGLE-COMMAND"),
    ("goose", "ICS-GOOSE-SPOOF-TRIP"),
    ("bacnet", "ICS-BACNET-WRITEPROP"),
    ("enip", "ICS-ENIP-CIP-SETATTR"),
    ("mqtt", "ICS-MQTT-SPARKPLUG-DCMD"),
    ("ff_h1", "ICS-FF-H1-MODE-OOS"),
]


def test_new_proto_rules_load_from_yaml():
    # 신규 규칙 6종이 실제 rules/*.yaml 에서 로드되는지(글롭 자동수집) 확인.
    loaded = {r.id for r in _load_yaml_rules()}
    for _proto, rid in _PROTO_RULE:
        assert rid in loaded, f"{rid} 규칙이 YAML 로 로드되지 않음"


def test_each_new_proto_event_fires_its_rule():
    engine = DetectionEngine(_load_yaml_rules())
    for proto, rid in _PROTO_RULE:
        ids = _ids(engine.evaluate(_proto_event(proto)))
        assert rid in ids, f"raw.protocol={proto} 인데 {rid} 미발화 (fired={ids})"


def test_new_proto_rules_have_ics_mitre_and_twin_source():
    # 규칙 품질 계약: source_type=twin, ICS ATT&CK(T0xxx), 심각도 1~5.
    by_id = {r.id: r for r in _load_yaml_rules()}
    for _proto, rid in _PROTO_RULE:
        r = by_id[rid]
        assert r.source_type == "twin"
        assert r.mitre and all(m.startswith("T0") for m in r.mitre), r.mitre
        assert 1 <= r.severity <= 5


def test_wrong_protocol_does_not_fire_other_proto_rule():
    # goose 이벤트가 iec104 규칙을 발화시키면 안 됨(정확 매칭).
    engine = DetectionEngine(_load_yaml_rules())
    ids = _ids(engine.evaluate(_proto_event("goose")))
    assert "ICS-GOOSE-SPOOF-TRIP" in ids
    assert "ICS-IEC104-SINGLE-COMMAND" not in ids


def test_substation_killchain_sequence_fires():
    # 변전소 킬체인: 같은 src.ip 가 iec61850 MMS 정찰 후 위조 GOOSE 트립 → 시퀀스 발화.
    engine = DetectionEngine(_load_yaml_rules())
    engine.evaluate(_proto_event("iec61850", src_ip="10.7.7.7", endpoint="/iec61850/read"))
    ids = _ids(engine.evaluate(_proto_event("goose", src_ip="10.7.7.7")))
    assert "ICS-SUBSTATION-KILLCHAIN-SEQ-001" in ids
