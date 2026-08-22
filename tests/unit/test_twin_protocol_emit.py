"""
Tier-3 ICS 프로토콜 트윈 배출 계약 고정 (feat/ics-twin-protocol-emit)
=====================================================================
6개 신규 ICS 프로토콜(iec104/goose/bacnet/enip/mqtt/ff_h1)을 실 트윈 런타임에 배선했다.
각 트윈의 신규 엔드포인트 핸들러가 SIEM access 로그로 흘리는 라인이
  - 실 트윈 파서(parse_twin_log_line)를 통과해 raw.protocol=<정규 태그> 로 정규화되고
  - 그 태그를 키로 하는 탐지 규칙(match: {raw.protocol: <태그>})이 실제로 발화하는지
를 못박는다. 태그 문자열은 SIEM 탐지 규칙과 공유되는 계약이므로 정확히 일치해야 한다.

emit_event 는 네트워크 의존이라 no-op 로 대체(테스트 격리·속도). 핸들러를 HTTP 없이 직접
호출하고, siem_access.<asset> 로거에 캡처 핸들러를 붙여 배출 라인을 수집한다.
"""
import json
import logging

import pytest

from services.siem.detection.engine import Rule, DetectionEngine
from services.siem.parsers.twin import parse_twin_log_line

# SIEM 탐지 규칙과 공유되는 정규 프로토콜 태그(계약). 오타/이표기 금지.
CANONICAL_TAGS = {"iec104", "goose", "bacnet", "enip", "mqtt", "ff_h1"}


class _Capture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def _capture(asset: str) -> _Capture:
    cap = _Capture()
    logging.getLogger(f"siem_access.{asset}").addHandler(cap)
    return cap


def _protocol_line(cap: _Capture) -> dict:
    """캡처된 라인 중 'protocol' 키를 가진 SIEM 라인을 파싱해 반환."""
    for raw in cap.lines:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if "protocol" in data:
            return data
    raise AssertionError(f"no protocol-tagged SIEM line captured: {cap.lines}")


# (asset, emit 속성명, 핸들러 호출자) — 호출자는 import 된 모듈을 받아 핸들러를 실행한다.
def _pp_iec104(m):
    return m.iec104_command(m.Iec104Command())


def _pp_goose(m):
    return m.goose_publish(m.GooseTrip())


def _dcx_bacnet(m):
    return m.bacnet_write_property(m.BacnetWrite())


def _ref_ffh1(m):
    return m.ffh1_write(m.FfH1Write())


def _fac_enip(m):
    return m.enip_cip(m.EnipCip())


def _fac_mqtt(m):
    return m.mqtt_command(m.MqttCommand())


CASES = [
    ("iec104", "services.power_plant.main", "power_plant", "emit_event", _pp_iec104, "PP-006"),
    ("goose", "services.power_plant.main", "power_plant", "emit_event", _pp_goose, "PP-006"),
    ("bacnet", "services.datacenter_bms.main", "datacenter_bms", "_emit_event", _dcx_bacnet, "DCX-001"),
    ("ff_h1", "services.refinery_plant.main", "refinery_plant", "_emit_event", _ref_ffh1, "REF-004"),
    ("enip", "services.smart_factory.main", "smart_factory", "_emit_event", _fac_enip, "FAC-004"),
    ("mqtt", "services.smart_factory.main", "smart_factory", "_emit_event", _fac_mqtt, "FAC-002"),
]


def _run(module_path, asset, emit_attr, caller, monkeypatch):
    import importlib
    m = importlib.import_module(module_path)
    monkeypatch.setattr(m, emit_attr, lambda **kw: None)  # 네트워크 의존 제거
    cap = _capture(asset)
    caller(m)
    return _protocol_line(cap)


@pytest.mark.parametrize("tag,module_path,asset,emit_attr,caller,vuln_id", CASES)
def test_emission_normalizes_to_raw_protocol(tag, module_path, asset, emit_attr, caller, vuln_id, monkeypatch):
    """핸들러 배출 → 실 트윈 파서 → raw.protocol=<정규 태그> + vuln_id 보존."""
    data = _run(module_path, asset, emit_attr, caller, monkeypatch)
    assert tag in CANONICAL_TAGS
    assert data["protocol"] == tag
    ev = parse_twin_log_line(json.dumps(data))
    assert ev is not None
    assert ev.raw["protocol"] == tag              # SIEM 정규화 형태에서 raw.protocol 로 도달
    assert ev.raw["vuln_id"] == vuln_id
    assert ev.source_type == "twin"


@pytest.mark.parametrize("tag,module_path,asset,emit_attr,caller,vuln_id", CASES)
def test_detection_rule_fires_on_protocol_tag(tag, module_path, asset, emit_attr, caller, vuln_id, monkeypatch):
    """match:{raw.protocol:<태그>} 규칙이 배출 이벤트에 실제로 발화한다(sibling 규칙 소비자 계약)."""
    data = _run(module_path, asset, emit_attr, caller, monkeypatch)
    ev = parse_twin_log_line(json.dumps(data))
    rule = Rule(id=f"ICS-{tag.upper()}-TEST", title=f"{tag} access", severity=4,
                mitre=["T0855"], source_type="twin", kind="match",
                match={"raw.protocol": tag})
    alerts = DetectionEngine([rule]).evaluate(ev.model_dump(mode="json"))
    assert {a.rule_id for a in alerts} == {f"ICS-{tag.upper()}-TEST"}


def test_all_six_tags_covered():
    """6개 신규 프로토콜 태그가 모두 케이스로 커버되는지(회귀 방지)."""
    assert {c[0] for c in CASES} == CANONICAL_TAGS
