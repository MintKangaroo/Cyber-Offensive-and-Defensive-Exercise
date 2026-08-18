"""
실 DNP3 아웃스테이션(shared/ics/dnp3.py) 단위 테스트 — §5 실 프로토콜 확장
============================================================================
- CRC: 문서화된 reset-link 프레임 벡터와 일치(스펙 정합 = 실 마스터 상호운용).
- 데이터링크 프레임 인코드/디코드 라운드트립 + CRC 손상 탐지.
- 응용: READ → Group30Var2 아날로그 응답, DIRECT_OPERATE CROB → 바이너리 출력 제어.
"""
import struct

from shared.ics import dnp3


def test_crc_known_vector():
    # 표준 reset-link 프레임 헤더의 CRC는 0x21E9(저장 LE = E9 21). IEEE 1815 예시와 일치.
    header = bytes([0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04])
    assert dnp3.dnp3_crc(header) == 0x21E9
    assert struct.pack("<H", dnp3.dnp3_crc(header)) == bytes([0xE9, 0x21])


def test_frame_roundtrip():
    user = b"\xC0\x01hello-dnp3-payload-over-16-bytes!!"
    frame = dnp3.encode_frame(0xC4, dest=4, source=1, user_data=user)
    assert frame[:2] == b"\x05\x64"
    pf = dnp3.parse_frame(frame)
    assert pf is not None
    assert pf.dest == 4 and pf.source == 1
    assert pf.user_data == user


def test_crc_corruption_detected():
    frame = bytearray(dnp3.encode_frame(0xC4, 4, 1, b"\xC0\x01abc"))
    frame[4] ^= 0xFF          # destination 바이트 훼손 → 헤더 CRC 불일치
    assert dnp3.parse_frame(bytes(frame)) is None


def test_read_request_response_roundtrip():
    os = dnp3.Dnp3Outstation(analog_inputs=[3000, -50, 120, 0, 500, 0, 0, 0])
    req = dnp3.build_read_request(dest=os.address, source=1)
    pf = dnp3.parse_frame(req)
    resp_app = dnp3.handle_app_fragment(os, pf.user_data)
    resp_frame = dnp3.encode_frame(0x44, pf.source, os.address, resp_app)
    vals = dnp3.parse_read_response(resp_frame)
    assert vals == [3000, -50, 120, 0, 500, 0, 0, 0]


def test_direct_operate_crob_controls_binary_output():
    operated = []
    os = dnp3.Dnp3Outstation()
    os.on_operate = lambda idx, on: operated.append((idx, on))
    # index 2 LATCH_ON
    req = dnp3.build_direct_operate_crob(dest=os.address, index=2, latch_on=True)
    pf = dnp3.parse_frame(req)
    resp = dnp3.handle_app_fragment(os, pf.user_data)
    assert os.binary_outputs[2] is True
    assert operated == [(2, True)]
    assert resp[1] == dnp3.FC_RESPONSE
    # LATCH_OFF
    req2 = dnp3.build_direct_operate_crob(dest=os.address, index=2, latch_on=False)
    pf2 = dnp3.parse_frame(req2)
    dnp3.handle_app_fragment(os, pf2.user_data)
    assert os.binary_outputs[2] is False


def test_unsupported_fc_sets_iin_no_func_support():
    os = dnp3.Dnp3Outstation()
    app = struct.pack("<BB", 0xC0, 0x99)   # 미지원 FC 0x99
    resp = dnp3.handle_app_fragment(os, app)
    assert resp[1] == dnp3.FC_RESPONSE
    iin = struct.unpack("<H", resp[2:4])[0]
    assert iin & (0x01 << 8)               # IIN2.1 no func code support


def test_dnp3_control_detection_rule_fires():
    """SIEM DNP3 제어 탐지 룰(raw.protocol=dnp3)이 발화하는지(§5 attack↔detect 완결)."""
    from services.siem.detection.engine import Rule, DetectionEngine
    rule = Rule(id="ICS-DNP3-CONTROL-PP", title="dnp3", severity=5, mitre=["T0855"],
                source_type="twin", kind="match", match={"raw.protocol": "dnp3"})
    eng = DetectionEngine([rule])
    # DNP3 제어 이벤트(정규화된 twin 이벤트, raw에 protocol 보존)
    ev = {"source_type": "twin", "vuln_id": "PP-006", "asset": "power_plant",
          "raw": {"protocol": "dnp3", "endpoint": "/dnp3/direct_operate/interlock"}}
    alerts = eng.evaluate(ev)
    assert any(a.rule_id == "ICS-DNP3-CONTROL-PP" for a in alerts)
    # Modbus(HTTP) 활동엔 미발화(오탐 방지)
    ev2 = {"source_type": "twin", "vuln_id": "PP-006", "raw": {"protocol": "modbus"}}
    assert not any(a.rule_id == "ICS-DNP3-CONTROL-PP" for a in eng.evaluate(ev2))
