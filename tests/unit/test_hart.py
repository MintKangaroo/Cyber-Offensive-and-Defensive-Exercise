"""
실 HART-IP 필드 디바이스(shared/ics/hart.py) 단위 테스트 — §5 실 프로토콜 확장
=============================================================================
- HART-IP 헤더 인코드/디코드 라운드트립(필드 패킹 정합 = 실 마스터 상호운용).
- HART 체크섬(XOR) 정확성 + 손상 탐지.
- 세션 개시 응답 + Command 1/3 읽기 라운드트립(순수 함수).
- serve() 라이브 소켓 라운드트립(asyncio, port 0).
- SIEM HART 탐지 룰(raw.protocol=hart) 발화(§5 attack↔detect 완결).
"""
import asyncio
import struct

from shared.ics import hart


def test_hart_ip_header_roundtrip():
    hdr = hart.build_hart_ip_header(hart.MSG_TYPE_REQUEST, hart.MSG_ID_TOKEN_PDU,
                                    seq=0x1234, byte_count=0x000A)
    assert len(hdr) == 8
    # 필드 패킹: version=1, type, id, status=0, seq(2 BE), byte_count(2 BE)
    assert hdr == bytes([1, 0, 3, 0, 0x12, 0x34, 0x00, 0x0A])
    p = hart.parse_hart_ip_header(hdr)
    assert p is not None
    assert (p.version, p.msg_type, p.msg_id, p.status, p.seq, p.byte_count) == \
        (1, hart.MSG_TYPE_REQUEST, hart.MSG_ID_TOKEN_PDU, 0, 0x1234, 0x000A)


def test_hart_header_too_short_returns_none():
    assert hart.parse_hart_ip_header(b"\x01\x00\x03") is None


def test_hart_checksum_known_vector():
    # delimiter 0x02, address 0x00, command 0x01, byte_count 0x00 → XOR = 0x03
    body = bytes([0x02, 0x00, 0x01, 0x00])
    assert hart.hart_checksum(body) == 0x03
    # PDU 는 body + checksum
    pdu = hart.build_hart_pdu(hart.DELIM_STX, 0x00, 0x01, b"")
    assert pdu == body + bytes([0x03])


def test_hart_pdu_roundtrip_and_corruption():
    pdu = hart.build_hart_pdu(hart.DELIM_STX, 0, 3, b"\xDE\xAD\xBE\xEF")
    parsed = hart.parse_hart_pdu(pdu)
    assert parsed is not None
    assert parsed.delimiter == hart.DELIM_STX
    assert parsed.command == 3
    assert parsed.data == b"\xDE\xAD\xBE\xEF"
    # 체크섬 손상 → None
    bad = bytearray(pdu)
    bad[-1] ^= 0xFF
    assert hart.parse_hart_pdu(bytes(bad)) is None
    # data 바이트 손상도 체크섬 불일치로 탐지
    bad2 = bytearray(pdu)
    bad2[5] ^= 0x01
    assert hart.parse_hart_pdu(bytes(bad2)) is None


def test_session_init_roundtrip():
    req = hart.build_session_init(seq=7, master_type=1, inactivity_timer_ms=30000)
    resp = hart.handle_hart_ip(hart.HartField(), req)
    p = hart.parse_hart_response(resp)
    assert p is not None
    assert p["msg_type"] == hart.MSG_TYPE_RESPONSE
    assert p["msg_id"] == hart.MSG_ID_SESSION_INIT
    assert p["seq"] == 7
    # 세션 응답은 마스터 파라미터를 에코
    assert resp[8:] == req[8:]


def test_command1_read_primary_variable():
    dev = hart.HartField(pv=63.5, pv_unit=57)
    req = hart.build_read_command(1)
    resp = hart.handle_hart_ip(dev, req)
    p = hart.parse_hart_response(resp)
    assert p["command"] == 1
    assert p["response_code"] == hart.RC_SUCCESS
    assert p["pv_unit"] == 57
    assert abs(p["pv"] - 63.5) < 1e-4


def test_command3_read_dynamic_variables_roundtrip():
    dev = hart.HartField(pv=63.2, sv=25.0, tv=1.2, qv=0.0,
                         pv_unit=57, sv_unit=32, tv_unit=220, loop_current=12.5)
    req = hart.build_read_command(3)
    resp = hart.handle_hart_ip(dev, req)
    p = hart.parse_hart_response(resp)
    assert p["command"] == 3
    assert p["response_code"] == hart.RC_SUCCESS
    assert abs(p["loop_current"] - 12.5) < 1e-4
    assert p["pv_unit"] == 57 and abs(p["pv"] - 63.2) < 1e-4
    assert p["sv_unit"] == 32 and abs(p["sv"] - 25.0) < 1e-4
    assert p["tv_unit"] == 220 and abs(p["tv"] - 1.2) < 1e-4


def test_on_command_callback_fires():
    seen = []
    dev = hart.HartField()
    dev.on_command = lambda cmd, data: seen.append(cmd)
    hart.handle_hart_ip(dev, hart.build_read_command(3))
    assert seen == [3]


def test_unsupported_command_returns_not_implemented():
    dev = hart.HartField()
    resp = hart.handle_hart_ip(dev, hart.build_read_command(99))
    p = hart.parse_hart_response(resp)
    assert p["command"] == 99
    assert p["response_code"] == hart.RC_CMD_NOT_IMPLEMENTED


def test_serve_live_socket_roundtrip():
    async def _run():
        dev = hart.HartField(pv=77.7, pv_unit=57, sv=30.0, tv=2.0, loop_current=15.0)
        server = await hart.serve(dev, host="127.0.0.1", port=0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            # 세션 개시
            writer.write(hart.build_session_init(seq=1))
            await writer.drain()
            hdr = await reader.readexactly(8)
            h = hart.parse_hart_ip_header(hdr)
            _ = await reader.readexactly(h.byte_count - 8) if h.byte_count > 8 else b""
            assert h.msg_id == hart.MSG_ID_SESSION_INIT

            # Command 3 읽기
            writer.write(hart.build_read_command(3, seq=2))
            await writer.drain()
            hdr2 = await reader.readexactly(8)
            h2 = hart.parse_hart_ip_header(hdr2)
            body2 = await reader.readexactly(h2.byte_count - 8)
            p = hart.parse_hart_response(hdr2 + body2)
            assert p["command"] == 3
            assert abs(p["pv"] - 77.7) < 1e-3
            assert abs(p["loop_current"] - 15.0) < 1e-4
        finally:
            writer.close()
            server.close()
            await server.wait_closed()

    asyncio.run(_run())


def test_hart_access_detection_rule_fires():
    """SIEM HART 탐지 룰(raw.protocol=hart)이 발화하는지(§5 attack↔detect 완결)."""
    from services.siem.detection.engine import Rule, DetectionEngine
    rule = Rule(id="ICS-HART-ACCESS-REF", title="hart", severity=4,
                mitre=["T0861", "T0888"], source_type="twin", kind="match",
                match={"raw.protocol": "hart"})
    eng = DetectionEngine([rule])
    ev = {"source_type": "twin", "vuln_id": "REF-003", "asset": "refinery_plant",
          "raw": {"protocol": "hart", "endpoint": "/hart/command/3"}}
    alerts = eng.evaluate(ev)
    assert any(a.rule_id == "ICS-HART-ACCESS-REF" for a in alerts)
    # 다른 프로토콜 활동엔 미발화(오탐 방지)
    ev2 = {"source_type": "twin", "vuln_id": "REF-004", "raw": {"protocol": "modbus"}}
    assert not any(a.rule_id == "ICS-HART-ACCESS-REF" for a in eng.evaluate(ev2))
