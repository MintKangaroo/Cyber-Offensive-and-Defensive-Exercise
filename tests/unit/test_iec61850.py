"""
실 IEC 61850 MMS(shared/ics/iec61850.py) 단위/라이브 테스트 — §5 실 프로토콜 확장
==================================================================================
- TPKT 인코드/길이, COTP CR→CC(S7comm 과 바이트 동일한 프레이밍 재사용).
- MMS Initiate → Initiate-Response.
- MMS Read → Read-Response 값 라운드트립(모선전압·선로전류·차단기상태).
- serve(): 실제 소켓으로 CR→CC, Initiate, Read.
PURE, no docker.
"""
import asyncio

from shared.ics import iec61850


# ---- TPKT / COTP: S7comm 과 바이트 동일한 프레이밍 ----
def test_tpkt_frame():
    f = iec61850.tpkt(b"abcd")
    assert f[0] == 0x03 and f[1] == 0x00
    assert iec61850.parse_tpkt_len(f[:4]) == len(f) == 8


def test_cotp_cr_detected_and_cc_built():
    cr = iec61850.build_cotp_cr()
    cotp = cr[4:]                     # TPKT 헤더 제거
    assert iec61850.is_cotp_cr(cotp)
    cc = iec61850.build_cotp_cc()
    assert cc[1] == 0xD0             # Connection Confirm


def test_cotp_dt_roundtrip():
    payload = b"\xa8\x03\x80\x01\x05"
    dt = iec61850.build_cotp_dt(payload)
    assert iec61850.cotp_dt_payload(dt) == payload


# ---- BER 최소 인코딩 ----
def test_ber_len_short_and_long():
    assert iec61850.ber_len(5) == b"\x05"
    assert iec61850.ber_len(200) == bytes([0x81, 200])
    assert iec61850.ber_len(300) == bytes([0x82, 0x01, 0x2C])


# ---- MMS Initiate ----
def test_mms_initiate_response():
    ied = iec61850.IED.substation_default()
    seen = []
    ied.on_initiate = lambda: seen.append(True)
    req = iec61850.build_mms_initiate()
    mms = iec61850.cotp_dt_payload(req[4:])
    resp = iec61850.handle_mms_pdu(ied, mms)
    assert resp is not None
    assert iec61850.is_mms_initiate_response(resp)
    assert resp[0] == iec61850.TAG_INITIATE_RESPONSE
    assert seen == [True]


# ---- MMS Read 라운드트립 ----
def test_mms_read_roundtrip():
    ied = iec61850.IED.substation_default()
    counts = []
    ied.on_read = lambda n: counts.append(n)
    req = iec61850.build_mms_read(["MMXU1.PhV", "MMXU1.A", "XCBR1.Pos"], invoke_id=7)
    mms = iec61850.cotp_dt_payload(req[4:])
    resp = iec61850.handle_mms_pdu(ied, mms)
    assert resp is not None
    frame = iec61850.tpkt(iec61850.build_cotp_dt(resp))
    vals = iec61850.parse_mms_read_response(frame)
    assert vals == [("int", 22900), ("int", 415), ("bits", 0b10)]
    assert counts == [3]      # 요청 변수 개수 카운트


def test_mms_read_custom_ied_values():
    ied = iec61850.IED(points=[
        iec61850.MmsDataPoint("V", "int", -128),           # 음수 정수 BER
        iec61850.MmsDataPoint("pos", "bits", 0b11, bits=2),
    ])
    req = iec61850.build_mms_read(["V", "pos"])
    mms = iec61850.cotp_dt_payload(req[4:])
    resp = iec61850.handle_mms_pdu(ied, mms)
    frame = iec61850.tpkt(iec61850.build_cotp_dt(resp))
    assert iec61850.parse_mms_read_response(frame) == [("int", -128), ("bits", 0b11)]


def test_unknown_pdu_ignored():
    ied = iec61850.IED.substation_default()
    assert iec61850.handle_mms_pdu(ied, b"\xbb\x00") is None
    assert iec61850.handle_mms_pdu(ied, b"") is None


# ---- 라이브 serve() 소켓 라운드트립 ----
def test_serve_live_cr_initiate_read():
    async def run():
        ied = iec61850.IED.substation_default()
        events = []
        ied.on_initiate = lambda: events.append("init")
        ied.on_read = lambda n: events.append(("read", n))
        server = await iec61850.serve(ied, host="127.0.0.1", port=0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        async def rpc(req):
            writer.write(req); await writer.drain()
            head = await reader.readexactly(4)
            total = iec61850.parse_tpkt_len(head)
            rest = await reader.readexactly(total - 4)
            return head + rest

        cc = await rpc(iec61850.build_cotp_cr())
        assert cc[5] == 0xD0                          # COTP CC
        init = await rpc(iec61850.build_mms_initiate())
        assert iec61850.is_mms_initiate_response(iec61850.cotp_dt_payload(init[4:]))
        rd = await rpc(iec61850.build_mms_read())
        vals = iec61850.parse_mms_read_response(rd)
        assert vals == [("int", 22900), ("int", 415), ("bits", 0b10)]
        assert events == ["init", ("read", 3)]

        writer.close()
        server.close()

    asyncio.run(run())
