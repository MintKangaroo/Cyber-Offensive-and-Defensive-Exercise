"""
실 Profinet DCP(최소 서브셋, audit §5) 계약 고정.
DCP 프레임/TLV 패킹·Identify·Get(NameOfStation)·live serve() 왕복을 소켓/도커 없이 순수 검증.
전송 정직성(프레임은 규격대로, 전송만 TCP)은 shared/ics/profinet.py 도크스트링 참조.
"""
import asyncio
import struct

from shared.ics.profinet import (
    ProfinetDevice, handle_dcp, serve,
    encode_dcp_header, encode_block, encode_dcp_frame,
    parse_dcp_header, parse_blocks, parse_dcp_response,
    build_dcp_identify_all, build_dcp_get,
    SERVICE_IDENTIFY, SERVICE_GET, TYPE_REQUEST, TYPE_RESPONSE,
    OPT_DEVICE, SUB_DEV_NAMEOFSTATION, OPT_IP, SUB_IP_PARAM, HEADER_LEN,
)


def _device():
    return ProfinetDevice(station_name="plc-line-a", vendor_id=0x002A, device_id=0x0301,
                          ip="10.20.0.11", vendor_value="Siemens S7-1500")


# ── 프레임/TLV 라운드트립 ─────────────────────────────────────────
def test_header_roundtrip():
    frame = encode_dcp_header(SERVICE_IDENTIFY, TYPE_REQUEST, 0x11223344, data_length=7,
                              response_delay=0)
    hdr = parse_dcp_header(frame)
    assert (hdr.service_id, hdr.service_type, hdr.xid, hdr.data_length) == \
           (SERVICE_IDENTIFY, TYPE_REQUEST, 0x11223344, 7)
    assert HEADER_LEN == 10 and len(frame) == 10


def test_block_tlv_roundtrip_with_padding():
    # 홀수 길이 값 -> 짝수 정렬 패딩이 붙지만 파서가 값을 정확히 복원
    val = b"odd"                       # 3바이트(홀수)
    block = encode_block(OPT_DEVICE, SUB_DEV_NAMEOFSTATION, val, block_info=0)
    # 헤더4 + BlockInfo2 + 값3 = 9(홀수) -> 패딩1 = 10
    assert len(block) == 10
    parsed = parse_blocks(block, has_block_info=True)
    assert parsed == [(OPT_DEVICE, SUB_DEV_NAMEOFSTATION, val)]


def test_block_length_field_counts_blockinfo_not_padding():
    block = encode_block(OPT_DEVICE, SUB_DEV_NAMEOFSTATION, b"abc", block_info=0)
    option, suboption, blen = struct.unpack(">BBH", block[:4])
    assert (option, suboption) == (OPT_DEVICE, SUB_DEV_NAMEOFSTATION)
    assert blen == 5                   # BlockInfo(2) + "abc"(3), 패딩 미포함


def test_multi_block_frame_roundtrip():
    blocks = [
        encode_block(OPT_DEVICE, SUB_DEV_NAMEOFSTATION, b"plc-1", block_info=0),
        encode_block(OPT_IP, SUB_IP_PARAM,
                     struct.pack(">4B4B4B", 10, 0, 0, 5, 255, 255, 255, 0, 0, 0, 0, 0),
                     block_info=0),
    ]
    frame = encode_dcp_frame(SERVICE_IDENTIFY, TYPE_RESPONSE, 1, blocks)
    hdr = parse_dcp_header(frame)
    body = frame[HEADER_LEN:HEADER_LEN + hdr.data_length]
    got = parse_blocks(body, has_block_info=True)
    assert got[0] == (OPT_DEVICE, SUB_DEV_NAMEOFSTATION, b"plc-1")
    assert got[1][0:2] == (OPT_IP, SUB_IP_PARAM)


# ── Identify 요청 → 응답 ──────────────────────────────────────────
def test_identify_request_to_response():
    dev = _device()
    req = build_dcp_identify_all(xid=0xABCD)
    resp = handle_dcp(dev, req)
    assert resp, "Identify 는 응답을 내야 함"
    info = parse_dcp_response(resp)
    assert info["service_id"] == SERVICE_IDENTIFY
    assert info["service_type"] == TYPE_RESPONSE
    assert info["xid"] == 0xABCD       # xid 상관 유지
    assert info["station_name"] == "plc-line-a"
    assert info["vendor_id"] == 0x002A and info["device_id"] == 0x0301
    assert info["ip"] == "10.20.0.11"
    assert info["vendor_value"] == "Siemens S7-1500"


# ── Get(NameOfStation) 요청 → 응답 ────────────────────────────────
def test_get_name_of_station():
    dev = _device()
    req = build_dcp_get(OPT_DEVICE, SUB_DEV_NAMEOFSTATION, xid=7)
    resp = handle_dcp(dev, req)
    info = parse_dcp_response(resp)
    assert info["service_id"] == SERVICE_GET and info["xid"] == 7
    assert info["station_name"] == "plc-line-a"
    # NameOfStation 만 요청했으니 IP/DeviceID 블록은 없어야 함
    assert "ip" not in info and "device_id" not in info


def test_get_ip_parameter():
    dev = _device()
    resp = handle_dcp(dev, build_dcp_get(OPT_IP, SUB_IP_PARAM))
    info = parse_dcp_response(resp)
    assert info["ip"] == "10.20.0.11" and info["subnet"] == "255.255.255.0"


def test_response_frame_is_not_handled_as_request():
    # ServiceType=response 프레임을 서버에 주면 무응답(b"")
    dev = _device()
    resp_frame = handle_dcp(dev, build_dcp_identify_all())
    assert handle_dcp(dev, resp_frame) == b""


# ── live serve() 소켓 왕복 ────────────────────────────────────────
def test_serve_socket_roundtrip():
    dev = _device()
    seen = []

    async def _run():
        server = await serve(dev, host="127.0.0.1", port=0,
                             on_request=lambda sid, st, xid, body: seen.append((sid, st, xid)))
        try:
            port = server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            # Identify
            writer.write(build_dcp_identify_all(xid=0x55))
            await writer.drain()
            header = await reader.readexactly(HEADER_LEN)
            _, _, _, _, dlen = struct.unpack(">BBIHH", header)
            body = await reader.readexactly(dlen)
            info = parse_dcp_response(header + body)
            assert info["station_name"] == "plc-line-a" and info["xid"] == 0x55

            # Get(NameOfStation) 두 번째 요청도 같은 연결에서
            writer.write(build_dcp_get(OPT_DEVICE, SUB_DEV_NAMEOFSTATION, xid=0x66))
            await writer.drain()
            header = await reader.readexactly(HEADER_LEN)
            _, _, _, _, dlen = struct.unpack(">BBIHH", header)
            body = await reader.readexactly(dlen)
            info2 = parse_dcp_response(header + body)
            assert info2["station_name"] == "plc-line-a" and info2["xid"] == 0x66

            writer.close()
            await asyncio.sleep(0.05)
            assert (SERVICE_IDENTIFY, TYPE_REQUEST, 0x55) in seen
            assert (SERVICE_GET, TYPE_REQUEST, 0x66) in seen
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_run())
