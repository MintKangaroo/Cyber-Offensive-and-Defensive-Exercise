"""
실 CCSDS Space Packet Protocol 계약 고정 — 위성 TT&C.
지상국 트윈이 진짜 CCSDS 를 말하게 하는 핵심. 1차 헤더 비트 패킹·텔레커맨드 처리·서버 라운드트립을
소켓 유무와 무관하게 검증한다. PURE, 도커 불필요.
"""
import asyncio
import struct

import pytest

from shared.space.ccsds import (
    encode_primary_header, parse_primary_header, encode_packet, parse_packet,
    build_tc, parse_tm, handle_tc, SpacecraftState, serve,
    TM, TC, SEQ_UNSEGMENTED, APID_TC_CMD, APID_TM_ACK, APID_TM_HK,
    CMD_PING, CMD_DISABLE_ATTITUDE_SAFETY, CMD_SET_ATTITUDE, CMD_SET_THRUSTER,
    STATUS_ACCEPT, STATUS_REJECT, build_tm_housekeeping,
)


# ---------------------------------------------------------------------------
# 1차 헤더 비트 패킹 라운드트립
# ---------------------------------------------------------------------------
def test_primary_header_roundtrip_recovers_all_fields():
    hdr = encode_primary_header(ptype=TC, apid=0x64, seq_count=1234, data_len=5,
                                seq_flags=SEQ_UNSEGMENTED)
    assert len(hdr) == 6
    p = parse_primary_header(hdr)
    assert p["version"] == 0
    assert p["type"] == TC
    assert p["apid"] == 0x64
    assert p["seq_flags"] == SEQ_UNSEGMENTED
    assert p["seq_count"] == 1234
    assert p["data_len"] == 5   # Packet Data Length 필드 = 4, 파서가 +1 복원


def test_data_length_field_is_len_minus_one():
    # data_len=1 → 필드값 0 (CCSDS: 최소 데이터 1바이트)
    hdr = encode_primary_header(ptype=TM, apid=0x1, seq_count=0, data_len=1)
    assert struct.unpack(">H", hdr[4:6])[0] == 0
    hdr2 = encode_primary_header(ptype=TM, apid=0x1, seq_count=0, data_len=256)
    assert struct.unpack(">H", hdr2[4:6])[0] == 255


def test_apid_11bit_and_type_bit_boundaries():
    # APID 최대 11비트(0x7FF), type 비트가 APID 로 새지 않아야 함
    hdr = encode_primary_header(ptype=TC, apid=0x7FF, seq_count=0, data_len=1)
    p = parse_primary_header(hdr)
    assert p["apid"] == 0x7FF and p["type"] == TC and p["version"] == 0
    # TM(type=0) 로 바꾸면 최상위 워드의 type 비트만 달라진다
    hdr_tm = encode_primary_header(ptype=TM, apid=0x7FF, seq_count=0, data_len=1)
    w_tc = struct.unpack(">H", hdr[:2])[0]
    w_tm = struct.unpack(">H", hdr_tm[:2])[0]
    assert w_tc ^ w_tm == (1 << 12)   # 오직 type 비트(비트12)만 차이


def test_seq_count_14bit_masked():
    hdr = encode_primary_header(ptype=TC, apid=0, seq_count=0x3FFF, data_len=1)
    assert parse_primary_header(hdr)["seq_count"] == 0x3FFF


def test_encode_parse_packet_roundtrip():
    data = b"\x11\x22\x33"
    pkt = encode_packet(ptype=TC, apid=APID_TC_CMD, seq_count=7, data=data)
    hdr, body = parse_packet(pkt)
    assert body == data and hdr["apid"] == APID_TC_CMD and hdr["seq_count"] == 7


def test_empty_data_field_rejected():
    with pytest.raises(ValueError):
        encode_packet(ptype=TC, apid=1, seq_count=0, data=b"")


# ---------------------------------------------------------------------------
# 텔레커맨드 → 텔레메트리 ACK
# ---------------------------------------------------------------------------
def test_tc_disable_safety_mutates_state_and_acks():
    state = SpacecraftState()
    assert state.attitude_safety_enabled is True
    tc = build_tc(APID_TC_CMD, CMD_DISABLE_ATTITUDE_SAFETY, seq_count=3)
    tm = handle_tc(state, tc)
    assert state.attitude_safety_enabled is False
    assert state.tc_seq == 3
    ack = parse_tm(tm)
    assert ack["type"] == TM and ack["apid"] == APID_TM_ACK
    assert ack["command"] == CMD_DISABLE_ATTITUDE_SAFETY
    assert ack["status"] == STATUS_ACCEPT


def test_tc_set_attitude_parses_args():
    state = SpacecraftState()
    args = struct.pack(">hhh", -100, 250, 30000)
    tc = build_tc(APID_TC_CMD, CMD_SET_ATTITUDE, args=args)
    handle_tc(state, tc)
    assert (state.roll_mdeg, state.pitch_mdeg, state.yaw_mdeg) == (-100, 250, 30000)


def test_tc_set_thruster_parses_args():
    state = SpacecraftState()
    tc = build_tc(APID_TC_CMD, CMD_SET_THRUSTER, args=struct.pack(">H", 750))
    handle_tc(state, tc)
    assert state.thruster_level == 750


def test_ping_accepted_unknown_apid_rejected():
    state = SpacecraftState()
    ack = parse_tm(handle_tc(state, build_tc(APID_TC_CMD, CMD_PING)))
    assert ack["status"] == STATUS_ACCEPT
    # 인식 못한 APID → REJECT
    rej = parse_tm(handle_tc(state, build_tc(0x2AA, CMD_PING)))
    assert rej["status"] == STATUS_REJECT


def test_unknown_command_rejected():
    state = SpacecraftState()
    ack = parse_tm(handle_tc(state, build_tc(APID_TC_CMD, 0xEE)))
    assert ack["status"] == STATUS_REJECT


def test_tm_packet_is_not_treated_as_tc():
    state = SpacecraftState()
    tm = build_tm_housekeeping(state)
    # TM(type=0) 을 handle_tc 에 넣으면 무시(None)
    assert handle_tc(state, tm) is None


def test_housekeeping_tm_roundtrip():
    state = SpacecraftState(battery_voltage_mv=27500, roll_mdeg=-1234)
    tm = parse_tm(build_tm_housekeeping(state))
    assert tm["apid"] == APID_TM_HK
    assert tm["battery_voltage_mv"] == 27500
    assert tm["roll_mdeg"] == -1234
    assert tm["attitude_safety_enabled"] is True


# ---------------------------------------------------------------------------
# 라이브 serve() 소켓 라운드트립(asyncio, port 0)
# ---------------------------------------------------------------------------
def test_live_serve_socket_roundtrip():
    async def _run():
        state = SpacecraftState()
        received = []
        server = await serve(state, host="127.0.0.1", port=0,
                             on_tc=lambda pkt, hdr, data: received.append(hdr["apid"]))
        port = server.sockets[0].getsockname()[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        tc = build_tc(APID_TC_CMD, CMD_DISABLE_ATTITUDE_SAFETY, seq_count=42)
        writer.write(tc)
        await writer.drain()

        # 응답 TM 수신: 헤더 6B → 데이터 길이 → 나머지
        header = await asyncio.wait_for(reader.readexactly(6), timeout=2)
        p = parse_primary_header(header)
        body = await asyncio.wait_for(reader.readexactly(p["data_len"]), timeout=2)
        ack = parse_tm(header + body)

        writer.close()
        server.close()
        await server.wait_closed()

        assert ack["apid"] == APID_TM_ACK
        assert ack["command"] == CMD_DISABLE_ATTITUDE_SAFETY
        assert ack["status"] == STATUS_ACCEPT
        assert state.attitude_safety_enabled is False   # 서버가 실제로 상태 변형
        assert received == [APID_TC_CMD]                 # on_tc 훅 호출됨

    asyncio.run(_run())
