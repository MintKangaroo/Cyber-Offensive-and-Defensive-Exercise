"""
실 S7comm(shared/ics/s7comm.py) 단위/라이브 테스트 — §5 실 프로토콜 확장
=========================================================================
- TPKT 인코드/길이, COTP CR→CC, S7 Setup Communication, S7 Read Var 라운드트립.
- serve(): 실제 소켓으로 CR→CC, Setup, Read Var 값 수신.
"""
import asyncio
import struct

from shared.ics import s7comm


def test_tpkt_frame():
    f = s7comm.tpkt(b"abcd")
    assert f[0] == 0x03 and f[1] == 0x00
    assert s7comm.parse_tpkt_len(f[:4]) == len(f) == 8


def test_cotp_cr_detected_and_cc_built():
    cr = s7comm.build_cotp_cr()
    cotp = cr[4:]                      # TPKT 헤더 제거
    assert s7comm.is_cotp_cr(cotp)
    cc = s7comm.build_cotp_cc()
    assert cc[1] == 0xD0              # Connection Confirm


def test_s7_setup_communication_ack():
    os = s7comm.S7Outstation()
    setup = s7comm.build_s7_setup()
    s7 = s7comm.cotp_dt_payload(setup[4:])
    resp = s7comm.handle_s7_pdu(os, s7)
    assert resp is not None
    assert resp[0] == 0x32 and resp[1] == 0x03    # S7 Ack_Data
    assert resp[12] == 0xF0                        # function setup echo(Ack 헤더 12바이트 뒤)


def test_s7_read_var_roundtrip():
    os = s7comm.S7Outstation(db=[0] * 64)
    os.db[0] = 385      # word0
    os.db[1] = 420      # word1
    os.db[2] = 63       # word2
    read = []
    os.on_read = lambda dbn, start, count: read.append((dbn, start, count))
    req = s7comm.build_s7_read(db_num=1, start_byte=0, count_words=3)
    s7 = s7comm.cotp_dt_payload(req[4:])
    resp = s7comm.handle_s7_pdu(os, s7)
    # 응답 프레임으로 감싸 파싱
    frame = s7comm.tpkt(s7comm.build_cotp_dt(resp))
    vals = s7comm.parse_s7_read_response(frame)
    assert vals == [385, 420, 63]
    assert read == [(1, 0, 3)]


def test_serve_live_cr_setup_read():
    async def run():
        os = s7comm.S7Outstation(db=[0] * 16)
        os.db[0] = 1111; os.db[1] = 2222
        server = await s7comm.serve(os, host="127.0.0.1", port=0)
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        async def rpc(req):
            writer.write(req); await writer.drain()
            head = await reader.readexactly(4)
            total = s7comm.parse_tpkt_len(head)
            rest = await reader.readexactly(total - 4)
            return head + rest

        cc = await rpc(s7comm.build_cotp_cr())
        assert cc[5] == 0xD0                      # COTP CC (cc[4]=len, cc[5]=pdu_type)
        await rpc(s7comm.build_s7_setup())
        rd = await rpc(s7comm.build_s7_read(1, 0, 2))
        assert s7comm.parse_s7_read_response(rd) == [1111, 2222]
        writer.close()
        server.close()

    asyncio.run(run())
