"""
실 OPC UA 전송 계층(shared/ics/opcua.py) 단위/라이브 테스트 — §5 실 프로토콜 확장
==================================================================================
- UACP 프레이밍: HEL 파싱 → ACK 생성(버퍼 협상), ERR, 메시지 헤더.
- OPN(OpenSecureChannel None) 응답 구조.
- serve(): 실제 소켓으로 HEL→ACK, OPN→OPN 라운드트립(클라이언트 헬퍼).
"""
import asyncio
import socket
import struct

from shared.ics import opcua


def test_hello_ack_roundtrip():
    hel = opcua.build_hello("opc.tcp://twin:4840")
    assert hel[0:3] == b"HEL" and hel[3:4] == b"F"
    mtype, chunk, size = opcua.parse_message_header(hel)
    assert mtype == b"HEL" and size == len(hel)
    hello = opcua.parse_hello(hel[8:])
    assert hello is not None
    assert hello.endpoint_url == "opc.tcp://twin:4840"
    ack = opcua.build_acknowledge(hello)
    assert ack[0:3] == b"ACK"
    # ACK body: 5 x u32 (version + 4 buffer params), endpoint url 없음
    _, _, ack_size = opcua.parse_message_header(ack)
    assert ack_size == 8 + 20


def test_ack_negotiates_min_buffers():
    # 클라이언트가 거대한 버퍼를 요청해도 서버 상한으로 클램프.
    hello = opcua.HelloParams(0, 10**9, 10**9, 10**9, 10**9, "opc.tcp://x")
    ack = opcua.build_acknowledge(hello)
    ver, rbuf, sbuf, maxmsg, maxchunk = struct.unpack_from("<IIIII", ack, 8)
    assert rbuf == opcua.DEFAULT_BUFFER and sbuf == opcua.DEFAULT_BUFFER
    assert maxmsg == opcua.DEFAULT_MAX_MESSAGE and maxchunk == opcua.DEFAULT_MAX_CHUNK


def test_bad_hello_returns_none():
    assert opcua.parse_hello(b"\x00\x01") is None


def test_error_frame():
    err = opcua.build_error(0x80020000, "Bad_TcpMessageTypeInvalid")
    assert err[0:3] == b"ERR"
    code = struct.unpack_from("<I", err, 8)[0]
    assert code == 0x80020000


def test_opn_response_structure():
    sc = opcua.SecureChannelState(channel_id=7, token_id=3)
    opn = opcua.build_open_secure_channel_response(sc)
    assert opn[0:3] == b"OPN"
    # body 시작: SecureChannelId(u32) == channel_id
    chan = struct.unpack_from("<I", opn, 8)[0]
    assert chan == 7
    # SecurityPolicyUri(None) 문자열이 프레임에 포함
    assert opcua.SECURITY_POLICY_NONE.encode() in opn


def test_serve_hel_ack_and_opn_live():
    async def run():
        server = await opcua.serve(host="127.0.0.1", port=0)
        port = server.sockets[0].getsockname()[1]

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # HEL → ACK
        writer.write(opcua.build_hello("opc.tcp://127.0.0.1:%d" % port)); await writer.drain()
        head = await reader.readexactly(8)
        mtype, _c, size = opcua.parse_message_header(head)
        rest = await reader.readexactly(size - 8)
        assert mtype == b"ACK"
        # OPN → OpenSecureChannelResponse
        # 최소 OPN 요청(서버는 body 내용을 요구하지 않음): 프레임만 보냄
        opn_req = opcua._frame(b"OPN", b"\x00" * 16)
        writer.write(opn_req); await writer.drain()
        head2 = await reader.readexactly(8)
        m2, _c2, s2 = opcua.parse_message_header(head2)
        body2 = await reader.readexactly(s2 - 8)
        assert m2 == b"OPN"
        assert opcua.SECURITY_POLICY_NONE.encode() in (head2 + body2)
        writer.close()
        server.close()

    asyncio.run(run())


def test_session_browse_read_roundtrip():
    """실 OPC UA 세션 계층: CreateSession→ActivateSession(Anonymous)→Browse→Read.

    익명 세션으로 은닉 노드를 Browse 로 발견하고 Read 로 값을 회수한다(ICS-001 경로).
    on_read 콜백(SIEM 트리거)이 접근 노드로 발화하는지도 확인.
    """
    hidden = "ns=4;s=Diag.Maint_cafe"
    space = {"ns=2;s=Boiler.TempC": 210.5, hidden: "flag{opcua_anon_read_test}"}
    reads = []

    async def run():
        server = await opcua.serve(
            host="127.0.0.1", port=0,
            browse_nodes=lambda: [(n, n.split(";")[-1]) for n in space],
            read_node=lambda n: space.get(n),
            on_read=lambda n, peer: reads.append(n))
        port = server.sockets[0].getsockname()[1]
        loop = asyncio.get_event_loop()
        browsed, values = await loop.run_in_executor(
            None, lambda: opcua.session_browse_read("127.0.0.1", port, [hidden]))
        server.close()
        return browsed, values

    browsed, values = asyncio.run(run())
    assert hidden in browsed                       # 익명 Browse 로 은닉 노드 노출
    assert values[hidden] == space[hidden]         # 익명 Read 로 값(플래그) 회수
    assert hidden in reads                          # on_read(SIEM 트리거) 발화


def test_read_node_value_types():
    """Variant 스칼라 인코딩 왕복(String/Double/Int32)."""
    space = {"ns=2;s=a": "txt", "ns=2;s=b": 3.14, "ns=2;s=c": 42}

    async def run():
        server = await opcua.serve(host="127.0.0.1", port=0,
                                   browse_nodes=lambda: [],
                                   read_node=lambda n: space.get(n))
        port = server.sockets[0].getsockname()[1]
        loop = asyncio.get_event_loop()
        _, values = await loop.run_in_executor(
            None, lambda: opcua.session_browse_read(
                "127.0.0.1", port, ["ns=2;s=a", "ns=2;s=b", "ns=2;s=c"]))
        server.close()
        return values

    values = asyncio.run(run())
    assert values["ns=2;s=a"] == "txt"
    assert abs(values["ns=2;s=b"] - 3.14) < 1e-9
    assert values["ns=2;s=c"] == 42
