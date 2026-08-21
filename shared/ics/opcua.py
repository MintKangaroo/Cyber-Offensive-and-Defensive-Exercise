"""
실 OPC UA 전송 계층(UACP: UA Connection Protocol) — HEL/ACK 핸드셰이크 + 최소 SecureChannel
=============================================================================================
OPC UA(IEC 62541)는 산업 자동화의 사실상 표준. 트윈이 HTTP 목업이 아니라 **실제 OPC UA 바이너리
프레이밍**으로 응답하게 해, 스캐너/클라이언트의 첫 접속(Hello→Acknowledge)과 SecureChannel
개설(OpenSecureChannel, security None)을 실제 프로토콜로 처리한다. (Modbus/DNP3와 동일 철학:
소켓 무관 순수 함수 + serve().)

구현 범위(정직한 최소 상호운용셋):
  - UACP 메시지 프레이밍: 3바이트 타입(HEL/ACK/ERR/OPN/MSG/CLO) + 1바이트 chunk + u32 size.
  - HEL(Hello) 파싱 → ACK(Acknowledge) 생성(버퍼 파라미터 협상).
  - OPN(OpenSecureChannel, SecurityPolicy None) → OpenSecureChannelResponse(채널/토큰 발급).
  - **세션/Browse/Read 응용 서비스**(MSG 청크, SecurityPolicy None): CreateSession →
    ActivateSession(Anonymous) → Browse(주소공간 열람) → Read(노드 값). 전부 OPC UA Binary
    서비스 인코딩(요청 TypeId NodeId 디스패치 + ResponseHeader + 서비스 바디). serve() 에
    browse_nodes/read_node 콜백을 주입해 트윈·챌린지가 주소공간과 값을 정의한다.
전 인코딩은 OPC UA Binary(리틀엔디언). 클라이언트 헬퍼(session_read 등)로 테스트/라이브 검증.
정직한 경계: 서명/암호화(None 만)·복잡 EndpointDescription 배열은 미구현 — 자체 클라이언트
헬퍼와의 상호운용을 보장하는 최소 실 바이너리 서브셋이다(Modbus/DNP3 모듈과 동일 철학).
"""
from __future__ import annotations

import asyncio
import struct
import time
from dataclasses import dataclass
from typing import Optional

OPCUA_DEFAULT_PORT = 4840
SECURITY_POLICY_NONE = "http://opcfoundation.org/UA/SecurityPolicy#None"

# UACP 협상 기본값(OPC UA 표준 최소치 이상).
DEFAULT_BUFFER = 65536
DEFAULT_MAX_MESSAGE = 16777216
DEFAULT_MAX_CHUNK = 5000


def _u32(v: int) -> bytes:
    return struct.pack("<I", v)


def _ua_string(s: Optional[str]) -> bytes:
    """OPC UA String: i32 길이 + UTF-8 바이트. None/빈 문자열은 길이 -1."""
    if s is None:
        return struct.pack("<i", -1)
    b = s.encode("utf-8")
    return struct.pack("<i", len(b)) + b


def _read_ua_string(buf: bytes, off: int) -> tuple[Optional[str], int]:
    (length,) = struct.unpack_from("<i", buf, off)
    off += 4
    if length < 0:
        return None, off
    s = buf[off:off + length].decode("utf-8", errors="replace")
    return s, off + length


def _frame(msg_type: bytes, body: bytes, chunk: bytes = b"F") -> bytes:
    """UACP 프레임: 타입(3) + chunk(1) + size(u32, 헤더 포함 전체) + body."""
    size = 8 + len(body)
    return msg_type + chunk + _u32(size) + body


@dataclass
class HelloParams:
    protocol_version: int
    receive_buffer_size: int
    send_buffer_size: int
    max_message_size: int
    max_chunk_count: int
    endpoint_url: Optional[str]


def parse_hello(body: bytes) -> Optional[HelloParams]:
    """HEL 메시지 body 파싱(프레임 헤더 제외)."""
    if len(body) < 20:
        return None
    ver, rbuf, sbuf, maxmsg, maxchunk = struct.unpack_from("<IIIII", body, 0)
    url, _ = _read_ua_string(body, 20)
    return HelloParams(ver, rbuf, sbuf, maxmsg, maxchunk, url)


def build_acknowledge(hello: HelloParams) -> bytes:
    """ACK: 협상된 버퍼 파라미터(양측 최소값). endpoint url 없음."""
    rbuf = min(hello.receive_buffer_size or DEFAULT_BUFFER, DEFAULT_BUFFER)
    sbuf = min(hello.send_buffer_size or DEFAULT_BUFFER, DEFAULT_BUFFER)
    maxmsg = min(hello.max_message_size or DEFAULT_MAX_MESSAGE, DEFAULT_MAX_MESSAGE) or DEFAULT_MAX_MESSAGE
    maxchunk = min(hello.max_chunk_count or DEFAULT_MAX_CHUNK, DEFAULT_MAX_CHUNK) or DEFAULT_MAX_CHUNK
    body = struct.pack("<IIIII", 0, rbuf, sbuf, maxmsg, maxchunk)
    return _frame(b"ACK", body)


def build_hello(endpoint_url: str) -> bytes:
    """클라이언트(마스터) HEL 생성 — 테스트/검증용."""
    body = struct.pack("<IIIII", 0, DEFAULT_BUFFER, DEFAULT_BUFFER,
                       DEFAULT_MAX_MESSAGE, DEFAULT_MAX_CHUNK) + _ua_string(endpoint_url)
    return _frame(b"HEL", body)


def build_error(code: int, reason: str) -> bytes:
    return _frame(b"ERR", _u32(code) + _ua_string(reason))


def parse_message_header(buf: bytes) -> Optional[tuple[bytes, bytes, int]]:
    """앞 8바이트에서 (msg_type, chunk_type, total_size). 부족하면 None."""
    if len(buf) < 8:
        return None
    msg_type = buf[0:3]
    chunk_type = buf[3:4]
    (size,) = struct.unpack_from("<I", buf, 4)
    return msg_type, chunk_type, size


# ---------------------------------------------------------------------------
# 최소 SecureChannel (OpenSecureChannel, SecurityPolicy None)
# ---------------------------------------------------------------------------
_NODEID_OPN_RESPONSE = bytes([0x01, 0x00]) + struct.pack("<H", 449)  # NodeId(ns=0, i=449) 4byte encoding


@dataclass
class SecureChannelState:
    channel_id: int = 1
    token_id: int = 1


def build_open_secure_channel_response(sc: SecureChannelState, request_id: int = 1,
                                       sequence_number: int = 1) -> bytes:
    """OPN 응답(security None). 상호운용 최소셋: Asymmetric 보안헤더(None) + 시퀀스헤더 +
    ExtensionObject(OpenSecureChannelResponse: ResponseHeader + ProtocolVersion + SecurityToken +
    ServerNonce)."""
    # Asymmetric algorithm security header: SecurityPolicyUri(None), senderCert(null), receiverThumb(null)
    sec_header = _ua_string(SECURITY_POLICY_NONE) + struct.pack("<i", -1) + struct.pack("<i", -1)
    seq_header = struct.pack("<II", sequence_number, request_id)

    # OpenSecureChannelResponse body(ExtensionObject: TypeId + encoding(0x01 bytestring) + length + body)
    # ResponseHeader: timestamp(i64 UA DateTime), requestHandle(u32), serviceResult(u32),
    #   serviceDiagnostics(1 byte encoding mask=0), stringTable(array=-1), additionalHeader(ExtObj null)
    now_ua = int((time.time() + 11644473600) * 10_000_000)   # UA DateTime(100ns since 1601)
    resp_header = struct.pack("<q", now_ua) + _u32(0) + _u32(0) + bytes([0]) + struct.pack("<i", -1)
    resp_header += bytes([0x00, 0x00, 0x00])  # additionalHeader: NodeId(2-byte i=0) + encoding 0x00
    server_proto = _u32(0)
    # ChannelSecurityToken: channelId, tokenId, createdAt(DateTime), revisedLifetime(u32)
    token = _u32(sc.channel_id) + _u32(sc.token_id) + struct.pack("<q", now_ua) + _u32(3600000)
    server_nonce = struct.pack("<i", 1) + bytes([0x00])       # ByteString len=1
    inner = resp_header + server_proto + token + server_nonce
    ext = _NODEID_OPN_RESPONSE + bytes([0x01]) + _u32(len(inner)) + inner

    body = _u32(sc.channel_id) + sec_header + seq_header + ext
    return _frame(b"OPN", body)


# ---------------------------------------------------------------------------
# 응용 서비스 계층 (MSG, SecurityPolicy None) — 세션/Browse/Read
# ---------------------------------------------------------------------------
# 서비스 요청/응답 TypeId(ns=0 numeric, DefaultBinary 인코딩 id, OPC UA Part 6).
SVC = {
    "CreateSessionRequest": 461, "CreateSessionResponse": 464,
    "ActivateSessionRequest": 467, "ActivateSessionResponse": 470,
    "CloseSessionRequest": 473, "CloseSessionResponse": 476,
    "BrowseRequest": 527, "BrowseResponse": 530,
    "ReadRequest": 631, "ReadResponse": 634,
    "ServiceFault": 397,
}
_STATUS_GOOD = 0
_STATUS_BAD_NODEID_UNKNOWN = 0x80340000


def _u16(v: int) -> bytes:
    return struct.pack("<H", v)


def _f64(v: float) -> bytes:
    return struct.pack("<d", v)


def _bytestring(b: Optional[bytes]) -> bytes:
    if b is None:
        return struct.pack("<i", -1)
    return struct.pack("<i", len(b)) + b


def _datetime_now() -> bytes:
    return struct.pack("<q", int((time.time() + 11644473600) * 10_000_000))


def _nodeid(node: str) -> bytes:
    """'ns=N;i=NUM' 또는 'ns=N;s=STR' → OPC UA NodeId 바이너리. ns 생략 시 0."""
    ns = 0
    ident = node
    if node.startswith("ns="):
        ns_part, ident = node.split(";", 1)
        ns = int(ns_part[3:])
    if ident.startswith("i="):
        num = int(ident[2:])
        if ns == 0 and num < 256:
            return bytes([0x00, num])                       # 2바이트 numeric
        return bytes([0x01]) + bytes([ns & 0xFF]) + _u16(num)  # 4바이트 numeric
    if ident.startswith("s="):
        return bytes([0x03]) + _u16(ns) + _ua_string(ident[2:])  # string NodeId
    raise ValueError(f"지원하지 않는 NodeId: {node}")


def _read_nodeid(buf: bytes, off: int) -> tuple[str, int]:
    enc = buf[off]; off += 1
    if enc == 0x00:
        (i,) = struct.unpack_from("<B", buf, off); return f"i={i}", off + 1
    if enc == 0x01:
        ns = buf[off]; (i,) = struct.unpack_from("<H", buf, off + 1)
        return (f"ns={ns};i={i}" if ns else f"i={i}"), off + 3
    if enc == 0x02:
        (ns,) = struct.unpack_from("<H", buf, off); (i,) = struct.unpack_from("<I", buf, off + 2)
        return (f"ns={ns};i={i}" if ns else f"i={i}"), off + 6
    if enc == 0x03:
        (ns,) = struct.unpack_from("<H", buf, off); off += 2
        s, off = _read_ua_string(buf, off)
        return (f"ns={ns};s={s}" if ns else f"s={s}"), off
    raise ValueError(f"NodeId 인코딩 미지원: {enc}")


def _expanded_nodeid(node: str) -> bytes:
    """최소 ExpandedNodeId: NodeId 그대로(namespaceUri/serverIndex 플래그 없음)."""
    return _nodeid(node)


def _qualified_name(ns: int, name: str) -> bytes:
    return _u16(ns) + _ua_string(name)


def _localized_text(text: str) -> bytes:
    return bytes([0x02]) + _ua_string(text)   # mask: text 존재


def _response_header(request_handle: int, service_result: int = _STATUS_GOOD) -> bytes:
    h = _datetime_now() + _u32(request_handle) + _u32(service_result)
    h += bytes([0x00])                 # serviceDiagnostics: encoding mask 0
    h += struct.pack("<i", -1)         # stringTable: null array
    h += bytes([0x00, 0x00, 0x00])     # additionalHeader: NodeId(i=0) + encoding 0x00
    return h


def _read_request_header(buf: bytes, off: int) -> tuple[str, int, int]:
    """RequestHeader 파싱 → (authToken NodeId, requestHandle, off)."""
    auth_token, off = _read_nodeid(buf, off)
    off += 8                           # timestamp(DateTime)
    (request_handle,) = struct.unpack_from("<I", buf, off); off += 4
    off += 4                           # returnDiagnostics(u32)
    _audit, off = _read_ua_string(buf, off)  # auditEntryId(String)
    off += 4                           # timeoutHint(u32)
    off += 3                           # additionalHeader ExtObj null (NodeId i=0 + enc 0x00)
    return auth_token, request_handle, off


def _svc_frame(sc: "SecureChannelState", resp_typeid: int, inner: bytes,
               sequence_number: int, request_id: int) -> bytes:
    """MSG(대칭 보안 None) 프레임: chanId + tokenId + seq헤더 + TypeId + 서비스바디."""
    type_nodeid = bytes([0x01, 0x00]) + _u16(resp_typeid)   # NodeId(ns=0, i=<id>) 4바이트
    payload = _u32(sc.channel_id) + _u32(sc.token_id)
    payload += struct.pack("<II", sequence_number, request_id)
    payload += type_nodeid + inner
    return _frame(b"MSG", payload)


# ---- 서버측 서비스 응답 빌더 (inner = ExtensionObject 없이 서비스 struct 직접) ----
def _create_session_response(request_handle: int, session_id: str,
                             auth_token: str) -> bytes:
    inner = _response_header(request_handle)
    inner += _nodeid(session_id)                 # SessionId
    inner += _nodeid(auth_token)                 # AuthenticationToken
    inner += _f64(3600000.0)                     # RevisedSessionTimeout
    inner += _bytestring(b"\x00")                # ServerNonce
    inner += _bytestring(None)                   # ServerCertificate
    inner += struct.pack("<i", -1)               # ServerEndpoints: null array
    inner += struct.pack("<i", -1)               # ServerSoftwareCertificates: null
    inner += _ua_string(None) + _bytestring(None)  # ServerSignature(algorithm, signature)
    inner += _u32(DEFAULT_MAX_MESSAGE)           # MaxRequestMessageSize
    return inner


def _activate_session_response(request_handle: int) -> bytes:
    inner = _response_header(request_handle)
    inner += _bytestring(b"\x00")                # ServerNonce
    inner += struct.pack("<i", -1)               # Results: null array
    inner += struct.pack("<i", -1)               # DiagnosticInfos: null array
    return inner


def _browse_response(request_handle: int, refs: list[tuple[str, str]]) -> bytes:
    """refs = [(nodeId, browseName)]. 단일 BrowseResult 에 참조 목록."""
    inner = _response_header(request_handle)
    inner += _u32(1)                             # Results: 배열 길이 1
    # BrowseResult
    inner += _u32(_STATUS_GOOD)                  # StatusCode
    inner += _bytestring(None)                   # ContinuationPoint
    inner += _u32(len(refs))                     # References 배열 길이
    for node, bname in refs:
        inner += _nodeid("i=35")                 # ReferenceTypeId: Organizes(i=35)
        inner += bytes([0x01])                   # IsForward = true
        inner += _expanded_nodeid(node)          # NodeId(ExpandedNodeId)
        inner += _qualified_name(4, bname)       # BrowseName
        inner += _localized_text(bname)          # DisplayName
        inner += _u32(2)                         # NodeClass: Variable(2)
        inner += _expanded_nodeid("i=63")        # TypeDefinition: BaseDataVariableType
    inner += struct.pack("<i", -1)               # DiagnosticInfos: null
    return inner


def _variant_scalar(value) -> bytes:
    """Variant 인코딩(스칼라). str→String(id 12), float→Double(id 11)."""
    if isinstance(value, str):
        return bytes([12]) + _ua_string(value)
    if isinstance(value, float):
        return bytes([11]) + _f64(value)
    if isinstance(value, int):
        return bytes([6]) + _u32(value)          # Int32
    return bytes([0])                            # Null variant


def _read_response(request_handle: int, values: list) -> bytes:
    inner = _response_header(request_handle)
    inner += _u32(len(values))                   # Results 배열
    for v in values:
        if v is None:
            inner += bytes([0x00])               # DataValue encoding mask 0 (없음)
            continue
        inner += bytes([0x01])                   # DataValue mask: Value 존재
        inner += _variant_scalar(v)
    inner += struct.pack("<i", -1)               # DiagnosticInfos: null
    return inner


async def serve(host: str = "0.0.0.0", port: int = OPCUA_DEFAULT_PORT,
                endpoint_url: str = "opc.tcp://twin:4840",
                on_connect=None, browse_nodes=None, read_node=None,
                on_read=None) -> asyncio.AbstractServer:
    """OPC UA/TCP 서버.

    핸드셰이크: HEL→ACK, OPN→OpenSecureChannelResponse.
    세션: MSG 로 CreateSession→ActivateSession(Anonymous)→Browse→Read 처리.
      - browse_nodes() -> list[(nodeId, browseName)] : 익명 브라우즈로 노출할 주소공간.
      - read_node(nodeId) -> value|None            : 노드 값(없으면 None).
      - on_read(nodeId, peer)                       : Read 접근 통지(SIEM 트리거).
      - on_connect(peer)                            : 최초 접속 통지.
    """
    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        sc = SecureChannelState()
        peer = writer.get_extra_info("peername")
        seq = 1
        try:
            while True:
                head = await reader.readexactly(8)
                mtype, _chunk, size = parse_message_header(head)
                body = await reader.readexactly(max(0, size - 8)) if size > 8 else b""
                if mtype == b"HEL":
                    hello = parse_hello(body)
                    if hello is None:
                        writer.write(build_error(0x80020000, "Bad_TcpMessageTypeInvalid"))
                        await writer.drain(); break
                    if on_connect:
                        try:
                            on_connect(peer)
                        except Exception:
                            pass
                    writer.write(build_acknowledge(hello)); await writer.drain()
                elif mtype == b"OPN":
                    writer.write(build_open_secure_channel_response(sc)); await writer.drain()
                elif mtype == b"MSG":
                    resp = _dispatch_msg(sc, body, seq, peer, browse_nodes, read_node, on_read)
                    if resp is None:
                        writer.write(build_error(0x80730000, "Bad_ServiceUnsupported"))
                        await writer.drain(); break
                    seq += 1
                    writer.write(resp); await writer.drain()
                elif mtype == b"CLO":
                    break
                else:
                    writer.write(build_error(0x80020000, "Bad_TcpMessageTypeInvalid"))
                    await writer.drain(); break
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(_handle, host, port)


def _dispatch_msg(sc, body, seq, peer, browse_nodes, read_node, on_read):
    """MSG body(보안헤더 포함) 파싱 → 서비스 응답 프레임. 미지원이면 None."""
    off = 0
    off += 4                                     # SecureChannelId
    off += 4                                     # TokenId
    (_seqnum, request_id) = struct.unpack_from("<II", body, off); off += 8
    req_type, off = _read_nodeid(body, off)      # 요청 TypeId NodeId
    # numeric id 추출
    try:
        req_id = int(req_type.split("i=")[-1])
    except ValueError:
        return None
    _auth, request_handle, off = _read_request_header(body, off)

    if req_id == SVC["CreateSessionRequest"]:
        inner = _create_session_response(request_handle, "ns=1;i=1000", "i=2000")
        return _svc_frame(sc, SVC["CreateSessionResponse"], inner, seq, request_id)
    if req_id == SVC["ActivateSessionRequest"]:
        inner = _activate_session_response(request_handle)
        return _svc_frame(sc, SVC["ActivateSessionResponse"], inner, seq, request_id)
    if req_id == SVC["BrowseRequest"]:
        refs = list(browse_nodes()) if browse_nodes else []
        inner = _browse_response(request_handle, refs)
        return _svc_frame(sc, SVC["BrowseResponse"], inner, seq, request_id)
    if req_id == SVC["ReadRequest"]:
        nodes = _parse_read_nodes(body, off)
        values = []
        for n in nodes:
            if on_read:
                try:
                    on_read(n, peer)
                except Exception:
                    pass
            values.append(read_node(n) if read_node else None)
        inner = _read_response(request_handle, values)
        return _svc_frame(sc, SVC["ReadResponse"], inner, seq, request_id)
    if req_id == SVC["CloseSessionRequest"]:
        inner = _response_header(request_handle) + bytes([0x00])  # deleteSubscriptions bool echo 무시
        return _svc_frame(sc, SVC["CloseSessionResponse"], inner, seq, request_id)
    return None


def _parse_read_nodes(body: bytes, off: int) -> list[str]:
    """ReadRequest 파라미터에서 nodesToRead 의 NodeId 목록 추출."""
    off += 8                                     # maxAge(Double)
    off += 4                                     # timestampsToReturn(u32)
    (count,) = struct.unpack_from("<i", body, off); off += 4
    if count < 0:
        return []
    nodes = []
    for _ in range(count):
        node, off = _read_nodeid(body, off)      # ReadValueId.nodeId
        off += 4                                 # attributeId(u32)
        _ir, off = _read_ua_string(body, off)    # indexRange(String)
        off += 2                                 # dataEncoding QualifiedName ns(u16)
        _n, off = _read_ua_string(body, off)     # dataEncoding.name(String)
        nodes.append(node)
    return nodes


# ---------------------------------------------------------------------------
# 클라이언트 헬퍼 (동기 소켓) — 테스트·라이브 검증·익스플로잇 재사용
# ---------------------------------------------------------------------------
def _client_request_header(auth_token: str, handle: int) -> bytes:
    h = _nodeid(auth_token)                      # AuthenticationToken
    h += _datetime_now() + _u32(handle) + _u32(0)
    h += _ua_string(None)                        # auditEntryId
    h += _u32(0)                                 # timeoutHint
    h += bytes([0x00, 0x00, 0x00])               # additionalHeader ExtObj null
    return h


def _client_msg(chan: int, token: int, seq: int, req_id: int,
                req_typeid: int, service_body: bytes) -> bytes:
    type_nodeid = bytes([0x01, 0x00]) + _u16(req_typeid)
    payload = _u32(chan) + _u32(token) + struct.pack("<II", seq, req_id)
    payload += type_nodeid + service_body
    return _frame(b"MSG", payload)


def _skip_response_header(buf: bytes, off: int) -> int:
    off += 8 + 4 + 4                             # timestamp, requestHandle, serviceResult
    off += 1                                     # serviceDiagnostics mask (0)
    off += 4                                     # stringTable null array
    off += 3                                     # additionalHeader ExtObj null
    return off


def _parse_msg_service(frame: bytes) -> tuple[int, bytes, int]:
    """서버 MSG 프레임 → (응답 TypeId numeric, body, 서비스바디 시작 off)."""
    # frame: MSG + F + size(4) + chanId(4) + tokenId(4) + seq(4) + reqId(4) + TypeId + inner
    off = 8 + 4 + 4 + 8
    typeid, off = _read_nodeid(frame, off)
    tid = int(typeid.split("i=")[-1])
    return tid, frame, off


def _recv_frame(sock) -> bytes:
    head = b""
    while len(head) < 8:
        c = sock.recv(8 - len(head))
        if not c:
            raise ConnectionError("소켓 종료")
        head += c
    (size,) = struct.unpack_from("<I", head, 4)
    rest = b""
    while len(rest) < size - 8:
        c = sock.recv(size - 8 - len(rest))
        if not c:
            raise ConnectionError("소켓 종료")
        rest += c
    return head + rest


def session_browse_read(host: str, port: int, read_targets: list[str],
                        endpoint_url: str = "opc.tcp://target:4840",
                        timeout: float = 5.0) -> tuple[list[str], dict]:
    """익명 OPC UA 세션으로 Browse + Read 를 수행(전체 실 핸드셰이크).

    반환: (browse 로 발견한 NodeId 목록, {요청노드: 값}). 실제 클라이언트가 하는
    HEL→ACK→OPN→CreateSession→ActivateSession(Anonymous)→Browse→Read 흐름 그대로.
    """
    import socket
    chan = 1; token = 1; seq = 1; rid = 1
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(build_hello(endpoint_url))
        _recv_frame(sock)                                    # ACK
        # OPN (Asymmetric None) — 최소 요청
        opn_sec = _ua_string(SECURITY_POLICY_NONE) + _bytestring(None) + _bytestring(None)
        opn_seq = struct.pack("<II", seq, rid)
        # OpenSecureChannelRequest: RequestHeader + ClientProtocolVersion + RequestType(Issue=0)
        #   + SecurityMode(None=1) + ClientNonce(null) + RequestedLifetime
        opn_inner = (bytes([0x01, 0x00]) + _u16(446)         # OpenSecureChannelRequest TypeId
                     + _client_request_header("i=0", rid)
                     + _u32(0) + _u32(0) + _u32(1) + _bytestring(None) + _u32(3600000))
        sock.sendall(_frame(b"OPN", _u32(0) + opn_sec + opn_seq + opn_inner))
        _recv_frame(sock)                                    # OPN response
        seq += 1; rid += 1

        def call(req_typeid_name: str, service_body: bytes, auth="i=0"):
            nonlocal seq, rid
            body = _client_request_header(auth, rid) + service_body
            sock.sendall(_client_msg(chan, token, seq, rid, SVC[req_typeid_name], body))
            frame = _recv_frame(sock)
            seq += 1; rid += 1
            return frame

        # CreateSession (서버가 RequestHeader 뒤 파라미터를 파싱하지 않으므로 빈 바디 허용)
        frame = call("CreateSessionRequest", b"")
        tid, buf, off = _parse_msg_service(frame)
        off = _skip_response_header(buf, off)
        _session_id, off = _read_nodeid(buf, off)
        auth_token, off = _read_nodeid(buf, off)             # AuthenticationToken

        # ActivateSession (Anonymous)
        call("ActivateSessionRequest", b"", auth=auth_token)

        # Browse
        frame = call("BrowseRequest", b"", auth=auth_token)
        tid, buf, off = _parse_msg_service(frame)
        browsed = _parse_browse_refs(buf, off)

        # Read
        values = {}
        if read_targets:
            rb = _f64(0.0) + _u32(0) + _u32(len(read_targets))
            for n in read_targets:
                rb += _nodeid(n) + _u32(13) + _ua_string(None) + _u16(0) + _ua_string(None)
            frame = call("ReadRequest", rb, auth=auth_token)
            tid, buf, off = _parse_msg_service(frame)
            values = dict(zip(read_targets, _parse_read_values(buf, off)))
    return browsed, values


def _parse_browse_refs(buf: bytes, off: int) -> list[str]:
    off = _skip_response_header(buf, off)
    (nresults,) = struct.unpack_from("<i", buf, off); off += 4
    nodes = []
    for _ in range(max(0, nresults)):
        off += 4                                             # StatusCode
        _cp, off = _read_ua_string(buf, off)                 # ContinuationPoint(ByteString 형식 동일)
        (nrefs,) = struct.unpack_from("<i", buf, off); off += 4
        for _ in range(max(0, nrefs)):
            _rt, off = _read_nodeid(buf, off)                # ReferenceTypeId
            off += 1                                         # IsForward
            node, off = _read_nodeid(buf, off)               # NodeId(ExpandedNodeId)
            off += 2; _bn, off = _read_ua_string(buf, off)   # BrowseName
            off += 1; _dt, off = _read_ua_string(buf, off)   # DisplayName(LocalizedText mask+text)
            off += 4                                         # NodeClass
            _td, off = _read_nodeid(buf, off)                # TypeDefinition
            nodes.append(node)
    return nodes


def _parse_read_values(buf: bytes, off: int) -> list:
    off = _skip_response_header(buf, off)
    (n,) = struct.unpack_from("<i", buf, off); off += 4
    out = []
    for _ in range(max(0, n)):
        mask = buf[off]; off += 1
        if not (mask & 0x01):
            out.append(None); continue
        vtype = buf[off]; off += 1
        if vtype == 12:                                      # String
            s, off = _read_ua_string(buf, off); out.append(s)
        elif vtype == 11:                                    # Double
            (v,) = struct.unpack_from("<d", buf, off); off += 8; out.append(v)
        elif vtype == 6:                                     # Int32
            (v,) = struct.unpack_from("<I", buf, off); off += 4; out.append(v)
        else:
            out.append(None)
    return out
