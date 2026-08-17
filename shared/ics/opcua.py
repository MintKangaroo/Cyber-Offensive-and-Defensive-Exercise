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
  - 세션/Read 등 응용 서비스는 별도(기존 HTTP 목업이 REF-001 앱계층 담당). 여기서 커버 X.
전 인코딩은 OPC UA Binary(리틀엔디언). 클라이언트 헬퍼로 테스트/라이브 검증.
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


async def serve(host: str = "0.0.0.0", port: int = OPCUA_DEFAULT_PORT,
                endpoint_url: str = "opc.tcp://twin:4840",
                on_connect=None) -> asyncio.AbstractServer:
    """OPC UA/TCP 서버: HEL→ACK, OPN→OpenSecureChannelResponse. on_connect(peer)로 접속 통지."""
    sc = SecureChannelState()

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
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
                            on_connect(writer.get_extra_info("peername"))
                        except Exception:
                            pass
                    writer.write(build_acknowledge(hello)); await writer.drain()
                elif mtype == b"OPN":
                    writer.write(build_open_secure_channel_response(sc)); await writer.drain()
                elif mtype == b"CLO":
                    break
                else:
                    # 세션/Read 등 MSG는 미구현 → 정상적으로 채널 종료(honest scope).
                    writer.write(build_error(0x80730000, "Bad_ServiceUnsupported"))
                    await writer.drain(); break
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(_handle, host, port)
