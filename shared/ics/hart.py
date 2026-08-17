"""
실 HART-IP(HART over TCP/UDP) 필드 디바이스 — 최소 상호운용 서브셋
====================================================================
정유/석유화학 Tank Farm 의 스마트 트랜스미터가 쓰는 HART-IP(기본 포트 5094)를 트윈이
'실제로' 말하게 한다. DNP3(shared/ics/dnp3.py)/Modbus 와 동일한 설계 철학:
소켓과 무관한 순수 함수(handle_hart_ip)로 두어 단위 테스트가 쉽고, serve()가 TCP 프레이밍만
담당한다.

구현 범위(진짜 프로토콜, 상호운용 가능한 최소셋):
  - HART-IP 헤더(8바이트): version(1)=1, message-type(1: 0=request/1=response/2=publish),
    message-id(1: 0=session-init/3=token-passing-PDU), status(1),
    sequence-number(2 BE), byte-count(2 BE, 헤더 포함 전체 길이).
  - HART 명령 PDU(short frame): delimiter(1) + address(1) + command(1) + byte-count(1)
    + data(n) + checksum(1). checksum = delimiter~data 전 바이트의 XOR.
  - 세션 개시(message-id 0) → 응답 에코.
  - Command 1 (Read Primary Variable) → PV 단위코드 + PV(IEEE754 float BE).
  - Command 3 (Read Dynamic Variables) → 루프전류 + PV/SV/TV/QV(각 단위코드+float).
클라이언트 헬퍼(build_session_init/build_read_command/parse_hart_response)로 테스트/검증.

실제 산업장비와 연결되지 않으며 모든 값은 합성 더미다. HART 도 Modbus/DNP3 처럼
insecure-by-design(무인증) 을 의도적으로 재현한다.
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

HART_IP_DEFAULT_PORT = 5094

# HART-IP message-type
MSG_TYPE_REQUEST = 0
MSG_TYPE_RESPONSE = 1
MSG_TYPE_PUBLISH = 2

# HART-IP message-id
MSG_ID_SESSION_INIT = 0
MSG_ID_KEEPALIVE = 1
MSG_ID_TOKEN_PDU = 3      # token-passing PDU (HART 명령을 감싼다)

# HART PDU delimiter (short frame)
DELIM_STX = 0x02          # 요청(마스터→필드)
DELIM_ACK = 0x06          # 응답(필드→마스터)

# HART 응답 코드
RC_SUCCESS = 0x00
RC_CMD_NOT_IMPLEMENTED = 0x40


# ---------------------------------------------------------------------------
# HART-IP 헤더
# ---------------------------------------------------------------------------
@dataclass
class HartIpHeader:
    version: int
    msg_type: int
    msg_id: int
    status: int
    seq: int
    byte_count: int          # 헤더(8) 포함 전체 메시지 길이


def build_hart_ip_header(msg_type: int, msg_id: int, seq: int, byte_count: int,
                         version: int = 1, status: int = 0) -> bytes:
    """HART-IP 8바이트 헤더 인코드. byte_count 는 헤더 포함 전체 길이(BE)."""
    return struct.pack(">BBBBHH", version, msg_type, msg_id, status, seq, byte_count)


def parse_hart_ip_header(data: bytes) -> Optional[HartIpHeader]:
    """HART-IP 헤더 디코드. 8바이트 미만이면 None."""
    if len(data) < 8:
        return None
    version, msg_type, msg_id, status, seq, byte_count = struct.unpack(">BBBBHH", data[:8])
    return HartIpHeader(version, msg_type, msg_id, status, seq, byte_count)


# ---------------------------------------------------------------------------
# HART 명령 PDU (short frame) + 체크섬
# ---------------------------------------------------------------------------
def hart_checksum(body: bytes) -> int:
    """HART 체크섬 = delimiter 부터 마지막 data 바이트까지 전 바이트의 XOR."""
    c = 0
    for b in body:
        c ^= b
    return c & 0xFF


def build_hart_pdu(delimiter: int, address: int, command: int, data: bytes) -> bytes:
    """HART short-frame PDU 인코드(끝에 XOR 체크섬 부착)."""
    body = bytes([delimiter & 0xFF, address & 0xFF, command & 0xFF, len(data) & 0xFF]) + data
    return body + bytes([hart_checksum(body)])


@dataclass
class HartPdu:
    delimiter: int
    address: int
    command: int
    data: bytes


def parse_hart_pdu(pdu: bytes) -> Optional[HartPdu]:
    """HART short-frame PDU 디코드 + 체크섬 검증. 유효하지 않으면 None."""
    if len(pdu) < 5:
        return None
    delimiter, address, command, byte_count = pdu[0], pdu[1], pdu[2], pdu[3]
    end = 4 + byte_count
    if len(pdu) < end + 1:
        return None
    data = pdu[4:end]
    checksum = pdu[end]
    if hart_checksum(pdu[:end]) != checksum:
        return None
    return HartPdu(delimiter, address, command, data)


# ---------------------------------------------------------------------------
# 필드 디바이스 상태
# ---------------------------------------------------------------------------
@dataclass
class HartField:
    """HART 스마트 트랜스미터 상태. 4개 동적 변수(PV/SV/TV/QV) + 루프 전류(mA)."""
    pv: float = 63.2         # Primary Variable  — 예: 탱크 레벨(%)
    sv: float = 25.0         # Secondary Variable — 예: 온도(°C)
    tv: float = 1.2          # Tertiary Variable  — 예: 압력(bar)
    qv: float = 0.0          # Quaternary Variable
    pv_unit: int = 57        # HART 단위코드 57 = percent
    sv_unit: int = 32        # 32 = degrees Celsius
    tv_unit: int = 220       # 220 = bar
    qv_unit: int = 0
    loop_current: float = 12.0   # 아날로그 4-20mA 루프 전류
    polling_address: int = 0
    device_status: int = 0
    # on_command(command_no, request_data): HART 명령 수신 시 호출(트윈 SIEM 로그·이벤트 발행용)
    on_command: Optional[Callable[[int, bytes], None]] = None


def _dynamic_vars_block(dev: HartField) -> bytes:
    """Command 3 동적변수 블록: 루프전류(float) + [단위코드+float]×4(PV/SV/TV/QV)."""
    out = struct.pack(">f", dev.loop_current)
    for unit, val in ((dev.pv_unit, dev.pv), (dev.sv_unit, dev.sv),
                      (dev.tv_unit, dev.tv), (dev.qv_unit, dev.qv)):
        out += bytes([unit & 0xFF]) + struct.pack(">f", val)
    return out


def handle_hart_command(dev: HartField, pdu: HartPdu) -> bytes:
    """HART 명령 PDU → 응답 PDU. 순수함수(소켓 무관). Command 1/3 지원."""
    if dev.on_command:
        try:
            dev.on_command(pdu.command, pdu.data)
        except Exception:
            pass
    status = bytes([RC_SUCCESS, dev.device_status & 0xFF])  # 응답코드 + 필드 디바이스 상태
    if pdu.command == 1:            # Read Primary Variable
        data = status + bytes([dev.pv_unit & 0xFF]) + struct.pack(">f", dev.pv)
    elif pdu.command == 3:          # Read Dynamic Variables
        data = status + _dynamic_vars_block(dev)
    else:                            # 미지원 명령 → 응답코드 64
        data = bytes([RC_CMD_NOT_IMPLEMENTED, dev.device_status & 0xFF])
    return build_hart_pdu(DELIM_ACK, dev.polling_address, pdu.command, data)


def handle_hart_ip(dev: HartField, msg: bytes) -> bytes:
    """HART-IP 메시지 → 응답 바이트. 순수함수(소켓 무관).

    - message-id 0(session-init): 페이로드 에코 응답.
    - message-id 3(token-passing PDU): 내부 HART 명령 처리 후 응답 PDU 감싸기.
    """
    hdr = parse_hart_ip_header(msg)
    if hdr is None:
        return b""
    payload = msg[8:]

    if hdr.msg_id == MSG_ID_SESSION_INIT:
        # 세션 개시 응답: 마스터 파라미터(마스터 타입·비활성 타이머)를 에코.
        return build_hart_ip_header(MSG_TYPE_RESPONSE, MSG_ID_SESSION_INIT,
                                    hdr.seq, 8 + len(payload)) + payload

    if hdr.msg_id == MSG_ID_TOKEN_PDU:
        pdu = parse_hart_pdu(payload)
        if pdu is None:
            return build_hart_ip_header(MSG_TYPE_RESPONSE, MSG_ID_TOKEN_PDU,
                                        hdr.seq, 8, status=1)
        resp_pdu = handle_hart_command(dev, pdu)
        return build_hart_ip_header(MSG_TYPE_RESPONSE, MSG_ID_TOKEN_PDU,
                                    hdr.seq, 8 + len(resp_pdu)) + resp_pdu

    # 미지원 message-id → status=1 로 거부.
    return build_hart_ip_header(MSG_TYPE_RESPONSE, hdr.msg_id, hdr.seq, 8, status=1)


# ---------------------------------------------------------------------------
# 클라이언트 헬퍼(마스터/게이트웨이 측) — 테스트/라이브 검증용
# ---------------------------------------------------------------------------
def build_session_init(seq: int = 0, master_type: int = 1,
                       inactivity_timer_ms: int = 30000) -> bytes:
    """HART-IP 세션 개시 요청. 페이로드 = 마스터 타입(1) + 비활성 종료 타이머(4 BE)."""
    payload = bytes([master_type & 0xFF]) + struct.pack(">I", inactivity_timer_ms & 0xFFFFFFFF)
    return build_hart_ip_header(MSG_TYPE_REQUEST, MSG_ID_SESSION_INIT,
                                seq, 8 + len(payload)) + payload


def build_read_command(cmd_no: int, seq: int = 0, polling_address: int = 0) -> bytes:
    """HART 읽기 명령(예: 1=Read PV, 3=Read Dynamic Vars)을 HART-IP 로 감싼 요청."""
    pdu = build_hart_pdu(DELIM_STX, polling_address, cmd_no, b"")
    return build_hart_ip_header(MSG_TYPE_REQUEST, MSG_ID_TOKEN_PDU,
                                seq, 8 + len(pdu)) + pdu


def parse_hart_response(msg: bytes) -> Optional[dict]:
    """HART-IP 응답 → dict. session-init/Command 1/3 를 디코드."""
    hdr = parse_hart_ip_header(msg)
    if hdr is None:
        return None
    out: dict = {"msg_type": hdr.msg_type, "msg_id": hdr.msg_id, "seq": hdr.seq,
                 "status": hdr.status}
    if hdr.msg_id != MSG_ID_TOKEN_PDU:
        return out                       # session-init 등: 헤더 정보만
    pdu = parse_hart_pdu(msg[8:])
    if pdu is None:
        return out
    out["command"] = pdu.command
    data = pdu.data
    if len(data) < 2:
        return out
    out["response_code"] = data[0]
    out["device_status"] = data[1]
    body = data[2:]
    if pdu.command == 1 and len(body) >= 5:
        out["pv_unit"] = body[0]
        out["pv"] = struct.unpack(">f", body[1:5])[0]
    elif pdu.command == 3 and len(body) >= 24:
        out["loop_current"] = struct.unpack(">f", body[0:4])[0]
        off = 4
        for name in ("pv", "sv", "tv", "qv"):
            out[f"{name}_unit"] = body[off]
            out[name] = struct.unpack(">f", body[off + 1:off + 5])[0]
            off += 5
    return out


# ---------------------------------------------------------------------------
# 서버(비차단)
# ---------------------------------------------------------------------------
async def serve(device: HartField, host: str = "0.0.0.0",
                port: int = HART_IP_DEFAULT_PORT) -> asyncio.AbstractServer:
    """HART-IP/TCP 서버 기동(비차단). 헤더의 byte-count 로 프레임 경계를 읽어 처리."""
    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                header = await reader.readexactly(8)
                hdr = parse_hart_ip_header(header)
                if hdr is None:
                    break
                remaining = hdr.byte_count - 8
                if remaining < 0:
                    break
                payload = await reader.readexactly(remaining) if remaining > 0 else b""
                resp = handle_hart_ip(device, header + payload)
                if resp:
                    writer.write(resp)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(_handle, host, port)
