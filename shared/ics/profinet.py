"""
실제 Profinet DCP(최소 서브셋) — 순수 프레임 인코딩 + asyncio 서버
====================================================================
스마트팩토리 트윈을 "진짜 Profinet DCP 를 말하는 장치"로 만든다. Profinet DCP
(Discovery and Configuration Protocol) 는 무-엔지니어링(engineering) 상태의 IO 디바이스를
네트워크에서 발견하고(Identify) 스테이션 이름/IP 를 읽고/쓰는(Get/Set) 계층이다.

⚠️ 전송(transport) 정직성:
    실 Profinet DCP 는 원래 raw-Ethernet L2(EtherType 0x8892) 멀티캐스트다. 컨테이너 환경에서
    L2 raw 프레임은 비현실적이라, 본 모듈은 **DCP 프레임 자체는 규격대로 정확히 인코딩**하되
    이를 **TCP(기본 34964)** 위로 나른다. 34964 는 실제 Profinet 의 acyclic DCE/RPC(UDP)
    포트로, 여기서는 DCP 프레임을 얹는 스코프드 전송으로 재사용한다. 즉 프레임/TLV 패킹은
    실물과 동일하고 오직 하위 전송만 다르다(OPC UA 트윈의 스코프드 전송 정직성과 동일한 태도).

DCP 프레임 구조(대엔디안):
    ServiceID(1)  : Identify=5, Get=3, Set=4
    ServiceType(1): request=0, response=1(+success)
    Xid(4)        : 요청/응답 상관(correlation) id
    ResponseDelay(2)
    DCPDataLength(2): 이하 블록 영역 바이트 수
    Blocks[]      : TLV — Option(1), Suboption(1), DCPBlockLength(2),
                    [BlockInfo(2)=응답 블록], Value(...), 짝수정렬 패딩(1)

지원:
    - DCP Identify(All) 요청 → Identify 응답(스테이션 이름/벤더·디바이스 id/역할/IP 블록)
    - DCP Get(Option/Suboption) 요청 → 해당 블록 응답(NameOfStation 등)

`handle_dcp(device, frame)` 는 소켓과 무관한 순수함수라 단위 테스트가 쉽다. `serve()` 가
DCP 자체-프레이밍(DCPDataLength)을 이용해 TCP 로 노출하고, 요청마다 on_request 콜백을 불러
트윈이 SIEM 로그·이벤트(디바이스 발견 recon)를 낼 수 있게 한다.
"""
from __future__ import annotations

import asyncio
import socket
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

# ── 서비스/타입 상수 ──────────────────────────────────────────────
SERVICE_GET = 3
SERVICE_SET = 4
SERVICE_IDENTIFY = 5
TYPE_REQUEST = 0
TYPE_RESPONSE = 1

# ── DCP 옵션/서브옵션(규격 값) ────────────────────────────────────
OPT_IP = 0x01
SUB_IP_PARAM = 0x02              # IP + 서브넷 + 게이트웨이
OPT_DEVICE = 0x02
SUB_DEV_VENDOR = 0x01            # Type of Station(제조사 문자열)
SUB_DEV_NAMEOFSTATION = 0x02     # Name of Station
SUB_DEV_ID = 0x03               # VendorID(2) + DeviceID(2)
SUB_DEV_ROLE = 0x04             # 디바이스 역할(1) + 예약(1)
OPT_ALL = 0xFF
SUB_ALL = 0xFF                  # All Selector(Identify all)

_HEADER_FMT = ">BBIHH"
HEADER_LEN = struct.calcsize(_HEADER_FMT)   # 10


@dataclass
class DcpHeader:
    service_id: int
    service_type: int
    xid: int
    response_delay: int
    data_length: int


@dataclass
class ProfinetDevice:
    """DCP 로 노출되는 IO 디바이스의 신원(identity)."""
    station_name: str
    vendor_id: int
    device_id: int
    ip: str
    role: int = 0x01                       # 0x01=IO Device, 0x02=IO Controller
    vendor_value: str = "CyberRange PLC"   # Type of Station(제조사/타입 문자열)
    subnet: str = "255.255.255.0"
    gateway: str = "0.0.0.0"


# ── IP 헬퍼 ───────────────────────────────────────────────────────
def _ip_bytes(dotted: str) -> bytes:
    return socket.inet_aton(dotted)


def _ip_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


# ── 프레임/블록 인코딩(순수) ──────────────────────────────────────
def encode_dcp_header(service_id: int, service_type: int, xid: int,
                      data_length: int, response_delay: int = 0) -> bytes:
    return struct.pack(_HEADER_FMT, service_id, service_type, xid, response_delay, data_length)


def encode_block(option: int, suboption: int, value: bytes,
                 block_info: Optional[int] = None) -> bytes:
    """TLV 블록 1개. block_info(2B)는 응답 블록에만 붙고 DCPBlockLength 에 포함된다.
    payload 길이가 홀수면 짝수 정렬 패딩 1B(길이에는 미포함)."""
    payload = b""
    if block_info is not None:
        payload += struct.pack(">H", block_info)
    payload += value
    block = struct.pack(">BBH", option, suboption, len(payload)) + payload
    if len(payload) % 2:            # 블록헤더 4B 는 짝수 → payload 홀수면 전체 홀수
        block += b"\x00"
    return block


def encode_dcp_frame(service_id: int, service_type: int, xid: int,
                     blocks: list[bytes], response_delay: int = 0) -> bytes:
    body = b"".join(blocks)
    return encode_dcp_header(service_id, service_type, xid, len(body), response_delay) + body


def parse_dcp_header(frame: bytes) -> DcpHeader:
    if len(frame) < HEADER_LEN:
        raise ValueError("short DCP frame")
    sid, stype, xid, delay, dlen = struct.unpack(_HEADER_FMT, frame[:HEADER_LEN])
    return DcpHeader(sid, stype, xid, delay, dlen)


def parse_blocks(body: bytes, has_block_info: bool = True) -> list[tuple[int, int, bytes]]:
    """블록 영역 → [(option, suboption, value)]. value 는 BlockInfo 를 벗겨낸 실제 값.
    응답 블록(has_block_info=True)은 앞 2B 가 BlockInfo 라 제거한다."""
    out: list[tuple[int, int, bytes]] = []
    i = 0
    while i + 4 <= len(body):
        option, suboption, blen = struct.unpack(">BBH", body[i:i + 4])
        i += 4
        content = body[i:i + blen]
        i += blen
        if blen % 2:                # 짝수 정렬 패딩 스킵
            i += 1
        if has_block_info and len(content) >= 2:
            content = content[2:]   # BlockInfo 제거
        out.append((option, suboption, content))
    return out


# ── 디바이스 응답 블록 조립 ───────────────────────────────────────
def _device_blocks(device: ProfinetDevice) -> list[bytes]:
    return [
        encode_block(OPT_DEVICE, SUB_DEV_VENDOR, device.vendor_value.encode("ascii", "replace"), block_info=0),
        encode_block(OPT_DEVICE, SUB_DEV_NAMEOFSTATION, device.station_name.encode("ascii", "replace"), block_info=0),
        encode_block(OPT_DEVICE, SUB_DEV_ID, struct.pack(">HH", device.vendor_id & 0xFFFF, device.device_id & 0xFFFF), block_info=0),
        encode_block(OPT_DEVICE, SUB_DEV_ROLE, struct.pack(">BB", device.role & 0xFF, 0), block_info=0),
        encode_block(OPT_IP, SUB_IP_PARAM,
                     _ip_bytes(device.ip) + _ip_bytes(device.subnet) + _ip_bytes(device.gateway),
                     block_info=0),
    ]


def _get_block(device: ProfinetDevice, option: int, suboption: int) -> Optional[bytes]:
    if option == OPT_DEVICE and suboption == SUB_DEV_NAMEOFSTATION:
        return encode_block(option, suboption, device.station_name.encode("ascii", "replace"), block_info=0)
    if option == OPT_DEVICE and suboption == SUB_DEV_VENDOR:
        return encode_block(option, suboption, device.vendor_value.encode("ascii", "replace"), block_info=0)
    if option == OPT_DEVICE and suboption == SUB_DEV_ID:
        return encode_block(option, suboption, struct.pack(">HH", device.vendor_id & 0xFFFF, device.device_id & 0xFFFF), block_info=0)
    if option == OPT_DEVICE and suboption == SUB_DEV_ROLE:
        return encode_block(option, suboption, struct.pack(">BB", device.role & 0xFF, 0), block_info=0)
    if option == OPT_IP and suboption == SUB_IP_PARAM:
        return encode_block(option, suboption,
                            _ip_bytes(device.ip) + _ip_bytes(device.subnet) + _ip_bytes(device.gateway),
                            block_info=0)
    return None


# ── 순수 핸들러 ───────────────────────────────────────────────────
def handle_dcp(device: ProfinetDevice, frame: bytes) -> bytes:
    """DCP 요청 프레임 → 응답 프레임(bytes). 소켓 무관 순수함수. 요청이 아니거나
    미지원이면 b"" 반환."""
    try:
        hdr = parse_dcp_header(frame)
    except (ValueError, struct.error):
        return b""
    if hdr.service_type != TYPE_REQUEST:
        return b""
    body = frame[HEADER_LEN:HEADER_LEN + hdr.data_length]

    if hdr.service_id == SERVICE_IDENTIFY:
        # Identify(all/특정 무관) → 전체 디바이스 블록으로 응답
        return encode_dcp_frame(SERVICE_IDENTIFY, TYPE_RESPONSE, hdr.xid, _device_blocks(device))

    if hdr.service_id == SERVICE_GET:
        # Get 요청 본문 = (Option, Suboption) 쌍의 나열(각 2B, 값/길이 없음)
        blocks: list[bytes] = []
        for i in range(0, len(body) - 1, 2):
            b = _get_block(device, body[i], body[i + 1])
            if b:
                blocks.append(b)
        return encode_dcp_frame(SERVICE_GET, TYPE_RESPONSE, hdr.xid, blocks)

    return b""


# ── 클라이언트 헬퍼 ───────────────────────────────────────────────
def build_dcp_identify_all(xid: int = 1) -> bytes:
    """DCP Identify-All 요청: All Selector 블록(0xFF/0xFF, len=0)."""
    sel = encode_block(OPT_ALL, SUB_ALL, b"")   # BlockInfo 없음(요청 셀렉터)
    return encode_dcp_frame(SERVICE_IDENTIFY, TYPE_REQUEST, xid, [sel])


def build_dcp_get(option: int, suboption: int, xid: int = 1) -> bytes:
    """DCP Get 요청: 원하는 (Option, Suboption) 쌍(2B)."""
    body = struct.pack(">BB", option, suboption)
    return encode_dcp_header(SERVICE_GET, TYPE_REQUEST, xid, len(body)) + body


def parse_dcp_response(frame: bytes) -> dict:
    """Identify/Get 응답 프레임 → 사람이 읽기 좋은 dict.
    반환 키(존재 시): service_id, xid, station_name, vendor_id, device_id, ip,
    subnet, gateway, role, vendor_value, options(원블록 목록)."""
    hdr = parse_dcp_header(frame)
    body = frame[HEADER_LEN:HEADER_LEN + hdr.data_length]
    out: dict = {"service_id": hdr.service_id, "service_type": hdr.service_type,
                 "xid": hdr.xid, "options": []}
    for option, suboption, value in parse_blocks(body, has_block_info=True):
        out["options"].append((option, suboption))
        if option == OPT_DEVICE and suboption == SUB_DEV_NAMEOFSTATION:
            out["station_name"] = value.decode("ascii", "replace")
        elif option == OPT_DEVICE and suboption == SUB_DEV_VENDOR:
            out["vendor_value"] = value.decode("ascii", "replace")
        elif option == OPT_DEVICE and suboption == SUB_DEV_ID and len(value) >= 4:
            vid, did = struct.unpack(">HH", value[:4])
            out["vendor_id"], out["device_id"] = vid, did
        elif option == OPT_DEVICE and suboption == SUB_DEV_ROLE and len(value) >= 1:
            out["role"] = value[0]
        elif option == OPT_IP and suboption == SUB_IP_PARAM and len(value) >= 12:
            out["ip"] = _ip_str(value[0:4])
            out["subnet"] = _ip_str(value[4:8])
            out["gateway"] = _ip_str(value[8:12])
    return out


# ── asyncio TCP 서버 ──────────────────────────────────────────────
# on_request(service_id: int, service_type: int, xid: int, body: bytes) -> None
RequestCB = Callable[[int, int, int, bytes], None]


async def _handle_client(device: ProfinetDevice, on_request: Optional[RequestCB],
                         reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            header = await reader.readexactly(HEADER_LEN)
            sid, stype, xid, delay, dlen = struct.unpack(_HEADER_FMT, header)
            body = await reader.readexactly(dlen) if dlen else b""
            if on_request:
                try:
                    on_request(sid, stype, xid, body)
                except Exception:
                    pass
            resp = handle_dcp(device, header + body)
            if resp:
                writer.write(resp)
                await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def serve(device: ProfinetDevice, host: str = "0.0.0.0", port: int = 34964,
                on_request: Optional[RequestCB] = None) -> asyncio.AbstractServer:
    """Profinet DCP-over-TCP 서버 기동(비차단). 반환된 server 를 close() 로 종료."""
    return await asyncio.start_server(
        lambda r, w: _handle_client(device, on_request, r, w), host, port)
