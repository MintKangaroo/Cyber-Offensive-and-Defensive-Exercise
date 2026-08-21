"""
EtherNet/IP + CIP 최소 인코더/파서 — 실 ENIP 캡슐화 프레이밍
============================================================
산업 이더넷(Rockwell 등)의 사실상 표준. TCP:44818. Wireshark 가 ENIP/CIP 로 디섹션한다.
여기서는 포렌식 캡처 합성에 필요한 SendRRData 캡슐화 + CIP 요청(GetAttributeSingle/
SetAttributeSingle)을 실제 바이트로 인코딩한다.

ENIP 헤더(24B): command(2) len(2) session(4) status(4) sender_context(8) options(4).
SendRRData(0x6F): iface handle(4)=0 + timeout(2) + CPF(item count + null addr + unconn data).
CIP 요청: service(1) + path_size(1 words) + EPATH(class/instance/attribute) + service data.
정직한 경계: 상호운용 최소셋(자체 파서와 왕복).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

ENIP_DEFAULT_PORT = 44818
CMD_SEND_RR_DATA = 0x6F
SVC_GET_ATTR_SINGLE = 0x0E
SVC_SET_ATTR_SINGLE = 0x10


def _epath(class_id: int, instance: int, attribute: Optional[int]) -> bytes:
    path = bytes([0x20, class_id & 0xFF, 0x24, instance & 0xFF])
    if attribute is not None:
        path += bytes([0x30, attribute & 0xFF])
    return path


def build_cip_request(service: int, class_id: int, instance: int,
                      attribute: Optional[int], data: bytes = b"") -> bytes:
    path = _epath(class_id, instance, attribute)
    return bytes([service & 0xFF, len(path) // 2]) + path + data


def build_sendrrdata(cip: bytes, session: int = 0x01020304) -> bytes:
    """CIP 요청을 SendRRData(ENIP)로 캡슐화한 완전 프레임."""
    cpf = struct.pack("<H", 2)                        # item count
    cpf += struct.pack("<HH", 0x0000, 0)              # null address item
    cpf += struct.pack("<HH", 0x00B2, len(cip)) + cip  # unconnected data item
    body = struct.pack("<IH", 0, 0) + cpf             # iface handle + timeout + CPF
    header = struct.pack("<HHII", CMD_SEND_RR_DATA, len(body), session, 0)
    header += b"\x00" * 8 + struct.pack("<I", 0)      # sender context + options
    return header + body


@dataclass
class ParsedCip:
    service: int
    class_id: int
    instance: int
    attribute: Optional[int]
    data: bytes


def parse_sendrrdata(frame: bytes) -> Optional[ParsedCip]:
    """SendRRData ENIP 프레임 → CIP 요청 파싱. 아니면 None."""
    if len(frame) < 24 or struct.unpack("<H", frame[:2])[0] != CMD_SEND_RR_DATA:
        return None
    body = frame[24:]
    if len(body) < 6:
        return None
    # body: iface(4) timeout(2) CPF...
    off = 6
    item_count = struct.unpack("<H", body[off:off + 2])[0]
    off += 2
    cip = b""
    for _ in range(item_count):
        if off + 4 > len(body):
            break
        type_id, ln = struct.unpack("<HH", body[off:off + 4])
        off += 4
        if type_id == 0x00B2:
            cip = body[off:off + ln]
        off += ln
    if len(cip) < 2:
        return None
    service = cip[0]
    path_words = cip[1]
    path = cip[2:2 + path_words * 2]
    data = cip[2 + path_words * 2:]
    class_id = path[1] if len(path) >= 2 and path[0] == 0x20 else None
    instance = path[3] if len(path) >= 4 and path[2] == 0x24 else None
    attribute = path[5] if len(path) >= 6 and path[4] == 0x30 else None
    return ParsedCip(service & 0x7F, class_id, instance, attribute, data)
