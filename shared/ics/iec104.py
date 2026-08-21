"""
IEC 60870-5-104 (IEC 104) 최소 인코더/파서 — 실 APCI/ASDU 프레이밍
==================================================================
전력 원격제어(SCADA↔RTU)의 사실상 표준. TCP:2404. Wireshark 가 `104apci`/`104asdu` 로
디섹션한다. 여기서는 포렌식 캡처 합성에 필요한 I-format APDU + 단일/제어 ASDU 를 실제
바이트로 인코딩한다(리틀엔디언 정보객체 주소).

APCI(I-format): START(0x68) + ApduLen(1) + control(4: send/recv 시퀀스).
ASDU: TypeID(1) + VSQ(1) + COT(2) + CommonAddr(2) + InfoObjects(IOA 3B + 정보요소…).
정직한 경계: 상호운용 최소셋(자체 파서와 왕복). shared/ics 모듈 철학 동일.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

IEC104_DEFAULT_PORT = 2404

# 대표 TypeID
M_SP_NA_1 = 1      # single-point information
C_SC_NA_1 = 45     # single command
C_DC_NA_1 = 46     # double command
C_BO_NA_1 = 51     # bitstring of 32 bit command
CONTROL_TYPES = {45, 46, 47, 48, 49, 50, 51}


def build_i_apdu(asdu: bytes, send_seq: int = 0, recv_seq: int = 0) -> bytes:
    """I-format APDU: APCI(0x68+len+control) + ASDU."""
    control = struct.pack("<HH", (send_seq << 1) & 0xFFFE, (recv_seq << 1) & 0xFFFE)
    body = control + asdu
    return bytes([0x68, len(body) & 0xFF]) + body


def build_asdu(type_id: int, cot: int, common_addr: int, ioa: int,
               info: bytes, originator: int = 0) -> bytes:
    """단일 정보객체 ASDU. VSQ = 1개 객체(SQ=0)."""
    vsq = 0x01
    cot_field = struct.pack("<BB", cot & 0xFF, originator & 0xFF)
    ca = struct.pack("<H", common_addr & 0xFFFF)
    ioa_b = struct.pack("<I", ioa & 0xFFFFFF)[:3]      # 3옥텟 IOA(LSB first)
    return bytes([type_id & 0xFF, vsq]) + cot_field + ca + ioa_b + info


@dataclass
class ParsedAsdu:
    type_id: int
    cot: int
    common_addr: int
    ioa: int
    info: bytes


def parse_apdu(apdu: bytes) -> Optional[ParsedAsdu]:
    """I-format APDU → ParsedAsdu. U/S-format·비 0x68 은 None."""
    if len(apdu) < 6 or apdu[0] != 0x68:
        return None
    length = apdu[1]
    body = apdu[2:2 + length]
    if len(body) < 4:
        return None
    ctrl0 = body[0]
    if ctrl0 & 0x01:                      # I-format 은 send_seq LSB=0
        return None
    asdu = body[4:]
    if len(asdu) < 9:
        return None
    type_id, _vsq = asdu[0], asdu[1]
    cot = asdu[2]
    common_addr = struct.unpack("<H", asdu[4:6])[0]
    ioa = int.from_bytes(asdu[6:9], "little")
    info = asdu[9:]
    return ParsedAsdu(type_id, cot, common_addr, ioa, info)
