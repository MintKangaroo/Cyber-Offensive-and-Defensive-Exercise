"""
Foundation Fieldbus H1 최소 인코더/파서 — 실 DLPDU(데이터링크) 구조
==================================================================
프로세스 자동화(연속공정)의 필드버스. H1 은 31.25kbps 시리얼 버스로 **IP 가 아니다** —
표준 pcap 링크타입이 없어 Wireshark 가 네이티브로 디섹션하지 않는다. 여기서는 실 FF-H1
DLPDU(FrameControl + dest/src 노드주소 + DLSDU) 바이트를 만들어 **합성 L2 캡슐화**(사설
EtherType)로 pcap 에 담는다(정직한 경계: 실장비 무관 합성, 프로토콜 구조만 실제).

DLPDU: FC(1) + dest_addr(1) + src_addr(1) + DLSDU(응용 데이터).
DLSDU(본 훈련용): op(1) + block(pstr) + param(pstr) + value(pstr) + token(pstr).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

FF_ETHERTYPE = 0x88FF          # 사설 EtherType(합성 캡슐화)
FC_DT = 0x10                   # Data
FC_CD = 0x08                   # Compel Data
OP_READ = 0x01
OP_WRITE = 0x02


def _pstr(s) -> bytes:
    b = s.encode() if isinstance(s, str) else s
    return bytes([len(b) & 0xFF]) + b


def _read_pstr(data: bytes, off: int) -> tuple[bytes, int]:
    ln = data[off]
    return data[off + 1:off + 1 + ln], off + 1 + ln


def build_dlsdu(op: int, block: str, param: str, value: str, token: bytes = b"") -> bytes:
    return bytes([op]) + _pstr(block) + _pstr(param) + _pstr(value) + _pstr(token)


def build_dlpdu(fc: int, dest: int, src: int, dlsdu: bytes) -> bytes:
    return bytes([fc & 0xFF, dest & 0xFF, src & 0xFF]) + dlsdu


@dataclass
class ParsedDlpdu:
    fc: int
    dest: int
    src: int
    op: Optional[int]
    block: str
    param: str
    value: str
    token: bytes


def parse_dlpdu(frame: bytes) -> Optional[ParsedDlpdu]:
    """FF-H1 DLPDU → 필드. DLSDU 가 본 훈련 포맷이 아니면 op/block 등은 비어있다."""
    if len(frame) < 3:
        return None
    fc, dest, src = frame[0], frame[1], frame[2]
    dlsdu = frame[3:]
    op = block = param = value = None
    token = b""
    try:
        if dlsdu:
            op = dlsdu[0]
            off = 1
            b, off = _read_pstr(dlsdu, off)
            p, off = _read_pstr(dlsdu, off)
            v, off = _read_pstr(dlsdu, off)
            t, off = _read_pstr(dlsdu, off)
            block, param, value, token = b.decode(), p.decode(), v.decode(), t
    except (IndexError, UnicodeDecodeError):
        pass
    return ParsedDlpdu(fc, dest, src, op, block or "", param or "", value or "", token)
