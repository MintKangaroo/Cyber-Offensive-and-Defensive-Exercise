"""
IEC 61850 GOOSE 최소 인코더/파서 — 실 GOOSE(EtherType 0x88B8) 프레이밍
=====================================================================
변전소 보호 자동화의 실시간 이벤트 통보(트립 등). raw Ethernet 0x88B8 멀티캐스트. Wireshark
가 GOOSE 로 디섹션한다. 여기서는 포렌식 캡처 합성에 필요한 GOOSE PDU(gocbRef/stNum/sqNum/
allData)를 BER 로 인코딩한다.

프레임(0x88B8 뒤): APPID(2) + Length(2) + Reserved1(2) + Reserved2(2) + goosePdu(BER, tag 0x61).
goosePdu 필드: 0x80 gocbRef, 0x82 datSet, 0x85 stNum, 0x86 sqNum, 0xAB allData(불리언+옥텟열).
정직한 경계: 상호운용 최소셋(자체 파서와 왕복).
"""
from __future__ import annotations

import struct
from typing import Optional

GOOSE_ETHERTYPE = 0x88B8


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82]) + struct.pack(">H", n)


def _tlv(tag: int, val: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(val)) + val


def _int(tag: int, v: int) -> bytes:
    if v == 0:
        body = b"\x00"
    else:
        length = (v.bit_length() + 8) // 8            # 부호 비트 여유
        body = v.to_bytes(length, "big")
    return _tlv(tag, body)


def build_goose(gocb_ref: str, dat_set: str, st_num: int, sq_num: int,
                trip: bool, token: bytes = b"", appid: int = 0x0001) -> bytes:
    """GOOSE 프레임 payload(EtherType 0x88B8 뒤). allData = 불리언(트립) + 옥텟열(토큰)."""
    all_data = _tlv(0x83, b"\x01" if trip else b"\x00")   # boolean
    if token:
        all_data += _tlv(0x89, token)                     # octet string
    pdu = b""
    pdu += _tlv(0x80, gocb_ref.encode())                  # gocbRef
    pdu += _int(0x81, 2000)                               # timeAllowedToLive
    pdu += _tlv(0x82, dat_set.encode())                   # datSet
    pdu += _tlv(0x83, b"IED1")                            # goID
    pdu += _tlv(0x84, b"\x00" * 8)                        # t (UTC time)
    pdu += _int(0x85, st_num)                             # stNum
    pdu += _int(0x86, sq_num)                             # sqNum
    pdu += _tlv(0x87, b"\x00")                            # test
    pdu += _int(0x88, 1)                                  # confRev
    pdu += _tlv(0x89, b"\x00")                            # ndsCom
    pdu += _int(0x8A, 1)                                  # numDatSetEntries
    pdu += _tlv(0xAB, all_data)                           # allData
    goose_pdu = _tlv(0x61, pdu)
    length = 8 + len(goose_pdu)
    return struct.pack(">HHHH", appid, length, 0, 0) + goose_pdu


def _parse_tlvs(data: bytes) -> list[tuple[int, bytes]]:
    out = []
    i = 0
    while i + 2 <= len(data):
        tag = data[i]
        ln = data[i + 1]
        i += 2
        if ln & 0x80:
            nbytes = ln & 0x7F
            ln = int.from_bytes(data[i:i + nbytes], "big")
            i += nbytes
        out.append((tag, data[i:i + ln]))
        i += ln
    return out


def parse_goose(payload: bytes) -> Optional[dict]:
    """GOOSE payload(0x88B8 뒤) → {gocbRef, stNum, sqNum, trip, token}. 아니면 None."""
    if len(payload) < 8:
        return None
    goose_pdu = payload[8:]
    tlvs = _parse_tlvs(goose_pdu)
    pdu = next((v for t, v in tlvs if t == 0x61), None)
    if pdu is None:
        return None
    out = {"gocbRef": None, "stNum": None, "sqNum": None, "trip": None, "token": b""}
    for tag, val in _parse_tlvs(pdu):
        if tag == 0x80:
            out["gocbRef"] = val.decode("ascii", "replace")
        elif tag == 0x85:
            out["stNum"] = int.from_bytes(val, "big")
        elif tag == 0x86:
            out["sqNum"] = int.from_bytes(val, "big")
        elif tag == 0xAB:
            for dt, dv in _parse_tlvs(val):
                if dt == 0x83:
                    out["trip"] = dv == b"\x01"
                elif dt == 0x89:
                    out["token"] = dv
    return out
