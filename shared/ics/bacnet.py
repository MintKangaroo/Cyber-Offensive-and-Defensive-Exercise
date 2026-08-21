"""
BACnet/IP 최소 인코더/파서 — 실 BVLC/NPDU/APDU 프레이밍
=======================================================
빌딩 자동화(BMS/HVAC)의 사실상 표준. UDP:47808. Wireshark 가 BACnet-APDU 로 디섹션한다.
여기서는 포렌식 캡처 합성에 필요한 Confirmed-Request ReadProperty/WriteProperty 를 실제
바이트로 인코딩한다(BACnet 태그 인코딩).

BVLC(4B): 0x81 + function(0x0A Original-Unicast-NPDU) + length(2, BE, 전체).
NPDU(2B): version(0x01) + control(0x00).
APDU: Confirmed-Request(0x00) + max-seg/apdu + invokeID + service-choice + service data(태그).
정직한 경계: 상호운용 최소셋(자체 파서와 왕복).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

BACNET_DEFAULT_PORT = 47808
SVC_READ_PROPERTY = 12
SVC_WRITE_PROPERTY = 15

# 오브젝트 타입
OBJ_ANALOG_INPUT = 0
OBJ_ANALOG_OUTPUT = 1
OBJ_ANALOG_VALUE = 2
OBJ_BINARY_INPUT = 3
OBJ_BINARY_OUTPUT = 4
PROP_PRESENT_VALUE = 85


def _object_id(obj_type: int, instance: int) -> int:
    return ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF)


def _bvlc_npdu(apdu: bytes) -> bytes:
    npdu = bytes([0x01, 0x00]) + apdu
    total = 4 + len(npdu)
    return bytes([0x81, 0x0A]) + struct.pack(">H", total) + npdu


def build_read_property(obj_type: int, instance: int, prop: int = PROP_PRESENT_VALUE,
                        invoke_id: int = 1) -> bytes:
    apdu = bytes([0x00, 0x05, invoke_id & 0xFF, SVC_READ_PROPERTY])
    apdu += bytes([0x0C]) + struct.pack(">I", _object_id(obj_type, instance))  # ctx0 objID
    apdu += bytes([0x19, prop & 0xFF])                                          # ctx1 propID
    return _bvlc_npdu(apdu)


def build_write_property(obj_type: int, instance: int, value: bytes,
                         prop: int = PROP_PRESENT_VALUE, priority: Optional[int] = None,
                         invoke_id: int = 1) -> bytes:
    """WriteProperty. value 는 OctetString(application tag 6)으로 인코딩."""
    apdu = bytes([0x00, 0x05, invoke_id & 0xFF, SVC_WRITE_PROPERTY])
    apdu += bytes([0x0C]) + struct.pack(">I", _object_id(obj_type, instance))  # ctx0 objID
    apdu += bytes([0x19, prop & 0xFF])                                          # ctx1 propID
    # ctx3 opening + OctetString value + ctx3 closing
    if len(value) < 5:
        val_tag = bytes([0x60 | len(value)]) + value
    else:
        val_tag = bytes([0x65, len(value) & 0xFF]) + value                      # 확장 길이
    apdu += bytes([0x3E]) + val_tag + bytes([0x3F])
    if priority is not None:
        apdu += bytes([0x49, priority & 0xFF])                                  # ctx4 priority
    return _bvlc_npdu(apdu)


@dataclass
class ParsedApdu:
    service: int
    obj_type: Optional[int]
    instance: Optional[int]
    value: bytes           # WriteProperty 의 OctetString 값(있으면)
    priority: Optional[int]


def parse_apdu(frame: bytes) -> Optional[ParsedApdu]:
    """BACnet/IP 프레임 → Confirmed-Request 파싱. 아니면 None."""
    if len(frame) < 6 or frame[0] != 0x81:
        return None
    npdu = frame[4:]
    if len(npdu) < 2:
        return None
    apdu = npdu[2:]
    if len(apdu) < 4 or (apdu[0] & 0xF0) != 0x00:      # Confirmed-Request
        return None
    service = apdu[3]
    obj_type = instance = priority = None
    value = b""
    i = 4
    while i < len(apdu):
        tag = apdu[i]
        if tag == 0x0C and i + 5 <= len(apdu):         # ctx0 objID(4B)
            oid = struct.unpack(">I", apdu[i + 1:i + 5])[0]
            obj_type = oid >> 22
            instance = oid & 0x3FFFFF
            i += 5
        elif tag == 0x19 and i + 2 <= len(apdu):       # ctx1 propID
            i += 2
        elif tag == 0x3E:                              # ctx3 opening
            vt = apdu[i + 1]
            if (vt & 0xF8) == 0x60:                    # OctetString app tag
                lvt = vt & 0x07
                if lvt < 5:
                    value = apdu[i + 2:i + 2 + lvt]
                    i += 2 + lvt
                else:
                    ln = apdu[i + 2]
                    value = apdu[i + 3:i + 3 + ln]
                    i += 3 + ln
                if i < len(apdu) and apdu[i] == 0x3F:
                    i += 1
            else:
                i += 1
        elif tag == 0x49 and i + 2 <= len(apdu):       # ctx4 priority
            priority = apdu[i + 1]
            i += 2
        else:
            i += 1
    return ParsedApdu(service, obj_type, instance, value, priority)
