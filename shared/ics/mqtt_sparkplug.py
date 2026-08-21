"""
MQTT + Sparkplug B 최소 인코더/파서 — 실 MQTT PUBLISH 프레이밍
=============================================================
IIoT/SCADA 브로커의 사실상 표준. TCP:1883. Wireshark 가 MQTT 로 디섹션한다(토픽·PUBLISH).
여기서는 포렌식 캡처 합성에 필요한 MQTT PUBLISH(QoS 0) + Sparkplug B 페이로드(최소 protobuf)를
실제 바이트로 인코딩한다.

MQTT PUBLISH: 고정헤더(0x30 + remaining-length varint) + 토픽(2B len + str) + 페이로드.
Sparkplug B 페이로드(최소 protobuf): field1 timestamp(varint), field2 metric name(string),
field3 body(bytes = 값/토큰).
정직한 경계: 상호운용 최소셋(자체 파서와 왕복).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

MQTT_DEFAULT_PORT = 1883
PUBLISH = 0x30


def _varint(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            return out


def _read_varint(data: bytes, off: int) -> tuple[int, int]:
    shift = 0
    val = 0
    while off < len(data):
        b = data[off]
        val |= (b & 0x7F) << shift
        off += 1
        if not (b & 0x80):
            break
        shift += 7
    return val, off


def build_sparkplug_payload(metric: str, body: bytes, timestamp: int = 1_700_000_000) -> bytes:
    p = bytes([0x08]) + _varint(timestamp)                              # field1 varint
    p += bytes([0x12]) + _varint(len(metric)) + metric.encode()        # field2 string
    p += bytes([0x1A]) + _varint(len(body)) + body                     # field3 bytes(body)
    return p


def build_publish(topic: str, payload: bytes) -> bytes:
    """MQTT PUBLISH(QoS 0) 패킷."""
    var = struct.pack(">H", len(topic)) + topic.encode() + payload
    return bytes([PUBLISH]) + _varint(len(var)) + var


@dataclass
class ParsedPublish:
    topic: str
    metric: Optional[str]
    body: bytes


def parse_publish(data: bytes) -> Optional[ParsedPublish]:
    """MQTT PUBLISH → (topic, Sparkplug metric/body). 아니면 None."""
    if not data or (data[0] & 0xF0) != PUBLISH:
        return None
    rem, off = _read_varint(data, 1)
    end = off + rem
    if end > len(data) or off + 2 > len(data):
        return None
    tlen = struct.unpack(">H", data[off:off + 2])[0]
    off += 2
    topic = data[off:off + tlen].decode("utf-8", "replace")
    off += tlen
    payload = data[off:end]
    metric, body = _parse_sparkplug(payload)
    return ParsedPublish(topic, metric, body)


def _parse_sparkplug(p: bytes):
    metric = None
    body = b""
    i = 0
    while i < len(p):
        tag = p[i]
        i += 1
        field = tag >> 3
        wt = tag & 0x07
        if wt == 0:                       # varint
            _v, i = _read_varint(p, i)
        elif wt == 2:                     # length-delimited
            ln, i = _read_varint(p, i)
            val = p[i:i + ln]
            i += ln
            if field == 2:
                metric = val.decode("utf-8", "replace")
            elif field == 3:
                body = val
        else:
            break
    return metric, body
