"""
Syslog Ingestion Server (22번 문서 1절, M5.2)
================================================
UDP 514 + TCP 514 동시 수신. TCP는 RFC6587 프레이밍(octet-counting과 non-transparent
개행 구분) 둘 다 지원 — 첫 바이트가 숫자면 octet-counting, 아니면 개행 구분으로 판별.
큐가 가득 차면 드롭하고 카운터를 올린다(무한 대기로 전체 수집이 막히는 것을 방지).
"""
from __future__ import annotations
import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RawLogLine:
    source_ip: str
    raw_text: str
    received_at: float = field(default_factory=time.time)
    transport: str = "udp"


@dataclass
class DropCounters:
    counts: dict[str, int] = field(default_factory=dict)

    def record_drop(self, source_ip: str) -> None:
        self.counts[source_ip] = self.counts.get(source_ip, 0) + 1

    def total(self) -> int:
        return sum(self.counts.values())


drop_counters = DropCounters()


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue):
        self.queue = queue

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        line = RawLogLine(source_ip=addr[0], raw_text=data.decode(errors="replace").rstrip("\n"), transport="udp")
        try:
            self.queue.put_nowait(line)
        except asyncio.QueueFull:
            drop_counters.record_drop(addr[0])


async def start_udp_syslog(host: str, port: int, queue: asyncio.Queue) -> asyncio.DatagramTransport:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _UdpProtocol(queue), local_addr=(host, port)
    )
    return transport


async def _handle_tcp_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, queue: asyncio.Queue) -> None:
    """첫 바이트로 프레이밍 방식을 판별한다: 숫자면 octet-counting, 아니면 개행 구분."""
    addr = writer.get_extra_info("peername")
    source_ip = addr[0] if addr else "unknown"

    def _emit(text: str) -> None:
        text = text.rstrip("\n")
        if not text:
            return
        line = RawLogLine(source_ip=source_ip, raw_text=text, transport="tcp")
        try:
            queue.put_nowait(line)
        except asyncio.QueueFull:
            drop_counters.record_drop(source_ip)

    try:
        first_byte = await reader.read(1)
        if not first_byte:
            return

        if first_byte.isdigit():
            # octet-counting 프레이밍
            length_bytes = bytearray(first_byte)
            while True:
                b = await reader.read(1)
                if not b or b == b" ":
                    break
                if not b.isdigit():
                    return  # 형식 위반, 연결 종료(이 스트림은 신뢰 불가로 판단)
                length_bytes += b
                if len(length_bytes) > 6:
                    return  # 비정상적으로 긴 길이 필드 -> 방어적으로 연결 종료
            if not length_bytes:
                return
            length = int(length_bytes)

            while True:
                msg = await reader.readexactly(length)
                _emit(msg.decode(errors="replace"))

                length_bytes = bytearray()
                while True:
                    b = await reader.read(1)
                    if not b:
                        return
                    if b == b" ":
                        break
                    if not b.isdigit():
                        return
                    length_bytes += b
                if not length_bytes:
                    return
                length = int(length_bytes)
        else:
            # non-transparent framing: 개행으로 구분. 첫 바이트도 포함해서 처리.
            buffer = bytearray(first_byte)
            while True:
                chunk = await reader.readline()
                if not chunk:
                    if buffer:
                        _emit(buffer.decode(errors="replace"))
                    return
                full = bytes(buffer) + chunk
                buffer = bytearray()
                _emit(full.decode(errors="replace"))
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        writer.close()


async def start_tcp_syslog(host: str, port: int, queue: asyncio.Queue) -> asyncio.AbstractServer:
    server = await asyncio.start_server(
        lambda r, w: _handle_tcp_connection(r, w, queue), host, port
    )
    return server
