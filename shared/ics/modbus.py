"""
실제 Modbus/TCP 서버(P1-1) — 순수 PDU 처리 + asyncio 서버
============================================================
트윈을 HTTP 목이 아니라 **진짜 Modbus 를 말하는 장치**로 만든다. 실 공격 도구(mbpoll,
pymodbus, metasploit modbus 모듈)가 그대로 붙는다.

지원 function code: FC1(코일 읽기), FC3(홀딩 레지스터 읽기), FC4(입력 레지스터=홀딩 별칭),
FC5(단일 코일 쓰기), FC6(단일 레지스터 쓰기), FC16(다중 레지스터 쓰기).
예외 응답: 01(illegal function), 02(illegal data address), 03(illegal data value).

`handle_pdu(bank, pdu)` 는 소켓과 무관한 순수함수라 단위 테스트가 쉽다. `serve()` 가 MBAP
프레이밍(트랜잭션 id/길이/유닛 id)을 입혀 TCP 로 노출한다. 쓰기에는 on_write 콜백이 붙어
트윈이 물리 상태 변화·이벤트 발행·안전 인터록을 걸 수 있다.
"""
from __future__ import annotations

import asyncio
import struct
from typing import Callable, Optional

# on_write(kind: "holding"|"coil", address: int, values: list[int|bool]) -> None
WriteCB = Callable[[str, int, list], None]


class ModbusBank:
    def __init__(self, holding: Optional[list[int]] = None, coils: Optional[list[bool]] = None,
                 on_write: Optional[WriteCB] = None):
        self.holding = holding if holding is not None else [0] * 128
        self.coils = coils if coils is not None else [False] * 128
        self.on_write = on_write


def _exc(fc: int, code: int) -> bytes:
    return struct.pack(">BB", fc | 0x80, code)


def handle_pdu(bank: ModbusBank, pdu: bytes) -> bytes:
    """Modbus PDU(함수코드+데이터) → 응답 PDU. 순수함수(소켓 무관)."""
    if not pdu:
        return b""
    fc = pdu[0]
    try:
        if fc in (3, 4):   # read holding / input registers
            start, qty = struct.unpack(">HH", pdu[1:5])
            if qty < 1 or qty > 125 or start + qty > len(bank.holding):
                return _exc(fc, 2)
            data = b"".join(struct.pack(">H", bank.holding[start + i] & 0xFFFF) for i in range(qty))
            return struct.pack(">BB", fc, qty * 2) + data
        if fc == 1 or fc == 2:   # read coils / discrete inputs
            start, qty = struct.unpack(">HH", pdu[1:5])
            if qty < 1 or qty > 2000 or start + qty > len(bank.coils):
                return _exc(fc, 2)
            nbytes = (qty + 7) // 8
            out = bytearray(nbytes)
            for i in range(qty):
                if bank.coils[start + i]:
                    out[i // 8] |= (1 << (i % 8))
            return struct.pack(">BB", fc, nbytes) + bytes(out)
        if fc == 6:   # write single holding register
            addr, val = struct.unpack(">HH", pdu[1:5])
            if addr >= len(bank.holding):
                return _exc(fc, 2)
            bank.holding[addr] = val
            if bank.on_write:
                bank.on_write("holding", addr, [val])
            return pdu[:5]   # echo
        if fc == 5:   # write single coil
            addr, val = struct.unpack(">HH", pdu[1:5])
            if addr >= len(bank.coils):
                return _exc(fc, 2)
            if val not in (0x0000, 0xFF00):
                return _exc(fc, 3)
            on = (val == 0xFF00)
            bank.coils[addr] = on
            if bank.on_write:
                bank.on_write("coil", addr, [on])
            return pdu[:5]   # echo
        if fc == 16:   # write multiple holding registers
            addr, qty = struct.unpack(">HH", pdu[1:5])
            bytecount = pdu[5]
            if qty < 1 or addr + qty > len(bank.holding) or bytecount != qty * 2:
                return _exc(fc, 2)
            vals = list(struct.unpack(">" + "H" * qty, pdu[6:6 + bytecount]))
            for i, v in enumerate(vals):
                bank.holding[addr + i] = v
            if bank.on_write:
                bank.on_write("holding", addr, vals)
            return struct.pack(">BHH", fc, addr, qty)
        return _exc(fc, 1)   # illegal function
    except (struct.error, IndexError):
        return _exc(fc, 3)   # illegal data value(형식 오류)


async def _handle_client(bank: ModbusBank, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            header = await reader.readexactly(7)   # MBAP: tid(2) pid(2) len(2) uid(1)
            tid, pid, length, uid = struct.unpack(">HHHB", header)
            body = await reader.readexactly(length - 1) if length > 1 else b""
            resp_pdu = handle_pdu(bank, body)
            resp = struct.pack(">HHHB", tid, 0, len(resp_pdu) + 1, uid) + resp_pdu
            writer.write(resp)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def serve(bank: ModbusBank, host: str = "0.0.0.0", port: int = 502) -> asyncio.AbstractServer:
    """Modbus/TCP 서버 기동(비차단). 반환된 server 를 close() 로 종료."""
    return await asyncio.start_server(lambda r, w: _handle_client(bank, r, w), host, port)
