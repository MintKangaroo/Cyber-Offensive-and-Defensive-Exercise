"""
실 S7comm(Siemens S7 PLC 프로토콜) 아웃스테이션 — TPKT/COTP/S7 3계층
=====================================================================
S7-300/400/1200/1500 PLC가 쓰는 사설 프로토콜. Stuxnet이 노린 바로 그 프로토콜.
트윈이 HTTP 목업이 아니라 실제 S7comm/TCP(포트 102)로 응답한다. (Modbus/DNP3/OPC UA와 동일
철학: 소켓 무관 순수 함수 + serve().)

계층:
  - TPKT(RFC 1006): 03 00 <len16>.
  - COTP(ISO 8073): CR(0xE0)→CC(0xD0) 연결설정, DT(0xF0) 데이터 운반.
  - S7 PDU: protocol_id 0x32 + ROSCTR + ... . 지원 function:
      · 0xF0 Setup Communication → PDU 길이/AMQ 협상.
      · 0x04 Read Var(DB word) → 데이터블록 워드 값 응답.
정직한 스코프: Read(정찰) + 연결설정. Write/프로그램 다운로드(FAC-001)는 HTTP 목업 담당.
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

S7_DEFAULT_PORT = 102


# ---- TPKT ----
def tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 0x03, 0x00, len(payload) + 4) + payload


def parse_tpkt_len(head4: bytes) -> Optional[int]:
    if len(head4) < 4 or head4[0] != 0x03:
        return None
    return struct.unpack(">H", head4[2:4])[0]


# ---- COTP ----
def build_cotp_cc(src_ref: int = 0x0001, dst_ref: int = 0x0000) -> bytes:
    """Connection Confirm(요청 TSAP 파라미터를 최소로 에코)."""
    # length, pdu_type(0xD0), dst_ref, src_ref, class(0x00) + params(src/dst TSAP, tpdu size)
    params = (bytes([0xC0, 0x01, 0x0A]) +          # tpdu-size = 1024
              bytes([0xC1, 0x02, 0x01, 0x00]) +    # src-tsap
              bytes([0xC2, 0x02, 0x01, 0x02]))     # dst-tsap
    body = struct.pack(">BHHB", 0xD0, dst_ref, src_ref, 0x00) + params
    return bytes([len(body)]) + body


def is_cotp_cr(cotp: bytes) -> bool:
    return len(cotp) >= 2 and cotp[1] == 0xE0


def cotp_dt_payload(cotp: bytes) -> Optional[bytes]:
    """COTP DT(0xF0)면 S7 페이로드 반환. length(1)+0xF0+eot(1) 뒤가 S7."""
    if len(cotp) >= 3 and cotp[1] == 0xF0:
        li = cotp[0]
        return cotp[li + 1:]
    return None


def build_cotp_dt(s7_payload: bytes) -> bytes:
    return bytes([0x02, 0xF0, 0x80]) + s7_payload


# ---- S7 PDU ----
@dataclass
class S7Outstation:
    db: list[int] = field(default_factory=lambda: [0] * 64)  # DB 워드(16-bit)
    pdu_length: int = 480
    on_read: Optional[Callable[[int, int, int], None]] = None  # (db_num, start, count)


def _s7_setup_ack(pdu_ref: int, negotiated: int) -> bytes:
    # header(Ack_Data ROSCTR=0x03) + error(2) + param(function 0xF0 setup)
    param = struct.pack(">BBHHH", 0xF0, 0x00, 0x0001, 0x0001, negotiated)
    header = struct.pack(">BBHHHH", 0x32, 0x03, 0x0000, pdu_ref, len(param), 0) + b"\x00\x00"
    return header + param


def _s7_read_ack(os: S7Outstation, pdu_ref: int, items: list[tuple[int, int, int]]) -> bytes:
    """items: [(db_num, start_byte, count_words)...]. 응답 데이터 조립."""
    param = struct.pack(">BB", 0x04, len(items))  # function 0x04, item count
    data = bytearray()
    for (_dbn, start, count) in items:
        start_word = start // 2
        words = [os.db[(start_word + i) % len(os.db)] & 0xFFFF for i in range(count)]
        raw = b"".join(struct.pack(">H", w) for w in words)
        # return_code 0xFF(success), transport_size 0x04(byte/word), length in BITS
        data += struct.pack(">BBH", 0xFF, 0x04, len(raw) * 8) + raw
    header = struct.pack(">BBHHHH", 0x32, 0x03, 0x0000, pdu_ref, len(param), len(data)) + b"\x00\x00"
    return header + param + bytes(data)


def handle_s7_pdu(os: S7Outstation, s7: bytes) -> Optional[bytes]:
    """S7 요청 PDU → 응답 PDU(순수 함수). Job(0x01) Setup/Read만 처리."""
    if len(s7) < 10 or s7[0] != 0x32:
        return None
    rosctr = s7[1]
    pdu_ref = struct.unpack(">H", s7[4:6])[0]
    param_len = struct.unpack(">H", s7[6:8])[0]
    if rosctr != 0x01:      # Job request 만 응답
        return None
    param = s7[10:10 + param_len]
    if not param:
        return None
    func = param[0]
    if func == 0xF0:        # Setup communication
        req_pdu = struct.unpack(">H", param[6:8])[0] if len(param) >= 8 else os.pdu_length
        os.pdu_length = min(os.pdu_length, req_pdu or os.pdu_length)
        return _s7_setup_ack(pdu_ref, os.pdu_length)
    if func == 0x04:        # Read Var
        item_count = param[1] if len(param) >= 2 else 0
        items = []
        p = 2
        for _ in range(item_count):
            # 각 item: 0x12,len,syntax(0x10),transport(1),count(2),db(2),area(1),addr(3)
            if p + 12 > len(param):
                break
            count = struct.unpack(">H", param[p + 4:p + 6])[0]
            db_num = struct.unpack(">H", param[p + 6:p + 8])[0]
            addr = int.from_bytes(param[p + 9:p + 12], "big")
            start_byte = addr >> 3
            items.append((db_num, start_byte, count))
            if os.on_read:
                os.on_read(db_num, start_byte, count)
            p += 12
        return _s7_read_ack(os, pdu_ref, items)
    return None


# ---- 클라이언트 헬퍼(테스트/검증용) ----
def build_cotp_cr() -> bytes:
    params = (bytes([0xC0, 0x01, 0x0A]) + bytes([0xC1, 0x02, 0x01, 0x00]) +
              bytes([0xC2, 0x02, 0x01, 0x02]))
    body = struct.pack(">BHHB", 0xE0, 0x0000, 0x0001, 0x00) + params
    return tpkt(bytes([len(body)]) + body)


def build_s7_setup(pdu_ref: int = 1) -> bytes:
    param = struct.pack(">BBHHH", 0xF0, 0x00, 0x0001, 0x0001, 480)
    header = struct.pack(">BBHHHH", 0x32, 0x01, 0x0000, pdu_ref, len(param), 0)
    return tpkt(build_cotp_dt(header + param))


def build_s7_read(db_num: int, start_byte: int, count_words: int, pdu_ref: int = 2) -> bytes:
    item = (bytes([0x12, 0x0A, 0x10, 0x04]) + struct.pack(">H", count_words) +
            struct.pack(">H", db_num) + bytes([0x84]) + (start_byte << 3).to_bytes(3, "big"))
    param = struct.pack(">BB", 0x04, 1) + item
    header = struct.pack(">BBHHHH", 0x32, 0x01, 0x0000, pdu_ref, len(param), 0)
    return tpkt(build_cotp_dt(header + param))


def parse_s7_read_response(frame: bytes) -> Optional[list[int]]:
    """TPKT+COTP+S7 Ack 응답에서 워드 값 목록 추출."""
    if len(frame) < 7 or frame[0] != 0x03:
        return None
    cotp = frame[4:]
    s7 = cotp_dt_payload(cotp)
    if s7 is None or len(s7) < 12 or s7[0] != 0x32 or s7[1] != 0x03:
        return None
    param_len = struct.unpack(">H", s7[6:8])[0]
    data = s7[12 + param_len:]  # Ack_Data header는 12바이트(+2 error)
    # 첫 item: return_code(1)+transport(1)+len_bits(2)+data
    if len(data) < 4 or data[0] != 0xFF:
        return None
    nbits = struct.unpack(">H", data[2:4])[0]
    raw = data[4:4 + nbits // 8]
    return [struct.unpack(">H", raw[i:i + 2])[0] for i in range(0, len(raw) - 1, 2)]


async def serve(os: S7Outstation, host: str = "0.0.0.0", port: int = S7_DEFAULT_PORT
                ) -> asyncio.AbstractServer:
    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                head = await reader.readexactly(4)
                total = parse_tpkt_len(head)
                if total is None:
                    break
                cotp = await reader.readexactly(total - 4)
                if is_cotp_cr(cotp):
                    writer.write(tpkt(build_cotp_cc())); await writer.drain()
                    continue
                s7 = cotp_dt_payload(cotp)
                if s7 is None:
                    continue
                resp = handle_s7_pdu(os, s7)
                if resp:
                    writer.write(tpkt(build_cotp_dt(resp))); await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(_handle, host, port)
