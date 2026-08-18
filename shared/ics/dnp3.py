"""
실 DNP3(Distributed Network Protocol 3) 아웃스테이션 (IEEE 1815) — 최소 상호운용 서브셋
=========================================================================================
전력/수도 SCADA에서 널리 쓰는 DNP3/TCP(기본 포트 20000)를 트윈이 '실제로' 말하게 한다.
Modbus(shared/ics/modbus.py)와 같은 설계 철학: 소켓과 무관한 순수 함수(handle_app_fragment)
로 두어 단위 테스트가 쉽고, serve()가 데이터링크 프레이밍/TCP만 담당한다.

구현 범위(진짜 프로토콜, 상호운용 가능한 최소셋):
  - 데이터링크 계층: 0x0564 프레임 + DNP3 CRC(다항식 0x3D65) 블록별 검증/생성.
  - 전송 계층: 단일 프래그먼트(FIR+FIN).
  - 응용 계층:
      · FC 0x01 READ  → Group 30 Var 2(16-bit analog input w/ flag) 로 아날로그 입력 응답.
      · FC 0x05 DIRECT_OPERATE → Group 12 Var 1 CROB 로 바이너리 출력 제어(+on_operate 콜백).
      · 그 외 FC → IIN에 'no func code support' 세팅 후 응답(정상 거부).
클라이언트 헬퍼(build_read_request/build_direct_operate/parse_read_response)로 테스트/검증.
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

DNP3_DEFAULT_PORT = 20000

# 응용 함수 코드
FC_READ = 0x01
FC_DIRECT_OPERATE = 0x05
FC_RESPONSE = 0x81

# CROB(Group12Var1) control code
CROB_LATCH_ON = 0x03
CROB_LATCH_OFF = 0x04


def dnp3_crc(data: bytes) -> int:
    """DNP3 CRC-16 (다항식 0x3D65, 반사형 0xA6BC, 최종 1의 보수). IEEE 1815 표준."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


def _crc_bytes(data: bytes) -> bytes:
    return struct.pack("<H", dnp3_crc(data))  # low byte first


def _append_crc_blocks(user_data: bytes) -> bytes:
    """사용자 데이터를 16바이트 블록으로 나눠 각 블록 뒤에 CRC를 붙인다."""
    out = bytearray()
    for i in range(0, len(user_data), 16):
        block = user_data[i:i + 16]
        out += block + _crc_bytes(block)
    return bytes(out)


def _strip_crc_blocks(body: bytes) -> Optional[bytes]:
    """CRC 붙은 블록들에서 CRC 검증 후 사용자 데이터만 반환. 불일치면 None."""
    out = bytearray()
    i = 0
    while i < len(body):
        block = body[i:i + 16]
        remaining = len(body) - i
        blen = min(16, remaining - 2) if remaining - 2 > 0 else 0
        block = body[i:i + blen]
        crc = body[i + blen:i + blen + 2]
        if len(crc) != 2 or _crc_bytes(block) != crc:
            return None
        out += block
        i += blen + 2
    return bytes(out)


def encode_frame(control: int, dest: int, source: int, user_data: bytes) -> bytes:
    """DNP3 데이터링크 프레임 인코드(헤더 CRC + 데이터 블록 CRC 포함)."""
    length = 5 + len(user_data)   # CTRL(1)+DEST(2)+SRC(2)+userdata, CRC/start 미포함
    header = struct.pack("<BBBBHH", 0x05, 0x64, length, control, dest, source)
    frame = header + _crc_bytes(header)
    if user_data:
        frame += _append_crc_blocks(user_data)
    return frame


@dataclass
class ParsedFrame:
    control: int
    dest: int
    source: int
    user_data: bytes


def parse_frame(frame: bytes) -> Optional[ParsedFrame]:
    """DNP3 프레임 디코드 + 전 CRC 검증. 유효하지 않으면 None."""
    if len(frame) < 10 or frame[0] != 0x05 or frame[1] != 0x64:
        return None
    header = frame[:8]
    if _crc_bytes(header) != frame[8:10]:
        return None
    length, control, dest, source = struct.unpack("<BBHH", frame[2:8])
    udlen = length - 5
    if udlen < 0:
        return None
    body = frame[10:]
    user_data = _strip_crc_blocks(body) if body else b""
    if user_data is None:
        return None
    return ParsedFrame(control, dest, source, user_data[:udlen] if udlen else b"")


@dataclass
class Dnp3Outstation:
    """아웃스테이션 상태. analog_inputs(측정값)·binary_outputs(제어 코일)."""
    analog_inputs: list[int] = field(default_factory=lambda: [0] * 8)
    binary_outputs: list[bool] = field(default_factory=lambda: [False] * 8)
    address: int = 4                       # 아웃스테이션 DNP 주소
    # on_operate(index, latch_on): 바이너리 출력 조작 시 호출(트윈 물리연동·이벤트 발행용)
    on_operate: Optional[Callable[[int, bool], None]] = None


def _read_response_objects(os: Dnp3Outstation) -> bytes:
    """Group 30 Var 2(16-bit analog input with flag), qualifier 0x00(8-bit start/stop)."""
    n = len(os.analog_inputs)
    hdr = struct.pack("<BBBBB", 30, 2, 0x00, 0, n - 1)  # grp,var,qual,start,stop
    # 각 점: flag 0x01(ONLINE) + 16-bit signed 값.
    body = b"".join(struct.pack("<Bh", 0x01, max(-32768, min(32767, int(v)))) for v in os.analog_inputs)
    return hdr + body


def handle_app_fragment(os: Dnp3Outstation, app: bytes) -> bytes:
    """응용 프래그먼트(app control + FC + objects) → 응답 프래그먼트. 순수함수(소켓 무관)."""
    if len(app) < 2:
        return b""
    app_ctrl, fc = app[0], app[1]
    resp_ctrl = 0xC0 | (app_ctrl & 0x0F)   # FIR+FIN + seq 에코
    iin = 0x0000

    if fc == FC_READ:
        objs = _read_response_objects(os)
        return struct.pack("<BBH", resp_ctrl, FC_RESPONSE, iin) + objs

    if fc == FC_DIRECT_OPERATE:
        # object header: grp=12 var=1 qual=0x28(count+index, 16-bit) or 0x17(8-bit) ... 최소 지원.
        rest = app[2:]
        ok = _apply_crob(os, rest)
        if not ok:
            iin |= 0x0001 << 8   # IIN2.0 근사(파라미터 오류)
        # 응답: 요청 오브젝트를 상태와 함께 에코(간이). status 0x00 = success.
        return struct.pack("<BBH", resp_ctrl, FC_RESPONSE, iin) + rest

    # 미지원 FC → IIN2.1 (no func code support)
    iin |= (0x01 << 8)
    return struct.pack("<BBH", resp_ctrl, FC_RESPONSE, iin)


def _apply_crob(os: Dnp3Outstation, obj: bytes) -> bool:
    """Group12Var1 CROB 파싱 후 바이너리 출력 조작. 지원: qual 0x17(8-bit count+index)."""
    if len(obj) < 3:
        return False
    grp, var, qual = obj[0], obj[1], obj[2]
    if grp != 12 or var != 1:
        return False
    p = 3
    if qual == 0x17:  # count(1) + [index(1) + CROB(11)]...
        if len(obj) < 4:
            return False
        count = obj[3]
        p = 4
    elif qual == 0x28:  # count(2) + [index(2) + CROB(11)]...
        if len(obj) < 5:
            return False
        count = struct.unpack("<H", obj[3:5])[0]
        p = 5
    else:
        return False
    applied = False
    for _ in range(count):
        if qual == 0x17:
            if p + 1 + 11 > len(obj):
                return False
            index = obj[p]; p += 1
        else:
            if p + 2 + 11 > len(obj):
                return False
            index = struct.unpack("<H", obj[p:p + 2])[0]; p += 2
        crob = obj[p:p + 11]; p += 11
        control_code = crob[0]
        if 0 <= index < len(os.binary_outputs):
            if control_code == CROB_LATCH_ON:
                os.binary_outputs[index] = True
            elif control_code == CROB_LATCH_OFF:
                os.binary_outputs[index] = False
            else:
                continue
            applied = True
            if os.on_operate:
                os.on_operate(index, os.binary_outputs[index])
    return applied


# ---------------------------------------------------------------------------
# 클라이언트 헬퍼(마스터 측) — 테스트/라이브 검증용
# ---------------------------------------------------------------------------
def build_read_request(dest: int, source: int = 1, seq: int = 0) -> bytes:
    app = struct.pack("<BB", 0xC0 | (seq & 0x0F), FC_READ)  # app_ctrl FIR+FIN, FC READ
    # class 0 read를 간이로: 오브젝트 헤더 생략(아웃스테이션이 전 아날로그 반환).
    return encode_frame(0xC4, dest, source, app)  # ctrl 0xC4 = PRM+UNCONFIRMED_USER_DATA


def build_direct_operate_crob(dest: int, index: int, latch_on: bool,
                              source: int = 1, seq: int = 0) -> bytes:
    cc = CROB_LATCH_ON if latch_on else CROB_LATCH_OFF
    crob = struct.pack("<BBIIBB", cc, 1, 0, 0, 0, 0)  # control_code,count,on_time,off_time,status,pad
    crob = crob[:11].ljust(11, b"\x00")
    obj = struct.pack("<BBBB", 12, 1, 0x17, 1) + struct.pack("<B", index) + crob
    app = struct.pack("<BB", 0xC0 | (seq & 0x0F), FC_DIRECT_OPERATE) + obj
    return encode_frame(0xC4, dest, source, app)


def parse_read_response(frame: bytes) -> Optional[list[int]]:
    """READ 응답 프레임 → 아날로그 입력 값 목록. 응답/오브젝트가 아니면 None."""
    pf = parse_frame(frame)
    if pf is None or len(pf.user_data) < 4:
        return None
    app = pf.user_data
    if app[1] != FC_RESPONSE:
        return None
    objs = app[4:]  # app_ctrl(1)+fc(1)+iin(2)
    if len(objs) < 5 or objs[0] != 30 or objs[1] != 2:
        return None
    start, stop = objs[3], objs[4]
    n = stop - start + 1
    vals = []
    p = 5
    for _ in range(n):
        if p + 3 > len(objs):
            break
        _flag, val = struct.unpack("<Bh", objs[p:p + 3])
        vals.append(val)
        p += 3
    return vals


async def serve(outstation: Dnp3Outstation, host: str = "0.0.0.0",
                port: int = DNP3_DEFAULT_PORT) -> asyncio.AbstractServer:
    """DNP3/TCP 서버 기동(비차단). 프레임을 읽어 handle_app_fragment로 처리 후 응답."""
    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                header = await reader.readexactly(10)
                if header[0] != 0x05 or header[1] != 0x64:
                    break
                length = header[2]
                udlen = length - 5
                nblocks = (udlen + 15) // 16 if udlen > 0 else 0
                body = await reader.readexactly(udlen + nblocks * 2) if udlen > 0 else b""
                pf = parse_frame(header + body)
                if pf is None:
                    continue
                resp_app = handle_app_fragment(outstation, pf.user_data)
                if resp_app:
                    # 응답은 아웃스테이션→마스터: dest=원 source, source=아웃스테이션 주소
                    resp = encode_frame(0x44, pf.source, outstation.address, resp_app)
                    writer.write(resp)
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(_handle, host, port)
