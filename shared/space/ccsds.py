"""
실 CCSDS Space Packet Protocol — 위성 TT&C (Telemetry, Tracking & Command)
==========================================================================
트윈을 HTTP 목이 아니라 **진짜 CCSDS 를 말하는 위성/지상국 링크**로 만든다. 실 우주 표준
CCSDS 133.0-B(Space Packet Protocol)의 6바이트 1차 헤더(primary header)를 비트 단위로
정확히 인코딩/파싱하므로, 표준을 아는 도구/스크립트가 그대로 붙는다.

Space Packet Primary Header (6 bytes, big-endian):

    +--------------------------------------------------------------+
    | Packet Version Number (3b) | Packet Type (1b) | Sec Hdr (1b) |  word1 (16b)
    | Application Process ID / APID (11b)                          |
    +--------------------------------------------------------------+
    | Sequence Flags (2b) | Packet Sequence Count (14b)            |  word2 (16b)
    +--------------------------------------------------------------+
    | Packet Data Length (16b)  == (data field 길이 - 1)           |  word3 (16b)
    +--------------------------------------------------------------+
    | User Data Field (가변)                                        |
    +--------------------------------------------------------------+

  - Packet Type: 0=TM(Telemetry, 위성→지상), 1=TC(Telecommand, 지상→위성)
  - Packet Data Length 필드는 "실제 데이터 길이 - 1" 로 인코딩된다(최소 1바이트 보장).

`handle_tc(state, packet)` 는 소켓과 무관한 **순수함수**라 단위 테스트가 쉽다. `serve()` 가
TCP 프레이밍(헤더 6B → 데이터 길이 계산 → 나머지 수신)을 입혀 노출한다. 트윈은 on_tc 콜백으로
텔레커맨드를 SIEM 로그/이벤트로 흘려 Blue 가 탐지하게 한다.
"""
from __future__ import annotations

import asyncio
import os
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

# --- Packet Type ---
TM = 0   # Telemetry (spacecraft -> ground)
TC = 1   # Telecommand (ground -> spacecraft)

# --- Sequence Flags (2b) ---
SEQ_CONTINUATION = 0b00
SEQ_FIRST = 0b01
SEQ_LAST = 0b10
SEQ_UNSEGMENTED = 0b11   # standalone(비분할) 패킷 — TT&C 는 보통 이 값을 쓴다

# --- APID (11b) 할당 (훈련용 더미) ---
APID_TC_CMD = 0x064        # 100  : 지상 → 위성 텔레커맨드
APID_TM_HK = 0x0C8         # 200  : 위성 → 지상 하우스키핑 텔레메트리
APID_TM_ACK = 0x0C9        # 201  : 위성 → 지상 커맨드 수신확인(ACK)
APID_IDLE = 0x7FF          # 2047 : CCSDS idle 패킷 예약값

# --- Telecommand 코드(데이터 필드 첫 바이트) ---
CMD_PING = 0x00
CMD_DISABLE_ATTITUDE_SAFETY = 0x11   # 자세제어 안전(SIS) 해제 — 위성 자세 상실 유발 가능
CMD_SET_ATTITUDE = 0x12              # 자세 설정: >hhh (roll,pitch,yaw) 밀리도
CMD_SET_THRUSTER = 0x13              # 추력기 레벨 설정: >H (0..1000)
CMD_ENABLE_ATTITUDE_SAFETY = 0x14    # 자세 안전 재무장(Blue 복구)

COMMAND_NAMES = {
    CMD_PING: "PING",
    CMD_DISABLE_ATTITUDE_SAFETY: "DISABLE_ATTITUDE_SAFETY",
    CMD_SET_ATTITUDE: "SET_ATTITUDE",
    CMD_SET_THRUSTER: "SET_THRUSTER",
    CMD_ENABLE_ATTITUDE_SAFETY: "ENABLE_ATTITUDE_SAFETY",
}

# --- Ack 상태 코드 ---
STATUS_ACCEPT = 0x00
STATUS_REJECT = 0x01


# ---------------------------------------------------------------------------
# 1차 헤더 비트 패킹(정확성이 핵심 — test_ccsds 로 라운드트립 검증)
# ---------------------------------------------------------------------------
def encode_primary_header(*, ptype: int, apid: int, seq_count: int, data_len: int,
                          version: int = 0, sec_hdr: int = 0,
                          seq_flags: int = SEQ_UNSEGMENTED) -> bytes:
    """CCSDS Space Packet 1차 헤더 6바이트 인코딩.

    data_len 은 user data field 의 **실제 바이트 수**(>=1). Packet Data Length 필드에는
    표준대로 (data_len - 1) 로 저장된다.
    """
    if not (1 <= data_len <= 65536):
        raise ValueError("data_len must be 1..65536 (CCSDS: data field >= 1 byte)")
    word1 = ((version & 0x7) << 13) | ((ptype & 0x1) << 12) | ((sec_hdr & 0x1) << 11) | (apid & 0x7FF)
    word2 = ((seq_flags & 0x3) << 14) | (seq_count & 0x3FFF)
    word3 = (data_len - 1) & 0xFFFF
    return struct.pack(">HHH", word1, word2, word3)


def parse_primary_header(header: bytes) -> dict:
    """6바이트 1차 헤더 → 필드 dict. data_len 은 재구성된 실제 데이터 길이(필드+1)."""
    if len(header) < 6:
        raise ValueError("primary header must be 6 bytes")
    word1, word2, word3 = struct.unpack(">HHH", header[:6])
    return {
        "version": (word1 >> 13) & 0x7,
        "type": (word1 >> 12) & 0x1,
        "sec_hdr": (word1 >> 11) & 0x1,
        "apid": word1 & 0x7FF,
        "seq_flags": (word2 >> 14) & 0x3,
        "seq_count": word2 & 0x3FFF,
        "data_len": (word3 & 0xFFFF) + 1,   # 표준: 필드값 = 실제길이 - 1
    }


def encode_packet(*, ptype: int, apid: int, seq_count: int, data: bytes,
                  version: int = 0, sec_hdr: int = 0,
                  seq_flags: int = SEQ_UNSEGMENTED) -> bytes:
    """1차 헤더 + user data field → 완성 Space Packet 바이트열."""
    if not data:
        raise ValueError("CCSDS user data field must be at least 1 byte")
    hdr = encode_primary_header(ptype=ptype, apid=apid, seq_count=seq_count,
                                data_len=len(data), version=version, sec_hdr=sec_hdr,
                                seq_flags=seq_flags)
    return hdr + data


def parse_packet(packet: bytes) -> tuple[dict, bytes]:
    """Space Packet → (헤더 dict, user data field). 순수함수."""
    hdr = parse_primary_header(packet)
    data = packet[6:6 + hdr["data_len"]]
    return hdr, data


# ---------------------------------------------------------------------------
# 위성 상태 + 텔레커맨드 처리(순수 로직)
# ---------------------------------------------------------------------------
@dataclass
class SpacecraftState:
    """모의 위성 버스 상태(더미). 텔레메트리 값 + 커맨드 처리 결과가 여기 누적된다."""
    # 하우스키핑 텔레메트리(더미)
    battery_voltage_mv: int = 28000     # 28.0 V
    solar_current_ma: int = 4200
    bus_temp_dc: int = 210              # 21.0 ℃ (deci-degree)
    # 자세(밀리도)
    roll_mdeg: int = 0
    pitch_mdeg: int = 0
    yaw_mdeg: int = 0
    thruster_level: int = 0
    # 안전(자세제어 SIS)
    attitude_safety_enabled: bool = True
    # 카운터/로그
    tc_seq: int = 0                     # 마지막 수신 TC seq
    tm_seq: int = 0                     # 다음 발행 TM seq
    last_command: Optional[str] = None
    commands_received: int = 0


def _next_tm_seq(state: SpacecraftState) -> int:
    state.tm_seq = (state.tm_seq + 1) & 0x3FFF
    return state.tm_seq


def build_tm_ack(state: SpacecraftState, command: int, status: int) -> bytes:
    """커맨드 수신확인(ACK) TM 패킷. 데이터 = command(1) + status(1)."""
    data = struct.pack(">BB", command & 0xFF, status & 0xFF)
    return encode_packet(ptype=TM, apid=APID_TM_ACK, seq_count=_next_tm_seq(state), data=data)


def build_tm_housekeeping(state: SpacecraftState) -> bytes:
    """하우스키핑 텔레메트리 TM 패킷(위성→지상). 위성 상태를 실제 텔레메트리로 노출."""
    data = struct.pack(
        ">HHhhhhBB",
        state.battery_voltage_mv & 0xFFFF,
        state.solar_current_ma & 0xFFFF,
        state.bus_temp_dc,
        state.roll_mdeg,
        state.pitch_mdeg,
        state.yaw_mdeg,
        state.thruster_level & 0xFF,
        1 if state.attitude_safety_enabled else 0,
    )
    return encode_packet(ptype=TM, apid=APID_TM_HK, seq_count=_next_tm_seq(state), data=data)


def handle_tc(state: SpacecraftState, packet: bytes) -> Optional[bytes]:
    """텔레커맨드 Space Packet 처리(순수함수, 소켓 무관).

    인식된 APID/커맨드면 state 를 변형하고 TM ACK 패킷을 반환한다.
    TM(위성→지상) 패킷이 잘못 들어오면 None. 인식 못한 APID 는 REJECT ACK 반환.
    """
    try:
        hdr, data = parse_packet(packet)
    except (ValueError, struct.error):
        return None
    if hdr["type"] != TC:
        return None   # 텔레커맨드가 아님

    state.tc_seq = hdr["seq_count"]
    if hdr["apid"] != APID_TC_CMD or not data:
        return build_tm_ack(state, 0xFF, STATUS_REJECT)

    command = data[0]
    args = data[1:]
    status = STATUS_ACCEPT

    if command == CMD_PING:
        pass
    elif command == CMD_DISABLE_ATTITUDE_SAFETY:
        state.attitude_safety_enabled = False
    elif command == CMD_ENABLE_ATTITUDE_SAFETY:
        state.attitude_safety_enabled = True
    elif command == CMD_SET_ATTITUDE and len(args) >= 6:
        state.roll_mdeg, state.pitch_mdeg, state.yaw_mdeg = struct.unpack(">hhh", args[:6])
    elif command == CMD_SET_THRUSTER and len(args) >= 2:
        state.thruster_level = struct.unpack(">H", args[:2])[0]
    else:
        status = STATUS_REJECT

    if status == STATUS_ACCEPT:
        state.last_command = COMMAND_NAMES.get(command, f"0x{command:02X}")
        state.commands_received += 1

    return build_tm_ack(state, command, status)


# ---------------------------------------------------------------------------
# 클라이언트 헬퍼(공격 도구/테스트가 쓰는 빌더/파서)
# ---------------------------------------------------------------------------
def build_tc(apid: int, command: int, args: bytes = b"", seq_count: int = 0) -> bytes:
    """텔레커맨드 Space Packet 생성. data = command(1) + args."""
    data = struct.pack(">B", command & 0xFF) + args
    return encode_packet(ptype=TC, apid=apid, seq_count=seq_count, data=data)


def parse_tm(packet: bytes) -> dict:
    """TM 패킷 파싱 → 필드 dict(apid 별 payload 해석 포함)."""
    hdr, data = parse_packet(packet)
    out = dict(hdr)
    out["raw_data"] = data
    if hdr["apid"] == APID_TM_ACK and len(data) >= 2:
        out["command"] = data[0]
        out["command_name"] = COMMAND_NAMES.get(data[0], f"0x{data[0]:02X}")
        out["status"] = data[1]
    elif hdr["apid"] == APID_TM_HK and len(data) >= 14:
        (batt, solar, temp, roll, pitch, yaw, thr, safety) = struct.unpack(">HHhhhhBB", data[:14])
        out.update({"battery_voltage_mv": batt, "solar_current_ma": solar, "bus_temp_dc": temp,
                    "roll_mdeg": roll, "pitch_mdeg": pitch, "yaw_mdeg": yaw,
                    "thruster_level": thr, "attitude_safety_enabled": bool(safety)})
    return out


# ---------------------------------------------------------------------------
# 실 CCSDS TCP 서버(비차단). serve() 는 프레이밍만, 로직은 handle_tc 가 담당.
# ---------------------------------------------------------------------------
# on_tc(packet: bytes, header: dict, data: bytes) -> None : 트윈 훅(로그/이벤트)
TcCB = Callable[[bytes, dict, bytes], None]

DEFAULT_PORT = int(os.environ.get("CCSDS_PORT", "1234"))


async def _handle_client(state: SpacecraftState, reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter, on_tc: Optional[TcCB]):
    try:
        while True:
            header = await reader.readexactly(6)          # 1차 헤더 고정 6바이트
            hdr = parse_primary_header(header)
            data = await reader.readexactly(hdr["data_len"])   # 필드값+1 = 실제 데이터 길이
            packet = header + data
            if on_tc is not None:
                try:
                    on_tc(packet, hdr, data)
                except Exception:
                    pass   # 훅 실패가 링크를 죽이면 안 됨
            resp = handle_tc(state, packet)
            if resp:
                writer.write(resp)
                await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError, ValueError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def serve(state: SpacecraftState, host: str = "0.0.0.0", port: int = DEFAULT_PORT,
                on_tc: Optional[TcCB] = None) -> asyncio.AbstractServer:
    """CCSDS TT&C TCP 서버 기동(비차단). 반환된 server 를 close() 로 종료."""
    return await asyncio.start_server(
        lambda r, w: _handle_client(state, r, w, on_tc), host, port)
