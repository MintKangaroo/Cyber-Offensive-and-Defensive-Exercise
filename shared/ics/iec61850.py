"""
실 IEC 61850 MMS(전력 변전소 프로토콜) 아웃스테이션 — TPKT/COTP/MMS 스택
=========================================================================
IEC 61850은 전력 변전소 자동화(IED: Intelligent Electronic Device) 표준. 스테이션 버스의
클라이언트/서버 통신은 MMS(Manufacturing Message Specification, ISO 9506)를 ISO 상위계층 위에
얹어 TCP 포트 102로 나른다. 트윈이 HTTP 목업이 아니라 실제 TPKT/COTP/MMS로 응답한다.
(Modbus/DNP3/OPC UA/S7comm 과 동일 철학: 소켓 무관 순수 함수 + serve().)

계층(S7comm 과 동일한 TPKT/COTP 프레이밍을 공유):
  - TPKT(RFC 1006): 03 00 <len16>.
  - COTP(ISO 8073): CR(0xE0)→CC(0xD0) 연결설정, DT(0xF0) 데이터 운반.
  - (표준 스택은 여기에 ISO Session/Presentation/ACSE 가 더 있지만, 본 트윈은 S7 과 동일하게
    COTP DT 위에 바로 MMS PDU 를 얹는 최소 프로파일을 쓴다 — 아래 정직한 스코프 참조.)
  - MMS PDU: ASN.1 BER 로 인코드. 지원 서비스:
      · Initiate-Request(context-tag 0xA8) → Initiate-Response(0xA9): 연결 파라미터 협상.
      · confirmed-RequestPDU(0xA0) + Read(0xA4) → confirmed-ResponsePDU(0xA1) + Read result:
        IED 아날로그/상태 측정값(모선전압·선로전류·차단기상태)을 Integer/BitString 으로 반환.

정직한 스코프(honest minimal-but-real subset)
--------------------------------------------
- 실제인 것: TPKT/COTP 프레이밍(S7comm 과 바이트 동일, 상호검증 가능). MMS Initiate/Read 의
  ASN.1 BER 태그/길이/값 인코딩(Read result 의 Integer/BitString 은 표준 BER).
- 최소화한 것: OPC UA 의 "transport+securechannel only" 스코프와 동일한 방침. ISO Session/
  Presentation/ACSE 상위계층과, MMS 의 방대한 서비스(GetNameList, GetVariableAccessAttributes,
  Report/GOOSE, 완전한 VariableAccessSpecification 파싱)는 구현하지 않는다. Read 요청의 변수
  스펙은 요청된 개수만 세고, 서버는 미리 정의된 IED 데이터셋을 순서대로 돌려준다.
- 클라이언트 헬퍼와 서버는 자기일관적(self-consistent)이다: 아래 build_mms_* 헬퍼가 만든
  PDU 를 handle_mms_pdu 가 정확히 해석하고, 응답을 parse_mms_read_response 가 되읽는다.
미인증 MMS Read/Initiate 는 그 자체로 변전소 IED 정찰이므로 이벤트 발행 + SIEM 기록(Blue 탐지).
"""
from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from typing import Callable, Optional

IEC61850_DEFAULT_PORT = 102


# ======================================================================
# TPKT (RFC 1006) — S7comm 과 바이트 동일
# ======================================================================
def tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 0x03, 0x00, len(payload) + 4) + payload


def parse_tpkt_len(head4: bytes) -> Optional[int]:
    if len(head4) < 4 or head4[0] != 0x03:
        return None
    return struct.unpack(">H", head4[2:4])[0]


# ======================================================================
# COTP (ISO 8073) — S7comm 과 바이트 동일 (CR→CC, DT)
# ======================================================================
def build_cotp_cr() -> bytes:
    """Connection Request — TPKT 로 감싼 완전한 프레임."""
    params = (bytes([0xC0, 0x01, 0x0A]) + bytes([0xC1, 0x02, 0x01, 0x00]) +
              bytes([0xC2, 0x02, 0x01, 0x02]))
    body = struct.pack(">BHHB", 0xE0, 0x0000, 0x0001, 0x00) + params
    return tpkt(bytes([len(body)]) + body)


def build_cotp_cc(src_ref: int = 0x0001, dst_ref: int = 0x0000) -> bytes:
    """Connection Confirm(요청 TSAP 파라미터를 최소로 에코). COTP 본문만 반환."""
    params = (bytes([0xC0, 0x01, 0x0A]) +          # tpdu-size = 1024
              bytes([0xC1, 0x02, 0x01, 0x00]) +    # src-tsap
              bytes([0xC2, 0x02, 0x01, 0x02]))     # dst-tsap
    body = struct.pack(">BHHB", 0xD0, dst_ref, src_ref, 0x00) + params
    return bytes([len(body)]) + body


def is_cotp_cr(cotp: bytes) -> bool:
    return len(cotp) >= 2 and cotp[1] == 0xE0


def cotp_dt_payload(cotp: bytes) -> Optional[bytes]:
    """COTP DT(0xF0)면 상위(MMS) 페이로드 반환. length(1)+0xF0+eot(1) 뒤."""
    if len(cotp) >= 3 and cotp[1] == 0xF0:
        li = cotp[0]
        return cotp[li + 1:]
    return None


def build_cotp_dt(payload: bytes) -> bytes:
    return bytes([0x02, 0xF0, 0x80]) + payload


# ======================================================================
# ASN.1 BER — Initiate/Read 에 필요한 최소분
# ======================================================================
def ber_len(n: int) -> bytes:
    """BER 길이 인코딩(short/long form)."""
    if n < 0x80:
        return bytes([n])
    out = b""
    while n > 0:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def ber_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + ber_len(len(value)) + value


def parse_ber_len(buf: bytes, i: int) -> tuple[int, int]:
    """buf[i] 부터 BER 길이 파싱 → (length, next_index)."""
    first = buf[i]
    i += 1
    if first < 0x80:
        return first, i
    nbytes = first & 0x7F
    length = int.from_bytes(buf[i:i + nbytes], "big")
    return length, i + nbytes


def iter_ber(buf: bytes, i: int = 0, end: Optional[int] = None):
    """(tag, value_bytes, next_index) 를 순차 산출."""
    if end is None:
        end = len(buf)
    while i < end:
        tag = buf[i]
        length, j = parse_ber_len(buf, i + 1)
        yield tag, buf[j:j + length], j + length
        i = j + length


# ======================================================================
# MMS 태그(본 프로파일에서 사용하는 context/application 태그)
# ======================================================================
TAG_INITIATE_REQUEST = 0xA8    # [8] IMPLICIT
TAG_INITIATE_RESPONSE = 0xA9   # [9] IMPLICIT
TAG_CONFIRMED_REQUEST = 0xA0   # [0] IMPLICIT
TAG_CONFIRMED_RESPONSE = 0xA1  # [1] IMPLICIT
TAG_INVOKE_ID = 0x02           # INTEGER (confirmed PDU 의 invokeID)
TAG_READ_REQUEST = 0xA4        # [4] Read
TAG_READ_RESPONSE = 0xA4       # [4] Read (ConfirmedServiceResponse)
TAG_LIST_OF_VAR = 0xA1         # [1] listOfVariable / listOfAccessResult
TAG_DATA_INTEGER = 0x85        # [5] IMPLICIT INTEGER (MMS Data integer)
TAG_DATA_BITSTRING = 0x84      # [4] IMPLICIT BIT STRING (MMS Data bit-string)


# ======================================================================
# IED (변전소 지능형 전자장치) 데이터 모델
# ======================================================================
@dataclass
class MmsDataPoint:
    """IED 측정/상태 포인트. kind: 'int' | 'bits'."""
    name: str
    kind: str
    value: int          # int: 정수값(예: 전압 mV/전류 mA scaled). bits: 비트필드.
    bits: int = 8       # bits 종류일 때 비트 폭(예: 차단기 상태 이중포인트)


@dataclass
class IED:
    """변전소 IED — 미리 정의된 데이터셋을 MMS Read 로 노출."""
    points: list[MmsDataPoint] = field(default_factory=list)
    vendor: str = "CyberRange-IED"
    on_read: Optional[Callable[[int], None]] = None      # (요청 변수 개수)
    on_initiate: Optional[Callable[[], None]] = None

    @staticmethod
    def substation_default() -> "IED":
        return IED(points=[
            MmsDataPoint("MMXU1.PhV.phsA (bus voltage kV)", "int", 22900),   # 22.9 kV *1000
            MmsDataPoint("MMXU1.A.phsA (line current A)", "int", 415),       # 415 A
            MmsDataPoint("XCBR1.Pos.stVal (breaker status)", "bits", 0b10, bits=2),  # dbpos: on
        ])


# ======================================================================
# MMS 데이터 값 인코딩/디코딩
# ======================================================================
def encode_mms_data(dp: MmsDataPoint) -> bytes:
    if dp.kind == "bits":
        # BIT STRING: 첫 옥텟 = 미사용 비트 수, 이어서 비트 옥텟(들).
        nbytes = (dp.bits + 7) // 8
        unused = nbytes * 8 - dp.bits
        val = dp.value << unused
        body = bytes([unused]) + val.to_bytes(nbytes, "big")
        return ber_tlv(TAG_DATA_BITSTRING, body)
    # integer
    body = dp.value.to_bytes(((dp.value.bit_length() // 8) + 1), "big", signed=True)
    return ber_tlv(TAG_DATA_INTEGER, body)


def decode_mms_data(tag: int, value: bytes) -> tuple[str, int]:
    """(kind, value). BitString 은 미사용비트 정규화 후 정수."""
    if tag == TAG_DATA_BITSTRING:
        unused = value[0] if value else 0
        raw = int.from_bytes(value[1:], "big") if len(value) > 1 else 0
        return "bits", raw >> unused
    if tag == TAG_DATA_INTEGER:
        return "int", int.from_bytes(value, "big", signed=True)
    return "unknown", 0


# ======================================================================
# MMS PDU 조립 — 서버측
# ======================================================================
def _initiate_response() -> bytes:
    """Initiate-Response(0xA9): 협상 파라미터를 최소로 회신."""
    body = (
        ber_tlv(0x80, (128).to_bytes(2, "big")) +   # localDetailCalled
        ber_tlv(0x81, bytes([5])) +                 # proposedMaxServOutstandingCalling
        ber_tlv(0x82, bytes([5])) +                 # proposedMaxServOutstandingCalled
        ber_tlv(0x83, bytes([10]))                  # proposedDataStructureNestingLevel
    )
    return ber_tlv(TAG_INITIATE_RESPONSE, body)


def _read_response(ied: IED, invoke_id: int) -> bytes:
    """confirmed-ResponsePDU(0xA1) + Read result(전 데이터셋)."""
    access_results = b"".join(encode_mms_data(dp) for dp in ied.points)
    list_of_result = ber_tlv(TAG_LIST_OF_VAR, access_results)  # [1] listOfAccessResult
    read_resp = ber_tlv(TAG_READ_RESPONSE, list_of_result)      # [4] Read
    body = ber_tlv(TAG_INVOKE_ID, invoke_id.to_bytes(1, "big")) + read_resp
    return ber_tlv(TAG_CONFIRMED_RESPONSE, body)


def handle_mms_pdu(ied: IED, pdu: bytes) -> Optional[bytes]:
    """MMS 요청 PDU → 응답 PDU(순수 함수). Initiate / confirmed Read 만 처리."""
    if not pdu:
        return None
    tag = pdu[0]
    length, i = parse_ber_len(pdu, 1)
    body = pdu[i:i + length]

    if tag == TAG_INITIATE_REQUEST:
        if ied.on_initiate:
            ied.on_initiate()
        return _initiate_response()

    if tag == TAG_CONFIRMED_REQUEST:
        invoke_id = 0
        var_count = 0
        found_read = False
        for t, v, _ in iter_ber(body):
            if t == TAG_INVOKE_ID:
                invoke_id = int.from_bytes(v, "big") if v else 0
            elif t == TAG_READ_REQUEST:
                found_read = True
                # Read 안의 listOfVariable([1]) → 변수 개수만 카운트(최소 파싱)
                for st, sv, _ in iter_ber(v):
                    if st == TAG_LIST_OF_VAR:
                        var_count = sum(1 for _ in iter_ber(sv))
        if not found_read:
            return None
        if ied.on_read:
            ied.on_read(var_count)
        return _read_response(ied, invoke_id)

    return None


# ======================================================================
# 클라이언트 헬퍼(테스트/검증용)
# ======================================================================
def build_mms_initiate() -> bytes:
    """TPKT+COTP DT 로 감싼 MMS Initiate-Request."""
    body = (
        ber_tlv(0x80, (128).to_bytes(2, "big")) +   # localDetailCalling
        ber_tlv(0x81, bytes([5])) +                 # proposedMaxServOutstandingCalling
        ber_tlv(0x82, bytes([5]))                   # proposedMaxServOutstandingCalled
    )
    pdu = ber_tlv(TAG_INITIATE_REQUEST, body)
    return tpkt(build_cotp_dt(pdu))


def build_mms_read(var_names: Optional[list[str]] = None, invoke_id: int = 1) -> bytes:
    """TPKT+COTP DT 로 감싼 confirmed Read-Request.

    var_names 는 요청 변수명 목록(개수만 유효; 서버는 IED 데이터셋 전체를 반환)."""
    names = var_names or ["MMXU1.PhV", "MMXU1.A", "XCBR1.Pos"]
    # listOfVariable([1]): 각 변수는 objectName(간이) 로 표현 — VisibleString(0x1A) 로 최소 인코딩
    variables = b"".join(ber_tlv(0x1A, n.encode()) for n in names)
    list_of_var = ber_tlv(TAG_LIST_OF_VAR, variables)
    read_req = ber_tlv(TAG_READ_REQUEST, list_of_var)
    body = ber_tlv(TAG_INVOKE_ID, invoke_id.to_bytes(1, "big")) + read_req
    pdu = ber_tlv(TAG_CONFIRMED_REQUEST, body)
    return tpkt(build_cotp_dt(pdu))


def parse_mms_read_response(frame: bytes) -> Optional[list[tuple[str, int]]]:
    """TPKT+COTP+MMS confirmed-Response 에서 (kind, value) 목록 추출."""
    if len(frame) < 7 or frame[0] != 0x03:
        return None
    mms = cotp_dt_payload(frame[4:])
    if mms is None or not mms or mms[0] != TAG_CONFIRMED_RESPONSE:
        return None
    length, i = parse_ber_len(mms, 1)
    body = mms[i:i + length]
    out: list[tuple[str, int]] = []
    for t, v, _ in iter_ber(body):
        if t == TAG_READ_RESPONSE:                     # [4] Read
            for st, sv, _ in iter_ber(v):
                if st == TAG_LIST_OF_VAR:              # [1] listOfAccessResult
                    for dt, dv, _ in iter_ber(sv):
                        out.append(decode_mms_data(dt, dv))
    return out


def is_mms_initiate_response(pdu: bytes) -> bool:
    return len(pdu) >= 1 and pdu[0] == TAG_INITIATE_RESPONSE


# ======================================================================
# 서버 (asyncio)
# ======================================================================
async def serve(ied: IED, host: str = "0.0.0.0", port: int = IEC61850_DEFAULT_PORT
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
                mms = cotp_dt_payload(cotp)
                if mms is None:
                    continue
                resp = handle_mms_pdu(ied, mms)
                if resp:
                    writer.write(tpkt(build_cotp_dt(resp))); await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(_handle, host, port)
