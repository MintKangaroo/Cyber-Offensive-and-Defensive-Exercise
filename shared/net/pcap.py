"""
최소 PCAP 라이터 + Ethernet/IPv4/TCP·UDP 프레이밍 (외부 의존 0)
================================================================
ICS 포렌식 챌린지의 "합성 로그(jsonl)"를 **진짜 .pcap**(Wireshark·tcpdump가 프로토콜을
그대로 디섹션)으로 승격하기 위한 재사용 헬퍼. 애플리케이션 페이로드(Modbus MBAP+PDU,
DNP3, S7 TPKT/COTP, HART-IP 등)는 각 `shared/ics/*.py` 실 인코더가 만들고, 여기서 L2~L4
로 감싸 체크섬을 채운다.

- link-type = Ethernet(1). 표준 pcap 매직(0xa1b2c3d4, us 해상도).
- IPv4/TCP/UDP 체크섬 정확 계산 → Wireshark 가 "checksum valid" 로 디섹션.
- `TCPSession` 이 seq/ack 를 추적해 클라이언트↔서버 스트림을 만든다(포트 기반 디섹터 발화).
전부 합성 트래픽(실장비/실호스트 무관).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1

# 합성 MAC(로컬 관리 비트 set). 실장비 무관.
MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def _checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ip_to_bytes(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def ipv4(src: str, dst: str, proto: int, payload: bytes, ident: int = 0, ttl: int = 64) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH", 0x45, 0, total, ident & 0xFFFF, 0x4000, ttl, proto, 0)
    hdr += _ip_to_bytes(src) + _ip_to_bytes(dst)
    chk = _checksum16(hdr)
    hdr = hdr[:10] + struct.pack(">H", chk) + hdr[12:]
    return hdr + payload


def _l4_checksum(src: str, dst: str, proto: int, segment: bytes) -> int:
    pseudo = _ip_to_bytes(src) + _ip_to_bytes(dst) + struct.pack(">BBH", 0, proto, len(segment))
    return _checksum16(pseudo + segment)


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
        flags: int, payload: bytes = b"") -> bytes:
    off = (5 << 4)
    seg = struct.pack(">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                      off, flags, 8192, 0, 0) + payload
    chk = _l4_checksum(src, dst, 6, seg)
    seg = seg[:16] + struct.pack(">H", chk) + seg[18:]
    return ipv4(src, dst, 6, seg)


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    seg = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    chk = _l4_checksum(src, dst, 17, seg) or 0xFFFF
    seg = seg[:6] + struct.pack(">H", chk) + seg[8:]
    return ipv4(src, dst, 17, seg)


def ethernet(src_mac: bytes, dst_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", ethertype) + payload


def eth_ip(frame_ip: bytes, src_mac: bytes = MAC_A, dst_mac: bytes = MAC_B) -> bytes:
    return ethernet(src_mac, dst_mac, 0x0800, frame_ip)


def write_pcap(path: str, records: list[tuple[float, bytes]]) -> None:
    """records = [(epoch_ts, ethernet_frame_bytes)]."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts, frame in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000)) % 1_000_000
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)


@dataclass
class TCPSession:
    """클라이언트(A)↔서버(B) TCP 스트림. seq/ack 추적 + Ethernet 프레임 산출."""
    client_ip: str
    server_ip: str
    server_port: int
    client_port: int = 40000
    cseq: int = 1000
    sseq: int = 5000
    records: list = field(default_factory=list)

    def _emit(self, ts, ip_frame, from_client: bool):
        smac, dmac = (MAC_A, MAC_B) if from_client else (MAC_B, MAC_A)
        self.records.append((ts, ethernet(smac, dmac, 0x0800, ip_frame)))

    def handshake(self, ts: float):
        self._emit(ts, tcp(self.client_ip, self.server_ip, self.client_port,
                           self.server_port, self.cseq, 0, TCP_SYN), True)
        self.cseq += 1
        self._emit(ts, tcp(self.server_ip, self.client_ip, self.server_port,
                           self.client_port, self.sseq, self.cseq, TCP_SYN | TCP_ACK), False)
        self.sseq += 1
        self._emit(ts, tcp(self.client_ip, self.server_ip, self.client_port,
                           self.server_port, self.cseq, self.sseq, TCP_ACK), True)

    def client_msg(self, ts: float, payload: bytes):
        self._emit(ts, tcp(self.client_ip, self.server_ip, self.client_port,
                           self.server_port, self.cseq, self.sseq, TCP_PSH | TCP_ACK, payload), True)
        self.cseq += len(payload)

    def server_msg(self, ts: float, payload: bytes):
        self._emit(ts, tcp(self.server_ip, self.client_ip, self.server_port,
                           self.client_port, self.sseq, self.cseq, TCP_PSH | TCP_ACK, payload), False)
        self.sseq += len(payload)


# ---------------------------------------------------------------------------
# 읽기 헬퍼 — 포렌식(익스플로잇)에서 재사용
# ---------------------------------------------------------------------------
@dataclass
class Segment:
    ts: float
    src_ip: str
    dst_ip: str
    proto: int          # 6=TCP, 17=UDP
    sport: int
    dport: int
    payload: bytes


def read_pcap(path: str) -> list[tuple[float, bytes]]:
    """pcap → [(ts, ethernet_frame)]. little/big endian 매직 모두 지원."""
    with open(path, "rb") as f:
        data = f.read()
    magic = struct.unpack("<I", data[:4])[0]
    endian = "<" if magic == PCAP_MAGIC else ">"
    off = 24
    out = []
    while off + 16 <= len(data):
        sec, usec, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        frame = data[off:off + incl]
        off += incl
        out.append((sec + usec / 1_000_000, frame))
    return out


def parse_l4(frame: bytes) -> "Segment | None":
    """Ethernet+IPv4+TCP/UDP 프레임 → Segment(페이로드 포함). IPv4/TCP·UDP 만."""
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    l4 = ip[ihl:]
    if proto == 6:
        if len(l4) < 20:
            return None
        sport, dport = struct.unpack(">HH", l4[:4])
        doff = (l4[12] >> 4) * 4
        return Segment(0.0, src, dst, 6, sport, dport, l4[doff:])
    if proto == 17:
        if len(l4) < 8:
            return None
        sport, dport, length, _ = struct.unpack(">HHHH", l4[:8])
        return Segment(0.0, src, dst, 17, sport, dport, l4[8:length])
    return None


def read_segments(path: str) -> list["Segment"]:
    """pcap → 페이로드 있는 L4 세그먼트 목록(ts 채워짐)."""
    segs = []
    for ts, frame in read_pcap(path):
        seg = parse_l4(frame)
        if seg and seg.payload:
            seg.ts = ts
            segs.append(seg)
    return segs
