"""
shared/net/pcap.py + Modbus 실 프레임 빌더/파서 단위 테스트 — ICS 포렌식 pcap 승격.
- pcap write→read 라운드트립(TCP 세션), IPv4/TCP 체크섬 유효(파서 재해석).
- Modbus mbap/build_*/parse_frame/parse_pdu 라운드트립.
"""
import struct

from shared.ics import modbus
from shared.net import pcap


def test_pcap_write_read_roundtrip(tmp_path):
    sess = pcap.TCPSession("10.0.0.1", "10.0.0.2", 502, client_port=41000)
    sess.handshake(1_700_000_000.0)
    payload = modbus.mbap(modbus.build_read_holding(0, 4))
    sess.client_msg(1_700_000_001.0, payload)
    out = str(tmp_path / "t.pcap")
    pcap.write_pcap(out, sess.records)

    segs = pcap.read_segments(out)
    # 페이로드 있는 세그먼트는 client_msg 1건(핸드셰이크는 payload 없음)
    assert len(segs) == 1
    seg = segs[0]
    assert seg.src_ip == "10.0.0.1" and seg.dst_ip == "10.0.0.2"
    assert seg.dport == 502 and seg.proto == 6
    assert seg.payload == payload


def test_ipv4_tcp_checksums_valid():
    frame_ip = pcap.tcp("192.168.0.10", "192.168.0.20", 41000, 502, 1, 1,
                        pcap.TCP_PSH | pcap.TCP_ACK, b"\x00\x01\x02\x03")
    # IPv4 헤더 체크섬 재계산 = 0 (유효)
    assert pcap._checksum16(frame_ip[:20]) == 0
    # TCP 세그먼트 체크섬(pseudo-header 포함) = 0
    seg = frame_ip[20:]
    assert pcap._l4_checksum("192.168.0.10", "192.168.0.20", 6, seg) == 0


def test_modbus_frame_pdu_roundtrip():
    # FC16 다중 쓰기 프레임 → 파싱 라운드트립
    pdu = modbus.build_write_multiple(0, [0x4142, 0x4344, 0x4500])
    frame = modbus.mbap(pdu, unit=1, tid=7)
    tid, unit, back = modbus.parse_frame(frame)
    assert tid == 7 and unit == 1 and back == pdu
    info = modbus.parse_pdu(back)
    assert info["fc"] == 16 and info["addr"] == 0 and info["qty"] == 3
    assert info["values"] == [0x4142, 0x4344, 0x4500]
    assert info["raw_bytes"] == struct.pack(">HHH", 0x4142, 0x4344, 0x4500)


def test_modbus_read_write_single_parse():
    assert modbus.parse_pdu(modbus.build_read_holding(9, 2)) == {"fc": 3, "addr": 9, "qty": 2}
    assert modbus.parse_pdu(modbus.build_write_single(19, 42)) == {"fc": 6, "addr": 19, "value": 42}
