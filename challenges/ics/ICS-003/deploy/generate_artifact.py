"""
ICS-003 배포 생성기 — 실 DNP3 사보타주 캡처(.pcap) 합성.
=========================================================
목업 JSON 로그가 아니라 **진짜 DNP3(IEEE 1815) 트래픽**을 담은 pcap 을 만든다. Wireshark 가
포트 20000 을 DNP3 로 디섹션한다. 프레임은 플랫폼 트윈과 동일한 `shared/ics/dnp3.py` 실
인코더(데이터링크 CRC 포함)로 만든다.

시나리오: 정상 마스터(10.30.0.4)의 Class 0 READ 폴링 사이에, 무단 마스터(rogue, 팀별 IP)가
보호 제어점(차단기 CB, index 7)에 DIRECT_OPERATE(FC5, LATCH_ON)를 내린 사보타주 1건이 숨어
있다. 그 프레임에는 g110 octet string 오브젝트로 토큰(= flag ⊕ 공격자 IP)이 실려 있다.
분석: 보호 제어점 OPERATE 를 정상 마스터가 아닌 출발지에서 찾아 공격자 IP 를 식별하고,
DNP3 octet string 페이로드를 공격자 IP 로 반복 XOR 복호하면 flag.

팀별 공격자 IP·flag·타이밍이 HMAC 결정. 모든 값은 합성 더미(실장비/실호스트 무관).
"""
import hashlib
import hmac
import os
import random
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))  # repo 루트(shared 임포트)

from shared.ics import dnp3
from shared.net import pcap

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

LEGIT_MASTER = "10.30.0.4"
OUTSTATION_IP = "10.30.0.20"
DNP3_PORT = 20000
OUTSTATION_ADDR = 10
CB_POINT = 7


def _hmac(tag, team, n):
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team):
    return f"flag{{dnp3_unsolicited_control_{_hmac('ICS-003', team, 12)}}}"


def attacker_ip(team):
    return f"10.30.0.{int(_hmac('ICS-003-ip', team, 4), 16) % 200 + 30}"


def _xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


def octet_string_obj(data: bytes) -> bytes:
    """DNP3 g110 (octet string) 오브젝트 — 임의 바이트 운반. index 0, 8bit 범위."""
    return bytes([110, len(data), 0x00, 0x00, 0x00]) + data


def rogue_operate_frame(team, source_addr: int) -> bytes:
    """CB DIRECT_OPERATE + g110 토큰 오브젝트를 담은 실 DNP3 프레임."""
    cc = dnp3.CROB_LATCH_ON
    crob = struct.pack("<BBIIBB", cc, 1, 0, 0, 0, 0)[:11].ljust(11, b"\x00")
    crob_obj = struct.pack("<BBBB", 12, 1, 0x17, 1) + struct.pack("<B", CB_POINT) + crob
    token = _xor(dynamic_flag(team).encode(), attacker_ip(team).encode())
    app = struct.pack("<BB", 0xC0, dnp3.FC_DIRECT_OPERATE) + crob_obj + octet_string_obj(token)
    return dnp3.encode_frame(0xC4, OUTSTATION_ADDR, source_addr, app)


def build(team) -> list:
    rng = random.Random(int(_hmac("ICS-003-seed", team, 8), 16))
    ts = 1_700_000_000.0

    legit = pcap.TCPSession(LEGIT_MASTER, OUTSTATION_IP, DNP3_PORT, client_port=41000)
    legit.handshake(ts)
    events = []
    for i in range(60):
        ts += rng.uniform(0.5, 2.0)
        req = dnp3.build_read_request(OUTSTATION_ADDR, source=1, seq=i & 0x0F)
        events.append((ts, legit, "c", req))
        events.append((ts + 0.01, legit, "s", dnp3.encode_frame(0x44, 1, OUTSTATION_ADDR,
                       struct.pack("<BBH", 0xC0, 0x81, 0x0000))))
    # 미끼: 정상 마스터의 OPERATE(보호점 아님, index 11)
    for _ in range(3):
        ts += rng.uniform(0.5, 2.0)
        events.append((ts, legit, "c", dnp3.build_direct_operate_crob(OUTSTATION_ADDR, 11, True, source=1)))

    rogue = pcap.TCPSession(attacker_ip(team), OUTSTATION_IP, DNP3_PORT, client_port=42000)
    t_atk = 1_700_000_000.0 + rng.uniform(20, 90)
    rogue.handshake(t_atk)
    events.append((t_atk + 0.1, rogue, "c", rogue_operate_frame(team, source_addr=500)))

    for et, sess, kind, payload in sorted(events, key=lambda e: e[0]):
        (sess.client_msg if kind == "c" else sess.server_msg)(et, payload)

    records = legit.records + rogue.records
    records.sort(key=lambda r: r[0])
    return records


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "dnp3_sabotage.pcap")
    pcap.write_pcap(out, build(team))
    print(f"생성 완료: dnp3_sabotage.pcap (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
