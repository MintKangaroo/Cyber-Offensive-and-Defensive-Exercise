"""
ICS-011 배포 생성기 — 실 S7comm 사보타주 캡처(.pcap) 합성.
==========================================================
목업 JSON 로그가 아니라 **진짜 S7comm(TPKT/COTP/S7) 트래픽**을 담은 pcap 을 만든다. Wireshark
가 포트 102 를 S7COMM 으로 디섹션한다. 프레임은 플랫폼 트윈과 동일한 `shared/ics/s7comm.py`
실 인코더(TPKT/COTP/S7)로 만든다.

시나리오: 정상 엔지니어링 스테이션(10.85.0.5)의 READ_VAR 폴링 사이에, 무단 호스트(rogue,
팀별 IP)가 안전 데이터블록(DB 62)에 WRITE_VAR 를 주입해 안전 로직 변수를 조작한 사보타주가
숨어 있다. WRITE_VAR 의 데이터 페이로드가 토큰(= flag ⊕ 공격자 IP)이다. 분석: DB 62 에
WRITE_VAR 를 내린 정상 아닌 출발지를 찾아 공격자 IP 를 식별하고, 쓰기 데이터를 공격자 IP 로
반복 XOR 복호하면 flag.

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

from shared.ics import s7comm
from shared.net import pcap

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

LEGIT = "10.85.0.5"
PLC_IP = "10.85.0.10"
S7_PORT = 102
SAFETY_DB = 62


def _hmac(tag, team, n):
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team):
    return f"flag{{s7comm_safety_db_write_{_hmac('ICS-011', team, 12)}}}"


def attacker_ip(team):
    return f"10.85.0.{int(_hmac('ICS-011-ip', team, 4), 16) % 200 + 30}"


def _xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


def build_s7_write(db_num: int, start_byte: int, data: bytes, pdu_ref: int = 3) -> bytes:
    """실 S7 Write Var(func 0x05) 프레임 — DB 에 임의 바이트 쓰기."""
    count = len(data)
    item = (bytes([0x12, 0x0A, 0x10, 0x02]) + struct.pack(">H", count) +
            struct.pack(">H", db_num) + bytes([0x84]) + (start_byte << 3).to_bytes(3, "big"))
    param = struct.pack(">BB", 0x05, 1) + item
    ditem = bytes([0x00, 0x04]) + struct.pack(">H", count * 8) + data
    if len(ditem) % 2:
        ditem += b"\x00"
    header = struct.pack(">BBHHHH", 0x32, 0x01, 0x0000, pdu_ref, len(param), len(ditem))
    return s7comm.tpkt(s7comm.build_cotp_dt(header + param + ditem))


def _session(client_ip, cport, ts, seed):
    """TCP + COTP CR/CC + S7 Setup 까지 세션 확립. (session, 다음 ts) 반환."""
    s = pcap.TCPSession(client_ip, PLC_IP, S7_PORT, client_port=cport)
    s.handshake(ts)
    s.client_msg(ts + 0.01, s7comm.build_cotp_cr())
    s.server_msg(ts + 0.02, s7comm.tpkt(s7comm.build_cotp_cc()))
    s.client_msg(ts + 0.03, s7comm.build_s7_setup())
    s.server_msg(ts + 0.04, s7comm.tpkt(s7comm.build_cotp_dt(
        struct.pack(">BBHHHHBB", 0x32, 0x03, 0, 1, 8, 0, 0, 0) + struct.pack(">BBHHH", 0xF0, 0, 1, 1, 480))))
    return s, ts + 0.1


def build(team) -> list:
    rng = random.Random(int(_hmac("ICS-011-seed", team, 8), 16))
    ts = 1_700_000_000.0
    legit, ts = _session(LEGIT, 41000, ts, rng)
    for _ in range(58):
        ts += rng.uniform(0.1, 0.6)
        db = rng.choice([1, 10, 20, 62])
        legit.client_msg(ts, s7comm.build_s7_read(db, 0, 2))
        legit.server_msg(ts + 0.01, s7comm.tpkt(s7comm.build_cotp_dt(
            struct.pack(">BBHHHHBB", 0x32, 0x03, 0, 2, 2, 4, 0, 0)
            + bytes([0x04, 1]) + bytes([0xFF, 0x04]) + struct.pack(">H", 32) + b"\x00\x00\x00\x2a")))
    # 미끼: 정상 스테이션의 WRITE_VAR(안전 DB 아님)
    for _ in range(3):
        ts += rng.uniform(0.2, 0.8)
        legit.client_msg(ts, build_s7_write(rng.choice([10, 20]), 0, b"\x00\x01"))

    # 사보타주: rogue 가 별도 세션으로 안전 DB(62)에 WRITE_VAR(토큰 페이로드)
    rogue, t2 = _session(attacker_ip(team), 42000, 1_700_000_000.0 + rng.uniform(15, 60), rng)
    token = _xor(dynamic_flag(team).encode(), attacker_ip(team).encode())
    rogue.client_msg(t2 + 0.05, build_s7_write(SAFETY_DB, 0, token))

    records = legit.records + rogue.records
    records.sort(key=lambda r: r[0])
    return records


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "s7_sabotage.pcap")
    pcap.write_pcap(out, build(team))
    print(f"생성 완료: s7_sabotage.pcap (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
