"""
ICS-004 배포 생성기 — 실 IEC 60870-5-104 사보타주 캡처(.pcap) 합성.
====================================================================
목업 JSON 로그가 아니라 **진짜 IEC 104 트래픽**을 담은 pcap 을 만든다. Wireshark 가 포트 2404
를 IEC 104(104apci/104asdu)로 디섹션한다. 프레임은 `shared/ics/iec104.py` 실 인코더로 만든다.

시나리오: 정상 제어국(10.40.0.3)의 M_SP_NA_1 감시 트래픽 사이에, 무단 제어국(rogue, 팀별 IP)이
보호 차단기(CB, IOA=7)에 C_SC_NA_1(단일명령, 활성화)을 주입한 사보타주가 숨어 있다. 그 명령
ASDU 의 정보요소에 토큰(= flag ⊕ 공격자 IP)이 실려 있다. 분석: 보호 IOA 에 제어 ASDU 를 내린
정상 아닌 출발지를 찾아 공격자 IP 를 식별하고, 정보요소 페이로드를 공격자 IP 로 XOR 복호하면 flag.

팀별 공격자 IP·flag·타이밍이 HMAC 결정. 모든 값은 합성 더미(실장비/실호스트 무관).
"""
import hashlib
import hmac
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))  # repo 루트(shared 임포트)

from shared.ics import iec104
from shared.net import pcap

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

LEGIT_MASTER = "10.40.0.3"
RTU_IP = "10.40.0.20"
PORT = 2404
COMMON_ADDR = 1
CB_IOA = 7


def _hmac(tag, team, n):
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team):
    return f"flag{{iec104_command_injection_{_hmac('ICS-004', team, 12)}}}"


def attacker_ip(team):
    return f"10.40.0.{int(_hmac('ICS-004-ip', team, 4), 16) % 200 + 30}"


def _xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


def build(team) -> list:
    rng = random.Random(int(_hmac("ICS-004-seed", team, 8), 16))
    ts = 1_700_000_000.0

    master = pcap.TCPSession(LEGIT_MASTER, RTU_IP, PORT, client_port=41000)
    master.handshake(ts)
    events = []
    ssn = 0
    for _ in range(60):
        ts += rng.uniform(0.5, 2.0)
        ioa = rng.choice([100, 101, 102])
        asdu = iec104.build_asdu(iec104.M_SP_NA_1, cot=3, common_addr=COMMON_ADDR,
                                 ioa=ioa, info=bytes([rng.choice([0, 1])]))
        events.append((ts, master, "s", iec104.build_i_apdu(asdu, send_seq=ssn)))
        ssn += 1
    # 미끼: 정상 마스터의 제어(보호 IOA 아님)
    for _ in range(3):
        ts += rng.uniform(0.5, 2.0)
        asdu = iec104.build_asdu(iec104.C_SC_NA_1, cot=6, common_addr=COMMON_ADDR,
                                 ioa=rng.choice([200, 201]), info=bytes([1]))
        events.append((ts, master, "c", iec104.build_i_apdu(asdu, send_seq=ssn)))
        ssn += 1

    # 사보타주: rogue 제어국이 CB(IOA 7)에 C_SC_NA_1(활성화) + 토큰
    rogue = pcap.TCPSession(attacker_ip(team), RTU_IP, PORT, client_port=42000)
    t_atk = 1_700_000_000.0 + rng.uniform(20, 90)
    rogue.handshake(t_atk)
    token = _xor(dynamic_flag(team).encode(), attacker_ip(team).encode())
    sabotage = iec104.build_asdu(iec104.C_SC_NA_1, cot=6, common_addr=COMMON_ADDR,
                                 ioa=CB_IOA, info=bytes([1]) + token)
    events.append((t_atk + 0.1, rogue, "c", iec104.build_i_apdu(sabotage)))

    for et, sess, kind, payload in sorted(events, key=lambda e: e[0]):
        (sess.client_msg if kind == "c" else sess.server_msg)(et, payload)
    records = master.records + rogue.records
    records.sort(key=lambda r: r[0])
    return records


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "iec104_sabotage.pcap")
    pcap.write_pcap(out, build(team))
    print(f"생성 완료: iec104_sabotage.pcap (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
