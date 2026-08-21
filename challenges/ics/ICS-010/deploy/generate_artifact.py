"""
ICS-010 배포 생성기 — 실 EtherNet/IP CIP 사보타주 캡처(.pcap) 합성.
====================================================================
목업 JSON 로그가 아니라 **진짜 EtherNet/IP + CIP 트래픽**을 담은 pcap 을 만든다. Wireshark 가
포트 44818 을 ENIP/CIP 로 디섹션한다. 프레임은 `shared/ics/enip.py` 실 인코더로 만든다.

시나리오: 정상 스캐너(10.80.0.5)의 GetAttributeSingle 폴링 사이에, 무단 호스트(rogue, 팀별 IP)가
안전 Assembly 오브젝트(class 0x04, instance 101, attr 3)에 SetAttributeSingle 을 내려 안전
어셈블리를 조작한 사보타주가 숨어 있다. 그 CIP 요청 데이터에 토큰(= flag ⊕ 공격자 IP)이 실려
있다. 분석: 안전 Assembly 에 SetAttributeSingle 을 내린 정상 아닌 출발지를 찾아 공격자 IP 를
식별하고, CIP 데이터를 공격자 IP 로 XOR 복호하면 flag.

팀별 공격자 IP·flag·타이밍이 HMAC 결정. 모든 값은 합성 더미(실장비/실호스트 무관).
"""
import hashlib
import hmac
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))  # repo 루트(shared 임포트)

from shared.ics import enip
from shared.net import pcap

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

LEGIT = "10.80.0.5"
PLC_IP = "10.80.0.20"
PORT = 44818
SAFETY_CLASS = 0x04       # Assembly Object
SAFETY_INSTANCE = 101
ATTRIBUTE = 3


def _hmac(tag, team, n):
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team):
    return f"flag{{ethernetip_cip_safety_tamper_{_hmac('ICS-010', team, 12)}}}"


def attacker_ip(team):
    return f"10.80.0.{int(_hmac('ICS-010-ip', team, 4), 16) % 200 + 30}"


def _xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


def build(team) -> list:
    rng = random.Random(int(_hmac("ICS-010-seed", team, 8), 16))
    ts = 1_700_000_000.0

    scanner = pcap.TCPSession(LEGIT, PLC_IP, PORT, client_port=41000)
    scanner.handshake(ts)
    for _ in range(58):
        ts += rng.uniform(0.1, 0.6)
        cip = enip.build_cip_request(enip.SVC_GET_ATTR_SINGLE, rng.choice([0x04, 0x6B, 0x01]),
                                     rng.randint(1, 120), ATTRIBUTE)
        scanner.client_msg(ts, enip.build_sendrrdata(cip))
    # 미끼: 정상 스캐너의 SetAttributeSingle(안전 어셈블리 아님)
    for _ in range(3):
        ts += rng.uniform(0.2, 0.8)
        cip = enip.build_cip_request(enip.SVC_SET_ATTR_SINGLE, 0x04, rng.choice([150, 151]),
                                     ATTRIBUTE, b"\x00\x01")
        scanner.client_msg(ts, enip.build_sendrrdata(cip))

    # 사보타주: rogue 가 안전 Assembly 에 SetAttributeSingle(토큰 데이터)
    rogue = pcap.TCPSession(attacker_ip(team), PLC_IP, PORT, client_port=42000)
    t_atk = 1_700_000_000.0 + rng.uniform(15, 60)
    rogue.handshake(t_atk)
    token = _xor(dynamic_flag(team).encode(), attacker_ip(team).encode())
    cip = enip.build_cip_request(enip.SVC_SET_ATTR_SINGLE, SAFETY_CLASS, SAFETY_INSTANCE,
                                 ATTRIBUTE, token)
    rogue.client_msg(t_atk + 0.05, enip.build_sendrrdata(cip))

    records = scanner.records + rogue.records
    records.sort(key=lambda r: r[0])
    return records


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "enip_sabotage.pcap")
    pcap.write_pcap(out, build(team))
    print(f"생성 완료: enip_sabotage.pcap (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
