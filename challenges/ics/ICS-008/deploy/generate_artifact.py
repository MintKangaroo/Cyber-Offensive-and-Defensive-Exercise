"""
ICS-008 배포 생성기 — 실 BACnet/IP 사보타주 캡처(.pcap) 합성.
=============================================================
목업 JSON 로그가 아니라 **진짜 BACnet/IP 트래픽**을 담은 pcap 을 만든다. Wireshark 가 포트
47808(UDP)을 BACnet 으로 디섹션한다. 프레임은 `shared/ics/bacnet.py` 실 인코더로 만든다.

시나리오: 정상 BMS(10.70.0.10)의 ReadProperty 폴링 사이에, 무단 장치(rogue, 팀별 IP)가 냉방
setpoint 오브젝트(analog-output)에 WriteProperty(priority 8, 수동 오버라이드)를 내린 사보타주가
숨어 있다. WriteProperty 의 값(OctetString)에 토큰(= flag ⊕ 공격자 IP)이 실려 있다. 분석: 냉방
오브젝트에 WriteProperty 를 내린 정상 아닌 출발지를 찾아 공격자 IP 를 식별하고, 값을 공격자
IP 로 XOR 복호하면 flag.

팀별 공격자 IP·flag·타이밍이 HMAC 결정. 모든 값은 합성 더미(실장비/실호스트 무관).
"""
import hashlib
import hmac
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))  # repo 루트(shared 임포트)

from shared.ics import bacnet
from shared.net import pcap

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

LEGIT_BMS = "10.70.0.10"
CONTROLLER_IP = "10.70.0.40"
PORT = 47808
COOLING_OBJ = bacnet.OBJ_ANALOG_OUTPUT       # CRAC 급기온도 setpoint


def _hmac(tag, team, n):
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team):
    return f"flag{{bacnet_priority_override_{_hmac('ICS-008', team, 12)}}}"


def attacker_ip(team):
    return f"10.70.0.{int(_hmac('ICS-008-ip', team, 4), 16) % 200 + 30}"


def _xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


def _udp(src, payload):
    return pcap.eth_ip(pcap.udp(src, CONTROLLER_IP, PORT, PORT, payload))


def build(team) -> list:
    rng = random.Random(int(_hmac("ICS-008-seed", team, 8), 16))
    ts = 1_700_000_000.0
    read_objs = [bacnet.OBJ_ANALOG_INPUT, bacnet.OBJ_ANALOG_VALUE,
                 bacnet.OBJ_BINARY_INPUT, bacnet.OBJ_ANALOG_OUTPUT]
    records = []
    inv = 1
    for _ in range(58):
        ts += rng.uniform(0.5, 2.0)
        payload = bacnet.build_read_property(rng.choice(read_objs), rng.randint(1, 12), invoke_id=inv & 0xFF)
        records.append((ts, _udp(LEGIT_BMS, payload)))
        inv += 1
    # 미끼: 정상 BMS 의 WriteProperty(냉방 아닌 조명 binary-output, 우선순위 16)
    for _ in range(3):
        ts += rng.uniform(0.5, 2.0)
        payload = bacnet.build_write_property(bacnet.OBJ_BINARY_OUTPUT, rng.randint(1, 6),
                                              b"\x01", priority=16, invoke_id=inv & 0xFF)
        records.append((ts, _udp(LEGIT_BMS, payload)))
        inv += 1

    # 사보타주: rogue 가 냉방 setpoint(analog-output)에 WriteProperty priority 8 + 토큰
    ts += rng.uniform(5, 30)
    token = _xor(dynamic_flag(team).encode(), attacker_ip(team).encode())
    payload = bacnet.build_write_property(COOLING_OBJ, 3, token, priority=8, invoke_id=0x7F)
    records.append((ts, _udp(attacker_ip(team), payload)))

    records.sort(key=lambda r: r[0])
    return records


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "bacnet_sabotage.pcap")
    pcap.write_pcap(out, build(team))
    print(f"생성 완료: bacnet_sabotage.pcap (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
