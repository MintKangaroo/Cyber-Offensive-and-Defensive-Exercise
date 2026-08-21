"""
ICS-007 배포 생성기 — 실 HART-IP 사보타주 캡처(.pcap) 합성.
===========================================================
목업 JSON 로그가 아니라 **진짜 HART-IP 트래픽**을 담은 pcap 을 만든다. Wireshark 가 포트 5094
를 HART-IP 로 디섹션한다. 프레임은 플랫폼 트윈과 동일한 `shared/ics/hart.py` 실 인코더
(HART-IP 헤더 + HART short-frame PDU + XOR 체크섬)로 만든다.

시나리오: 정상 자산관리시스템(AMS, 10.60.0.5)의 읽기(cmd 1/3) 사이에, 무단 마스터(rogue,
팀별 IP)가 안전 트랜스미터(PT-101 = polling address 1)에 범위 재설정 쓰기(cmd 35)를 내려
계측값을 스푸핑한 사보타주가 숨어 있다. cmd 35 의 HART 데이터 바이트가 토큰(= flag ⊕ 공격자
IP)이다. 분석: 안전 트랜스미터에 write 명령(cmd 34/35/45/46)을 내린 정상 아닌 출발지를 찾아
공격자 IP 를 식별하고, HART 명령 데이터를 공격자 IP 로 반복 XOR 복호하면 flag.

팀별 공격자 IP·flag·타이밍이 HMAC 결정. 모든 값은 합성 더미(실장비/실호스트 무관).
"""
import hashlib
import hmac
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))  # repo 루트(shared 임포트)

from shared.ics import hart
from shared.net import pcap

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

LEGIT_AMS = "10.60.0.5"
GATEWAY_IP = "10.60.0.20"
HART_PORT = 5094
SAFETY_ADDR = 1        # PT-101 (polling address)
OTHER_ADDRS = [2, 3, 4]


def _hmac(tag, team, n):
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team):
    return f"flag{{hart_command_injection_{_hmac('ICS-007', team, 12)}}}"


def attacker_ip(team):
    return f"10.60.0.{int(_hmac('ICS-007-ip', team, 4), 16) % 200 + 30}"


def _xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


def _write_command(addr, cmd, data, seq):
    pdu = hart.build_hart_pdu(hart.DELIM_STX, addr, cmd, data)
    return hart.build_hart_ip_header(hart.MSG_TYPE_REQUEST, hart.MSG_ID_TOKEN_PDU, seq, 8 + len(pdu)) + pdu


def build(team) -> list:
    rng = random.Random(int(_hmac("ICS-007-seed", team, 8), 16))
    ts = 1_700_000_000.0

    ams = pcap.TCPSession(LEGIT_AMS, GATEWAY_IP, HART_PORT, client_port=41000)
    ams.handshake(ts)
    ams.client_msg(ts + 0.01, hart.build_session_init())
    seq = 1
    for _ in range(55):
        ts += rng.uniform(0.5, 2.0)
        ams.client_msg(ts, hart.build_read_command(rng.choice([1, 3]), seq=seq,
                                                   polling_address=rng.choice(OTHER_ADDRS + [SAFETY_ADDR])))
        seq += 1
    # 미끼: 정상 AMS 의 write(안전 트랜스미터 아님)
    for _ in range(3):
        ts += rng.uniform(0.5, 2.0)
        ams.client_msg(ts, _write_command(rng.choice(OTHER_ADDRS), 34, b"\x00\x01\x02", seq))
        seq += 1

    # 사보타주: rogue 가 안전 트랜스미터(addr 1)에 cmd 35 (범위 쓰기, 토큰 페이로드)
    rogue = pcap.TCPSession(attacker_ip(team), GATEWAY_IP, HART_PORT, client_port=42000)
    t_atk = 1_700_000_000.0 + rng.uniform(20, 90)
    rogue.handshake(t_atk)
    rogue.client_msg(t_atk + 0.02, hart.build_session_init())
    token = _xor(dynamic_flag(team).encode(), attacker_ip(team).encode())
    rogue.client_msg(t_atk + 0.1, _write_command(SAFETY_ADDR, 35, token, 1))

    records = ams.records + rogue.records
    records.sort(key=lambda r: r[0])
    return records


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "hart_sabotage.pcap")
    pcap.write_pcap(out, build(team))
    print(f"생성 완료: hart_sabotage.pcap (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
