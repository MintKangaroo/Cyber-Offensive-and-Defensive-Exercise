"""
ICS-002 배포 생성기 — 실 Modbus/TCP 사보타주 캡처(.pcap) 합성.
================================================================
목업 JSON 로그가 아니라 **진짜 Modbus/TCP 트래픽**을 담은 pcap 을 만든다. Wireshark·tcpdump
가 Modbus 를 그대로 디섹션한다(TCP 포트 502). 프로토콜 프레임은 플랫폼 트윈과 동일한
`shared/ics/modbus.py` 실 인코더로 만든다.

시나리오: 정상 HMI(10.20.0.5)가 홀딩 레지스터를 주기적으로 FC3 읽기 하는 사이, 무단 마스터
(rogue, 팀별 IP)가 **안전 레지스터(40001 = 프로토콜 주소 0)** 에 FC16(다중 쓰기)로 페이로드를
써넣는 사보타주 1건이 숨어 있다. 그 페이로드 바이트가 flag 를 공격자 IP 로 XOR 한 토큰이다.
분석: 안전 레지스터에 대한 write 를 정상 HMI 가 아닌 출발지에서 찾아 공격자 IP 를 식별하고,
FC16 페이로드를 공격자 IP 로 반복 XOR 복호하면 flag.

팀별로 공격자 IP·flag·타이밍이 HMAC 결정. 모든 값은 합성 더미(실장비/실호스트 무관).
"""
import hashlib
import hmac
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))  # repo 루트(shared 임포트)

from shared.ics import modbus
from shared.net import pcap

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

HMI_IP = "10.20.0.5"
PLC_IP = "10.20.0.10"
MODBUS_PORT = 502
SAFETY_PADDR = 0        # 40001 = 안전 인터록 홀딩 레지스터(프로토콜 주소 0)
READ_PADDRS = [1, 2, 9, 10]     # 40002/40003/40010/40011
BENIGN_WRITE_PADDRS = [19, 20]  # 40020/40021 (정상 HMI 쓰기, 안전영역 아님)


def _hmac(tag, team, n):
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team):
    return f"flag{{modbus_sabotage_{_hmac('ICS-002', team, 12)}}}"


def attacker_ip(team):
    return f"10.20.0.{int(_hmac('ICS-002-ip', team, 4), 16) % 200 + 30}"


def _xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


def _token_registers(team):
    """flag ⊕ attacker_ip → 16bit 레지스터 값 목록(짝수 패딩)."""
    tok = _xor(dynamic_flag(team).encode(), attacker_ip(team).encode())
    if len(tok) % 2:
        tok += b"\x00"
    return [int.from_bytes(tok[i:i + 2], "big") for i in range(0, len(tok), 2)]


def build(team) -> list:
    rng = random.Random(int(_hmac("ICS-002-seed", team, 8), 16))
    ts = 1_700_000_000.0

    hmi = pcap.TCPSession(HMI_IP, PLC_IP, MODBUS_PORT, client_port=41000)
    hmi.handshake(ts)
    events = []   # (ts, session, kind, payload)

    # 정상 HMI: FC3 읽기 다수 + 안전영역 아닌 FC6 쓰기 몇
    for _ in range(60):
        ts += rng.uniform(0.5, 2.0)
        pdu = modbus.build_read_holding(rng.choice(READ_PADDRS), 1)
        events.append((ts, hmi, "c", modbus.mbap(pdu)))
        events.append((ts + 0.01, hmi, "s", modbus.mbap(
            modbus.handle_pdu(modbus.ModbusBank(holding=[rng.randint(1, 3000)] * 32), pdu))))
    for _ in range(4):
        ts += rng.uniform(0.5, 2.0)
        pdu = modbus.build_write_single(rng.choice(BENIGN_WRITE_PADDRS), rng.randint(1, 100))
        events.append((ts, hmi, "c", modbus.mbap(pdu)))
        events.append((ts + 0.01, hmi, "s", modbus.mbap(pdu[:5])))

    # 사보타주: rogue 마스터가 안전 레지스터에 FC16 다중 쓰기(토큰 페이로드)
    rogue = pcap.TCPSession(attacker_ip(team), PLC_IP, MODBUS_PORT, client_port=42000)
    t_atk = 1_700_000_000.0 + rng.uniform(20, 90)
    rogue.handshake(t_atk)
    regs = _token_registers(team)
    wpdu = modbus.build_write_multiple(SAFETY_PADDR, regs)
    events.append((t_atk + 0.1, rogue, "c", modbus.mbap(wpdu)))
    events.append((t_atk + 0.11, rogue, "s", modbus.mbap(wpdu[:5])))

    # 세션별 메시지를 순서대로 흘려보내되 전체는 ts 정렬
    for et, sess, kind, payload in sorted(events, key=lambda e: e[0]):
        (sess.client_msg if kind == "c" else sess.server_msg)(et, payload)

    records = hmi.records + rogue.records
    records.sort(key=lambda r: r[0])
    return records


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "modbus_sabotage.pcap")
    pcap.write_pcap(out, build(team))
    print(f"생성 완료: modbus_sabotage.pcap (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
