"""
ICS-009 배포 생성기 — 실 Foundation Fieldbus H1 사보타주 캡처(.pcap) 합성.
==========================================================================
목업 JSON 로그가 아니라 **실 FF-H1 DLPDU 바이트**를 담은 pcap 을 만든다. FF-H1 은 시리얼
필드버스라 IP 가 아니고 Wireshark 네이티브 디섹션 대상이 아니므로, DLPDU 를 사설 EtherType
(0x88FF) 로 합성 캡슐화한다. DLPDU 구조(FC/dest/src/DLSDU)는 `shared/ics/ff_h1.py` 실 인코더로
만든다.

시나리오: 정상 LAS/DCS(노드 0x10/0x11)의 주기적 파라미터 read 사이에, 무단 호스트(rogue, 팀별
노드주소)가 안전 관련 PID 블록(FIC-201)의 MODE_BLK.TARGET 을 O/S(Out-of-Service)로 write 해
제어를 무력화한 사보타주가 숨어 있다. 그 write DLSDU 에 토큰(= flag ⊕ 공격자 주소)이 실려 있다.
분석: PID 블록에 MODE_BLK O/S write 를 낸 정상 아닌 노드주소를 찾아 공격자 주소를 식별하고,
토큰을 공격자 주소로 반복 XOR 복호하면 flag.

팀별 공격자 주소·flag·타이밍이 HMAC 결정. 모든 값은 합성 더미(실장비/실호스트 무관).
"""
import hashlib
import hmac
import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))  # repo 루트(shared 임포트)

from shared.ics import ff_h1
from shared.net import pcap

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")

LEGIT_ADDRS = {"0x10", "0x11"}
PID_BLOCK = "FIC-201"
BLOCKS = ["AI-101", "AI-102", "PID-301", "AO-401", "FIC-201"]
PARAMS = ["PV", "OUT", "SP", "PV_SCALE"]
_MAC_A = pcap.MAC_A
_MAC_B = pcap.MAC_B


def _hmac(tag, team, n):
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team):
    return f"flag{{ff_mode_blk_oos_sabotage_{_hmac('ICS-009', team, 12)}}}"


def attacker_addr(team):
    return "0x%02x" % (int(_hmac("ICS-009-addr", team, 4), 16) % 200 + 32)


def _xor(d, k):
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))


def _frame(fc, dest, src_addr_int, dlsdu):
    return pcap.ethernet(_MAC_A, _MAC_B, ff_h1.FF_ETHERTYPE,
                         ff_h1.build_dlpdu(fc, dest, src_addr_int, dlsdu))


def build(team) -> list:
    rng = random.Random(int(_hmac("ICS-009-seed", team, 8), 16))
    ts = 1_700_000_000.0
    records = []
    for _ in range(60):
        ts += rng.uniform(0.1, 0.6)
        src = rng.choice([0x10, 0x11])
        fc = ff_h1.FC_CD if src == 0x10 else ff_h1.FC_DT
        dlsdu = ff_h1.build_dlsdu(ff_h1.OP_READ, rng.choice(BLOCKS), rng.choice(PARAMS),
                                  "%.2f" % rng.uniform(10, 90))
        records.append((ts, _frame(fc, rng.randint(0x20, 0x28), src, dlsdu)))
    # 미끼: 정상 DCS 의 SP write(MODE_BLK 아님)
    for _ in range(3):
        ts += rng.uniform(0.2, 0.8)
        dlsdu = ff_h1.build_dlsdu(ff_h1.OP_WRITE, rng.choice(["PID-301", "AO-401"]), "SP",
                                  "%.2f" % rng.uniform(20, 80))
        records.append((ts, _frame(ff_h1.FC_DT, 0x24, 0x11, dlsdu)))

    # 사보타주: rogue 가 PID 블록에 MODE_BLK.TARGET = O/S write + 토큰
    ts += rng.uniform(2, 15)
    token = _xor(dynamic_flag(team).encode(), attacker_addr(team).encode())
    dlsdu = ff_h1.build_dlsdu(ff_h1.OP_WRITE, PID_BLOCK, "MODE_BLK", "OOS", token)
    records.append((ts, _frame(ff_h1.FC_DT, 0x24, int(attacker_addr(team), 16), dlsdu)))

    records.sort(key=lambda r: r[0])
    return records


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "ff_h1_sabotage.pcap")
    pcap.write_pcap(out, build(team))
    print(f"생성 완료: ff_h1_sabotage.pcap (team={team}, attacker={attacker_addr(team)})")


if __name__ == "__main__":
    main()
