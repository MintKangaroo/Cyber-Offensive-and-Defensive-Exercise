"""
ICS-009 배포 생성기 - Foundation Fieldbus H1 트래픽 로그(ff_h1_traffic.jsonl) 합성.

정상 LAS(Link Active Scheduler, addr 0x10)의 주기적 CD(Compel Data) 스케줄 사이에, 무단
호스트가 안전 관련 PID 제어 블록(FIC-201)에 MODE_BLK.TARGET=O/S(Out of Service) write SPDU를
주입해 제어 루프를 정지(사보타주)시켰다. 팀별 공격자 링크주소/토큰/flag가 HMAC 결정.
탐지: block=FIC-201(PID)에 param=MODE_BLK, value=OOS write를 정상 LAS/DCS(0x10/0x11)가 아닌
링크주소에서 찾음. note(base64) 토큰을 공격자 링크주소(hex 문자열)로 XOR 복호하면 flag.
"""
import base64
import hashlib
import hmac
import json
import os
import random
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
LEGIT_ADDRS = {"0x10", "0x11"}   # LAS, DCS 브리지
PID_BLOCK = "FIC-201"            # 안전 관련 PID 제어 블록


def _hmac(tag, team, n): return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]
def dynamic_flag(team): return f"flag{{ff_mode_blk_oos_sabotage_{_hmac('ICS-009', team, 12)}}}"
def attacker_addr(team): return "0x%02x" % (int(_hmac('ICS-009-addr', team, 4), 16) % 200 + 32)
def _xor(d, k): return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))
def token_b64(team): return base64.b64encode(_xor(dynamic_flag(team).encode(), attacker_addr(team).encode())).decode()


def build(team):
    rng = random.Random(int(_hmac("ICS-009-seed", team, 8), 16))
    rows = []
    ts = 1_700_000_000.0
    blocks = ["AI-101", "AI-102", "PID-301", "AO-401", "FIC-201"]
    params = ["PV", "OUT", "SP", "PV_SCALE"]
    # 정상 LAS 스케줄 CD + DCS의 파라미터 read(주기적 매크로사이클)
    for _ in range(60):
        ts += rng.uniform(0.1, 0.6)
        src = rng.choice(["0x10", "0x11"])
        rows.append({"ts": round(ts, 3), "src_addr": src, "dst_addr": "0x%02x" % rng.randint(0x20, 0x28),
                     "ff_pdu": "CD" if src == "0x10" else "DT",
                     "block": rng.choice(blocks), "param": rng.choice(params),
                     "op": "read", "value": round(rng.uniform(10, 90), 2), "note": ""})
    # 사보타주: rogue 호스트가 PID 블록에 MODE_BLK.TARGET = O/S write
    rows.append({"ts": round(ts + rng.uniform(2, 15), 3), "src_addr": attacker_addr(team),
                 "dst_addr": "0x24", "ff_pdu": "DT", "block": PID_BLOCK,
                 "param": "MODE_BLK", "op": "write", "value": "OOS", "note": token_b64(team)})
    # 미끼: 정상 DCS의 SP write(MODE_BLK 아님, 정상 주소)
    for _ in range(3):
        ts += rng.uniform(0.2, 0.8)
        rows.append({"ts": round(ts, 3), "src_addr": "0x11", "dst_addr": "0x24",
                     "ff_pdu": "DT", "block": rng.choice(["PID-301", "AO-401"]),
                     "param": "SP", "op": "write", "value": round(rng.uniform(20, 80), 2), "note": ""})
    rng.shuffle(rows)
    return rows


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "ff_h1_traffic.jsonl")
    with open(out, "w") as f:
        for r in build(team):
            f.write(json.dumps(r) + "\n")
    print(f"생성 완료: ff_h1_traffic.jsonl (team={team}, attacker={attacker_addr(team)})")


if __name__ == "__main__":
    main()
