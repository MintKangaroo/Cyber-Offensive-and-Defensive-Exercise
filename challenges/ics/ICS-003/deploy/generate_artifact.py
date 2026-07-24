"""
ICS-003 배포 생성기 - DNP3 트래픽 로그(dnp3_log.jsonl) 합성.

정상 마스터(10.30.0.4)의 READ(func 1) 폴링 사이에, 무단 마스터가 보호 제어점(차단기 CB, index 7)에
DIRECT_OPERATE(func 5, TCC=LATCH_ON) 제어를 내린 사보타주 1건이 숨어 있다.
팀별로 공격자 IP/토큰/flag가 HMAC 결정. note(base64) 토큰을 공격자 IP로 XOR 복호하면 flag.
"""
import base64
import hashlib
import hmac
import json
import os
import random
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ics003-dev-secret")
LEGIT_MASTER = "10.30.0.4"
CB_POINT = 7          # 보호 제어점(차단기)
OPERATE_FUNCS = {4, 5}  # OPERATE / DIRECT_OPERATE


def _hmac(tag, team, n): return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]
def dynamic_flag(team): return f"flag{{dnp3_unsolicited_control_{_hmac('ICS-003', team, 12)}}}"
def attacker_ip(team): return f"10.30.0.{int(_hmac('ICS-003-ip', team, 4), 16) % 200 + 30}"
def _xor(d, k): return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))
def token_b64(team): return base64.b64encode(_xor(dynamic_flag(team).encode(), attacker_ip(team).encode())).decode()


def build(team):
    rng = random.Random(int(_hmac("ICS-003-seed", team, 8), 16))
    rows = []
    ts = 1_700_000_000.0
    for _ in range(60):
        ts += rng.uniform(0.5, 2.0)
        rows.append({"ts": round(ts, 3), "src": LEGIT_MASTER, "dst": "10.30.0.20",
                     "func": 1, "obj": "Class 0 poll", "point": rng.choice([1, 2, 3, 4]), "note": ""})
    # 사보타주: rogue 마스터가 CB에 DIRECT_OPERATE(LATCH_ON)
    rows.append({"ts": round(ts + rng.uniform(5, 30), 3), "src": attacker_ip(team), "dst": "10.30.0.20",
                 "func": 5, "obj": "CROB", "point": CB_POINT, "tcc": "LATCH_ON", "note": token_b64(team)})
    # 미끼: 정상 마스터의 OPERATE(보호점 아님)
    for _ in range(3):
        ts += rng.uniform(0.5, 2.0)
        rows.append({"ts": round(ts, 3), "src": LEGIT_MASTER, "dst": "10.30.0.20",
                     "func": 5, "obj": "CROB", "point": rng.choice([11, 12]), "tcc": "PULSE_ON", "note": ""})
    rng.shuffle(rows)
    return rows


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "dnp3_log.jsonl")
    with open(out, "w") as f:
        for r in build(team):
            f.write(json.dumps(r) + "\n")
    print(f"생성 완료: dnp3_log.jsonl (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
