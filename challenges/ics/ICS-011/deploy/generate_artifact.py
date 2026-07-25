"""ICS-011 배포 생성기 - S7comm 안전 DB 무단 쓰기 분석 - Safety DB Write 합성 트래픽 로그.

팀별 공격자 IP/토큰/flag가 HMAC 결정. 탐지: 판별자 부합하는 무단(정상 출발지 아님) 프레임.
note(base64) 토큰을 공격자 IP로 XOR 복호하면 flag.
"""
import base64
import hashlib
import hmac
import json
import os
import random
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ics-011-dev-secret")
LEGIT = "10.85.0.5"


def _hmac(tag, team, n): return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]
def dynamic_flag(team): return f"flag{{s7comm_safety_db_write_{_hmac('ICS-011', team, 12)}}}"
def attacker_ip(team): return f"10.85.0.{int(_hmac('ICS-011-ip', team, 4), 16) % 200 + 30}"
def _xor(d, k): return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))
def token_b64(team): return base64.b64encode(_xor(dynamic_flag(team).encode(), attacker_ip(team).encode())).decode()


def build(team):
    rng = random.Random(int(_hmac("ICS-011-seed", team, 8), 16))
    rows = []
    ts = 1_700_000_000.0
    for _ in range(58):
        ts += rng.uniform(0.1, 0.6)
        rows.append({"ts": round(ts, 3), "src": LEGIT, "dst": "10.85.0.10",
                     "s7_function": "READ_VAR", "area": "DB",
                     "db_number": rng.choice([1, 10, 20, 62]), "op": "read", "note": ""})
    # 사보타주
    rows.append({"ts": round(ts + rng.uniform(2, 15), 3), "src": attacker_ip(team), "dst": "10.85.0.10",
                 "s7_function": "WRITE_VAR", "area": "DB", "db_number": 62, "op": "write",
                 "note": token_b64(team)})
    # 미끼(정상 출발지의 유사 요청)
    for _ in range(3):
        ts += rng.uniform(0.2, 0.8)
        rows.append({"ts": round(ts, 3), "src": LEGIT, "dst": "10.85.0.10",
                     "s7_function": "WRITE_VAR", "area": "DB", "db_number": rng.choice([10, 20]),
                     "op": "write", "note": ""})
    rng.shuffle(rows)
    return rows


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "s7_traffic.jsonl")
    with open(out, "w") as f:
        for r in build(team):
            f.write(json.dumps(r) + "\n")
    print(f"생성 완료: s7_traffic.jsonl (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
