"""
ICS-007 배포 생성기 - HART-IP 트래픽 로그(hart_traffic.jsonl) 합성.

정상 자산관리시스템(AMS, 10.60.0.5)의 HART 읽기 명령(cmd 1/3) 사이에, 무단 마스터가 안전
트랜스미터(tag PT-101)에 범위 재설정 쓰기(cmd 35 Write Range) 또는 DAC 트림(cmd 45)을 내려
계측값을 스푸핑한 사보타주가 숨어 있다. 팀별 공격자 IP/토큰/flag가 HMAC 결정.
탐지: 안전 트랜스미터에 대한 write 명령(cmd 35/45/46/34)을 정상 AMS가 아닌 출발지에서 찾음.
note(base64) 토큰을 공격자 IP로 XOR 복호하면 flag.
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
LEGIT_AMS = "10.60.0.5"
SAFETY_TAG = "PT-101"
WRITE_CMDS = {34, 35, 45, 46}   # damping / range / DAC trim


def _hmac(tag, team, n): return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]
def dynamic_flag(team): return f"flag{{hart_command_injection_{_hmac('ICS-007', team, 12)}}}"
def attacker_ip(team): return f"10.60.0.{int(_hmac('ICS-007-ip', team, 4), 16) % 200 + 30}"
def _xor(d, k): return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))
def token_b64(team): return base64.b64encode(_xor(dynamic_flag(team).encode(), attacker_ip(team).encode())).decode()


def build(team):
    rng = random.Random(int(_hmac("ICS-007-seed", team, 8), 16))
    rows = []
    ts = 1_700_000_000.0
    tags = ["PT-101", "TT-201", "FT-301", "LT-401"]
    for _ in range(55):
        ts += rng.uniform(0.5, 2.0)
        rows.append({"ts": round(ts, 3), "src": LEGIT_AMS, "dst": "10.60.0.20",
                     "hart_cmd": rng.choice([1, 3]), "tag": rng.choice(tags),
                     "op": "read", "note": ""})
    # 사보타주: rogue 마스터가 안전 트랜스미터에 Write Range(cmd 35)
    rows.append({"ts": round(ts + rng.uniform(5, 30), 3), "src": attacker_ip(team), "dst": "10.60.0.20",
                 "hart_cmd": 35, "tag": SAFETY_TAG, "op": "write", "note": token_b64(team)})
    # 미끼: 정상 AMS의 write(안전 트랜스미터 아님)
    for _ in range(3):
        ts += rng.uniform(0.5, 2.0)
        rows.append({"ts": round(ts, 3), "src": LEGIT_AMS, "dst": "10.60.0.20",
                     "hart_cmd": 34, "tag": rng.choice(["TT-201", "FT-301"]), "op": "write", "note": ""})
    rng.shuffle(rows)
    return rows


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "hart_traffic.jsonl")
    with open(out, "w") as f:
        for r in build(team):
            f.write(json.dumps(r) + "\n")
    print(f"생성 완료: hart_traffic.jsonl (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
