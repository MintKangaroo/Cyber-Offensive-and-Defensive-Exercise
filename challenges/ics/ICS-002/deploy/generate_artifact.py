"""
ICS-002 배포 생성기 - Modbus/TCP 트래픽 로그(modbus_traffic.jsonl) 합성.

정상 HMI(10.20.0.5)의 읽기(func 3) 트래픽 사이에, 무단 마스터(rogue)가 안전 레지스터
(40001)에 쓰기(func 6)를 수행한 사보타주 1건이 숨어 있다. 팀별로 공격자 IP/토큰/flag가 HMAC 결정.
분석: 안전 레지스터에 대한 write를 정상 HMI가 아닌 출발지에서 찾고, note(base64) 토큰을
공격자 IP로 XOR 복호하면 flag.
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
HMI_IP = "10.20.0.5"
SAFETY_ADDR = 40001


def _hmac(tag, team, n): return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]
def dynamic_flag(team): return f"flag{{modbus_sabotage_{_hmac('ICS-002', team, 12)}}}"
def attacker_ip(team): return f"10.20.0.{int(_hmac('ICS-002-ip', team, 4), 16) % 200 + 30}"
def _xor(d, k): return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))
def token_b64(team): return base64.b64encode(_xor(dynamic_flag(team).encode(), attacker_ip(team).encode())).decode()


def build(team):
    rng = random.Random(int(_hmac("ICS-002-seed", team, 8), 16))
    rows = []
    ts = 1_700_000_000.0
    read_addrs = [40002, 40003, 40010, 40011]
    for _ in range(60):
        ts += rng.uniform(0.5, 2.0)
        rows.append({"ts": round(ts, 3), "src": HMI_IP, "dst": "10.20.0.10", "unit_id": 1,
                     "func": 3, "addr": rng.choice(read_addrs), "qty": 1, "note": ""})
    # 사보타주: rogue 마스터가 안전 레지스터에 write(func 6)
    t = ts * 1 + rng.uniform(5, 30)
    rows.append({"ts": round(ts + rng.uniform(5, 30), 3), "src": attacker_ip(team), "dst": "10.20.0.10",
                 "unit_id": 1, "func": 6, "addr": SAFETY_ADDR, "value": 0, "note": token_b64(team)})
    # 미끼: 정상 HMI의 write(안전 아닌 레지스터)
    for _ in range(4):
        ts += rng.uniform(0.5, 2.0)
        rows.append({"ts": round(ts, 3), "src": HMI_IP, "dst": "10.20.0.10", "unit_id": 1,
                     "func": 6, "addr": rng.choice([40020, 40021]), "value": rng.randint(1, 100), "note": ""})
    rng.shuffle(rows)
    return rows


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "modbus_traffic.jsonl")
    with open(out, "w") as f:
        for r in build(team):
            f.write(json.dumps(r) + "\n")
    print(f"생성 완료: modbus_traffic.jsonl (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
