"""ICS-010 배포 생성기 - EtherNet/IP CIP 무단 제어 분석 - Safety Assembly Tamper 합성 트래픽 로그.

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

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
LEGIT = "10.80.0.5"


def _hmac(tag, team, n): return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]
def dynamic_flag(team): return f"flag{{ethernetip_cip_safety_tamper_{_hmac('ICS-010', team, 12)}}}"
def attacker_ip(team): return f"10.80.0.{int(_hmac('ICS-010-ip', team, 4), 16) % 200 + 30}"
def _xor(d, k): return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))
def token_b64(team): return base64.b64encode(_xor(dynamic_flag(team).encode(), attacker_ip(team).encode())).decode()


def build(team):
    rng = random.Random(int(_hmac("ICS-010-seed", team, 8), 16))
    rows = []
    ts = 1_700_000_000.0
    for _ in range(58):
        ts += rng.uniform(0.1, 0.6)
        rows.append({"ts": round(ts, 3), "src": LEGIT, "dst": "10.80.0.20",
                     "cip_service": 0x0e, "cip_service_name": "GetAttributeSingle",
                     "cip_class": rng.choice([0x04, 0x6b, 0x01]), "cip_instance": rng.randint(1, 120),
                     "attribute": 3, "op": "read", "note": ""})
    # 사보타주
    rows.append({"ts": round(ts + rng.uniform(2, 15), 3), "src": attacker_ip(team), "dst": "10.80.0.20",
                 "cip_service": 0x10, "cip_service_name": "SetAttributeSingle",
                 "cip_class": 0x04, "cip_instance": 101, "attribute": 3, "op": "write",
                 "note": token_b64(team)})
    # 미끼(정상 출발지의 유사 요청)
    for _ in range(3):
        ts += rng.uniform(0.2, 0.8)
        rows.append({"ts": round(ts, 3), "src": LEGIT, "dst": "10.80.0.20",
                     "cip_service": 0x10, "cip_service_name": "SetAttributeSingle",
                     "cip_class": 0x04, "cip_instance": rng.choice([150, 151]), "attribute": 3,
                     "op": "write", "note": ""})
    rng.shuffle(rows)
    return rows


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "enip_traffic.jsonl")
    with open(out, "w") as f:
        for r in build(team):
            f.write(json.dumps(r) + "\n")
    print(f"생성 완료: enip_traffic.jsonl (team={team}, attacker={attacker_ip(team)})")


if __name__ == "__main__":
    main()
