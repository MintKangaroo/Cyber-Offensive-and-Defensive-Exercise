"""
ICS-006 배포 생성기 - IEC 61850 GOOSE 메시지 로그(goose_messages.jsonl) 합성.

정상 보호 IED(MAC 00:21:c1:aa:bb:cc)의 GOOSE 발행(단조 sqNum) 사이에, 무단 발행자가 같은
보호 gocbRef로 비정상적으로 높은 stNum과 함께 CB_Trip=true를 주입한 GOOSE 스푸핑이 숨어 있다.
팀별 rogue MAC/토큰/flag가 HMAC 결정. 탐지: 보호 gocbRef의 트립 GOOSE를 정상 IED가 아닌
출발지가 발행 → 그 MAC이 공격자. note(base64) 토큰을 rogue MAC으로 XOR 복호하면 flag.
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
LEGIT_IED_MAC = "00:21:c1:aa:bb:cc"
TRIP_GCB = "IED1/LLN0$GO$gcbTrip"


def _hmac(tag, team, n): return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]
def dynamic_flag(team): return f"flag{{iec61850_goose_spoof_{_hmac('ICS-006', team, 12)}}}"


def attacker_mac(team):
    h = _hmac("ICS-006-mac", team, 6)
    return "de:ad:" + ":".join(h[i:i+2] for i in range(0, 8, 2))


def _xor(d, k): return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))
def token_b64(team): return base64.b64encode(_xor(dynamic_flag(team).encode(), attacker_mac(team).encode())).decode()


def build(team):
    rng = random.Random(int(_hmac("ICS-006-seed", team, 8), 16))
    rows = []
    ts = 1_700_000_000.0
    sq = 100
    st = 1
    for _ in range(50):
        ts += rng.uniform(0.2, 1.0)
        sq += 1
        rows.append({"ts": round(ts, 3), "src_mac": LEGIT_IED_MAC, "gocbRef": TRIP_GCB,
                     "stNum": st, "sqNum": sq, "dataset": "CB_Trip:false", "note": ""})
    # 스푸핑: rogue MAC이 높은 stNum으로 트립 GOOSE 주입
    rows.append({"ts": round(ts + rng.uniform(1, 5), 3), "src_mac": attacker_mac(team),
                 "gocbRef": TRIP_GCB, "stNum": st + 5000, "sqNum": 0,
                 "dataset": "CB_Trip:true", "note": token_b64(team)})
    rng.shuffle(rows)
    return rows


def main():
    team = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    out = os.path.join(os.path.dirname(__file__), "goose_messages.jsonl")
    with open(out, "w") as f:
        for r in build(team):
            f.write(json.dumps(r) + "\n")
    print(f"생성 완료: goose_messages.jsonl (team={team}, attacker_mac={attacker_mac(team)})")


if __name__ == "__main__":
    main()
