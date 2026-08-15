"""
NET-007 배포 생성기 - 넷플로우 로그(netflow.jsonl) 합성. 다중 홉 피벗 체인 은닉.

공격자가 진입호스트에서 내부 여러 홉을 거쳐 DC로 피벗한다(A→B→C→DC). 각 홉은 유입/유출
플로우가 **바이트 크기 보존 + 근접 시각(ms)** 으로 상관된다. 여기에 무관한 정상 플로우와
미끼(부분적으로만 상관되는) 플로우를 섞어, 단순 필터가 아니라 홉 그래프 상관으로만 체인을
복원할 수 있게 한다. 최종 홉 플로우의 note(base64)에 토큰이 실려 있고, 진입 IP로 XOR하면 flag.

팀별로 진입 IP/체인 경로/토큰/flag가 HMAC으로 결정된다.
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

INTERNAL = ["10.4.1.11", "10.4.1.23", "10.4.2.7", "10.4.2.39", "10.4.3.5", "10.4.3.88"]
DC = "10.4.0.10"


def _hmac(tag: str, team_id: str, n: int) -> str:
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team_id}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team_id: str) -> str:
    return f"flag{{pivot_chain_{_hmac('NET-007', team_id, 12)}}}"


def entry_ip(team_id: str) -> str:
    # 외부 진입 IP(203.0.113.x 대역)
    octet = int(_hmac("NET-007-entry", team_id, 4), 16) % 200 + 20
    return f"203.0.113.{octet}"


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def final_token_b64(team_id: str) -> str:
    flag = dynamic_flag(team_id).encode()
    token = _xor(flag, entry_ip(team_id).encode())
    return base64.b64encode(token).decode()


def build(team_id: str):
    rng = random.Random(int(_hmac("NET-007-seed", team_id, 8), 16))
    # 팀별 체인 경로: 내부 호스트 3개를 골라 A->B->C->DC
    hops = rng.sample(INTERNAL, 3)
    chain = [entry_ip(team_id)] + hops + [DC]

    flows = []
    ts = 1_700_000_000.0
    # 배경 정상 트래픽(무관)
    for _ in range(40):
        s = rng.choice(INTERNAL); d = rng.choice(INTERNAL)
        if s == d:
            continue
        flows.append({"ts": round(ts + rng.uniform(0, 600), 3), "src": s, "dst": d,
                      "dport": rng.choice([445, 3389, 80, 443, 53]),
                      "bytes": rng.randint(500, 4000), "note": ""})

    # 피벗 체인: 각 홉 바이트 보존 + ms 근접(상관). 홉마다 payload 크기 동일.
    payload = rng.randint(9000, 12000)
    t = ts + 300.0
    for i in range(len(chain) - 1):
        s, d = chain[i], chain[i + 1]
        t += rng.uniform(0.02, 0.09)   # 다음 홉은 수십 ms 뒤
        last = (i == len(chain) - 2)
        flows.append({
            "ts": round(t, 3), "src": s, "dst": d,
            "dport": 445,
            "bytes": payload + rng.randint(-40, 40),   # 거의 보존(±작은 오버헤드)
            "note": final_token_b64(team_id) if last else "",
        })

    # 미끼: 체인과 바이트는 비슷하나 시각이 크게 벌어져 상관 안 되는 플로우
    for _ in range(6):
        s = rng.choice(INTERNAL); d = rng.choice(INTERNAL + [DC])
        if s == d:
            continue
        flows.append({"ts": round(ts + rng.uniform(0, 600), 3), "src": s, "dst": d,
                      "dport": 445, "bytes": payload + rng.randint(-40, 40), "note": ""})

    rng.shuffle(flows)
    return flows, chain


def main():
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    flows, chain = build(team_id)
    out = os.path.join(os.path.dirname(__file__), "netflow.jsonl")
    with open(out, "w") as f:
        for fl in flows:
            f.write(json.dumps(fl) + "\n")
    print(f"생성 완료: netflow.jsonl (team={team_id}, chain={' -> '.join(chain)})")


if __name__ == "__main__":
    main()
