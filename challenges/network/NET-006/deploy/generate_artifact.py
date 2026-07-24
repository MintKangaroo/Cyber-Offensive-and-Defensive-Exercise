"""NET-006 아티팩트 생성기 - TCP 세그먼트 로그(tcp_segments.jsonl).

공격자 흐름(한 src->dst)의 유출 페이로드가 여러 TCP 세그먼트로 쪼개져 있고, 파일에는
순서가 섞여 저장돼 있다. 각 세그먼트는 seq와 base64 청크를 갖는다. 정상 흐름들도 섞여 있다.
조사자는 공격자 흐름을 골라 seq 순으로 재조립·디코드해야 한다.
"""
import base64
import hashlib
import hmac
import json
import os
import random
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "net006-dev-secret")
ATTACKER_IP = "10.9.9.9"
C2_IP = "203.0.113.7"


def dynamic_secret(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-006:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"SEC-{sig}"


def build_segments(team_id: str) -> list[dict]:
    payload = f"SECRET:{dynamic_secret(team_id)}".encode()
    chunk = 6
    rows = []
    seq = 1000
    for i in range(0, len(payload), chunk):
        part = payload[i:i + chunk]
        rows.append({
            "src_ip": ATTACKER_IP, "dst_ip": C2_IP, "seq": seq,
            "payload_b64": base64.b64encode(part).decode(),
        })
        seq += len(part)
    # 정상 흐름 세그먼트(다른 흐름)
    for i, (s, d) in enumerate([("10.0.3.5", "93.184.216.34"), ("10.0.3.6", "1.1.1.1")]):
        rows.append({"src_ip": s, "dst_ip": d, "seq": 500 + i * 10,
                     "payload_b64": base64.b64encode(b"GET / HTTP/1.1").decode()})
    random.Random(99).shuffle(rows)   # 순서 섞기
    return rows


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        for r in build_segments(team_id):
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("tcp_segments.jsonl", team_id)
    print(f"생성 완료: tcp_segments.jsonl (team={team_id})")
