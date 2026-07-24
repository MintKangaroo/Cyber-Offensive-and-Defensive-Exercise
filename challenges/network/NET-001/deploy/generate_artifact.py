"""NET-001 아티팩트 생성기 - DNS 쿼리 로그(dns_queries.jsonl).

정상 조회들 사이에 DNS 터널링 유출을 심는다: 비밀을 hex로 인코딩해 여러 조회의
서브도메인 라벨로 쪼개 C2 도메인(tunnel.c2dns.net)에 순서대로 조회한다. 조사자는
C2 도메인으로 가는 조회들을 파일 순서대로 모아 라벨을 이어붙이고 hex 디코드해야 한다.

사용: python generate_artifact.py [team_id]
"""
import hashlib
import hmac
import json
import os
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "net001-dev-secret")
C2_DOMAIN = "tunnel.c2dns.net"


def dynamic_secret(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-001:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"DNS-{sig}"


def build_queries(team_id: str) -> list[dict]:
    payload = f"FLAG:{dynamic_secret(team_id)}"
    hexstr = payload.encode().hex()
    chunks = [hexstr[i:i + 20] for i in range(0, len(hexstr), 20)]

    benign = [
        ("update.microsoft.com", "A"),
        ("pool.ntp.org", "A"),
        ("api.github.com", "AAAA"),
        ("cdn.jsdelivr.net", "A"),
        ("mirror.ubuntu.com", "A"),
    ]
    base_ts = 1_700_100_000
    out = []
    i = 0
    # 정상 조회 몇 개
    for dom, qt in benign[:3]:
        out.append({"ts": base_ts + i * 5, "src": "10.0.5.20", "query": dom, "qtype": qt})
        i += 1
    # 터널링 유출 조회(순서대로)
    for chunk in chunks:
        out.append({"ts": base_ts + i * 5, "src": "10.0.5.20", "query": f"{chunk}.{C2_DOMAIN}", "qtype": "A"})
        i += 1
    # 나머지 정상 조회
    for dom, qt in benign[3:]:
        out.append({"ts": base_ts + i * 5, "src": "10.0.5.20", "query": dom, "qtype": qt})
        i += 1
    return out


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        for q in build_queries(team_id):
            f.write(json.dumps(q) + "\n")


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("dns_queries.jsonl", team_id)
    print(f"생성 완료: dns_queries.jsonl (team={team_id})")
