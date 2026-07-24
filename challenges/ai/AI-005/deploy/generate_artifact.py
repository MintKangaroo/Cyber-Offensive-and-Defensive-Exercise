"""AI-005 아티팩트 생성기 - 모델 추론 API 접근 로그(api_log.jsonl).

정상 클라이언트들은 소량의 쿼리만 보내지만, 한 클라이언트가 짧은 시간에 대량의 서로 다른
쿼리를 보내 대리모델 학습용 입출력을 긁어간다(모델 추출/스틸링). 그 남용 클라이언트의
api_key는 팀별 동적. 조사자는 남용 클라이언트와 그 키, 쿼리 수를 찾아야 한다.
"""
import hashlib
import hmac
import json
import os
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ai005-dev-secret")
ABUSER_CLIENT = "client_zeta"
ABUSE_COUNT = 60


def dynamic_key(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"AI-005:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"sk-{sig}"


def build_log(team_id: str) -> list[dict]:
    abuser_key = dynamic_key(team_id)
    t0 = 1_700_600_000
    rows = []
    # 정상 클라이언트들: 소량
    normal = [("client_alpha", "sk-normal-a", 4), ("client_beta", "sk-normal-b", 6),
              ("client_gamma", "sk-normal-c", 3)]
    i = 0
    for cid, key, n in normal:
        for _ in range(n):
            rows.append({"ts": t0 + i, "client_id": cid, "api_key": key,
                         "query_hash": hashlib.md5(f"{cid}{i}".encode()).hexdigest()[:8]})
            i += 1
    # 남용 클라이언트: 대량의 서로 다른 쿼리(모델 추출)
    for j in range(ABUSE_COUNT):
        rows.append({"ts": t0 + i, "client_id": ABUSER_CLIENT, "api_key": abuser_key,
                     "query_hash": hashlib.md5(f"abuse{j}".encode()).hexdigest()[:8]})
        i += 1
    rows.sort(key=lambda r: r["ts"])
    return rows


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        for r in build_log(team_id):
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("api_log.jsonl", team_id)
    print(f"생성 완료: api_log.jsonl (team={team_id})")
