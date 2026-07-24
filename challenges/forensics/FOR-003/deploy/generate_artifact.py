"""FOR-003 아티팩트 생성기 - 세션 하이재킹 흔적이 담긴 웹 접근 로그(access_log.jsonl).

피해자 세션(팀별 동적 session id)이 원래 IP에서 여러 번 쓰인 뒤, 같은 세션이 다른 IP에서
민감 작업(/admin/export)에 재사용된다(세션 하이재킹). 정상 사용자들은 각자 자기 세션을
단일 IP에서만 사용한다.
"""
import hashlib
import hmac
import json
import os
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "for003-dev-secret")
VICTIM_IP = "10.0.0.5"
ATTACKER_IP = "203.0.113.9"
SENSITIVE_ACTION = "/admin/export"


def dynamic_session(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-003:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"sess_{sig}"


def build_log(team_id: str) -> list[dict]:
    victim_sess = dynamic_session(team_id)
    t0 = 1_700_200_000
    rows = []
    # 정상 사용자들(각자 단일 IP, 자기 세션)
    others = [
        ("10.0.0.11", "sess_aaa111", "/dashboard"),
        ("10.0.0.12", "sess_bbb222", "/profile"),
        ("10.0.0.13", "sess_ccc333", "/reports"),
    ]
    i = 0
    for ip, s, uri in others:
        rows.append({"ts": t0 + i * 10, "src_ip": ip, "session": s, "uri": uri}); i += 1
    # 피해자: 원래 IP에서 세션 사용
    for uri in ["/login", "/dashboard", "/profile"]:
        rows.append({"ts": t0 + i * 10, "src_ip": VICTIM_IP, "session": victim_sess, "uri": uri}); i += 1
    # 정상 잡음 하나 더
    rows.append({"ts": t0 + i * 10, "src_ip": "10.0.0.12", "session": "sess_bbb222", "uri": "/settings"}); i += 1
    # 공격자: 같은 세션을 다른 IP에서 민감 작업에 재사용
    rows.append({"ts": t0 + i * 10, "src_ip": ATTACKER_IP, "session": victim_sess, "uri": SENSITIVE_ACTION}); i += 1
    return rows


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        for r in build_log(team_id):
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("access_log.jsonl", team_id)
    print(f"생성 완료: access_log.jsonl (team={team_id})")
