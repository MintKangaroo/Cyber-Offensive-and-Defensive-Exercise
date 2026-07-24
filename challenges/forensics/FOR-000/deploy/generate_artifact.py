"""FOR-000 배포 - 카빙 대상 아티팩트(backup_config.txt) 생성."""
import hmac
import hashlib
import os

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "for000-dev-secret")


def dynamic_password(team_id: str) -> str:
    """팀별로 다른 더미 비밀번호(공유 방지). DN-003과 같은 톤의 더미 자격증명."""
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-000:{team_id}".encode(), hashlib.sha256).hexdigest()[:10]
    return f"B@ckup_{sig}!"


def generate_backup_config(path: str, team_id: str) -> None:
    password = dynamic_password(team_id)
    content = f"""# backup.conf (더미, 훈련용)
backup_server=backup01.internal.dummy
service_account=DUMMY\\svc_backup
password={password}
path=\\\\backup01\\shares\\daily
schedule=daily@02:00
"""
    with open(path, "w") as f:
        f.write(content)


if __name__ == "__main__":
    import sys
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate_backup_config("backup_config.txt", team_id)
    print(f"생성 완료: backup_config.txt (team={team_id})")
