"""FOR-005 아티팩트 생성기 - 프로세스 메모리 덤프(memory.dmp).

이진 잡음 사이에 인쇄 가능한 문자열들이 흩어져 있고, 그중 하나에 DB 자격증명(팀별 동적)이
평문으로 남아 있다(메모리에 남은 비밀). 조사자는 strings 추출로 자격증명을 복원한다.
"""
import hashlib
import hmac
import os
import random
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "for005-dev-secret")
SOURCE_PROCESS = "mysqld"


def dynamic_password(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-005:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"Db!{sig}"


def build_dump(team_id: str) -> bytes:
    rng = random.Random(1337)
    strings = [
        b"GET /index.html HTTP/1.1",
        b"/usr/lib/mysql/plugin",
        b"InnoDB: Buffer pool(s) load completed",
        b"connection established from 10.0.0.5",
        (f"DBPASS={dynamic_password(team_id)}").encode(),   # 평문 자격증명(메모리 잔존)
        b"SELECT * FROM sessions WHERE active=1",
        b"/etc/mysql/my.cnf",
        b"tmp/ib_buffer_pool",
    ]
    blob = bytearray()
    for s in strings:
        blob += bytes(rng.randint(0, 31) for _ in range(rng.randint(8, 24)))  # 비인쇄 이진 잡음(문자열 구분자)
        blob += s
        blob += b"\x00\x00"
    return bytes(blob)


def generate(path: str, team_id: str) -> None:
    with open(path, "wb") as f:
        f.write(build_dump(team_id))


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("memory.dmp", team_id)
    print(f"생성 완료: memory.dmp (team={team_id})")
