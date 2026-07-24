"""REV-004 배포 - 팀별 플래그를 작은 스택 VM 바이트코드로 인코딩한 program.json 생성.

각 플래그 문자는 (a + b) XOR K == charcode 가 되도록 PUSH a, PUSH b, ADD, XOR K, EMIT
바이트코드로 방출된다. 문자 리터럴이 그대로 보이지 않아 VM을 이해해야 복원할 수 있다.

VM 명령: ["PUSH", n] / ["ADD"] / ["XOR", k] / ["EMIT"]
"""
import hashlib
import hmac
import json
import os
import sys

CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "rev004-dev-secret")
K = 0x33


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"REV-004:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{vm_{sig}}}"


def compile_flag(flag: str) -> list:
    program = []
    for ch in flag.encode():
        target = ch ^ K            # (a+b) 가 되어야 할 값
        b = target // 2
        a = target - b
        program += [["PUSH", a], ["PUSH", b], ["ADD"], ["XOR", K], ["EMIT"]]
    return program


def generate(path: str, team_id: str) -> None:
    with open(path, "w") as f:
        json.dump(compile_flag(dynamic_flag(team_id)), f)


if __name__ == "__main__":
    team_id = sys.argv[1] if len(sys.argv) > 1 else "qa_team"
    generate("program.json", team_id)
    print(f"생성 완료: program.json (team={team_id})")
