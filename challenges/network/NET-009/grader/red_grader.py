"""NET-009 Red Grader - OT 사보타주 3필드(부분점수, 최종 통과는 flag 일치)."""
import hashlib
import hmac
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "net009-dev-secret")


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-009:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{ot_sabotage_{sig}}}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_flag = dynamic_flag(team_id)

    f_flag = str(submission.get("flag", "")).strip()
    f_rogue = str(submission.get("rogue_ip", "")).strip()
    f_reg = str(submission.get("covert_register", "")).strip()

    score = 0
    detail = {}
    # rogue_ip / covert_register 는 flag 를 풀어야만 결정론적으로 정합 -> 부분점수 기록용
    detail["rogue_ip_present"] = bool(f_rogue)
    detail["covert_register_present"] = bool(f_reg)
    detail["flag"] = (f_flag == expected_flag)
    if detail["rogue_ip_present"]:
        score += 60
    if detail["covert_register_present"]:
        score += 60
    if detail["flag"]:
        score += 180

    return GradeResult(detail["flag"], score, str(detail))
