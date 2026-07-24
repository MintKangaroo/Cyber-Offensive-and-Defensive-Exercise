"""REV-005 Red Grader - 복원한 팀별 플래그가 정답과 일치하는지 확인."""
import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "rev005-dev-secret")


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"REV-005:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{lcg_{sig}}}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    submitted = submission.get("flag", "").strip()
    expected = dynamic_flag(team_id)
    if submitted == expected:
        return GradeResult(True, 130, "flag correct")
    return GradeResult(False, 0, "incorrect or empty flag")
