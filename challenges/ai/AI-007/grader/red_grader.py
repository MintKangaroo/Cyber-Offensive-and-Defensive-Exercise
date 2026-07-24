"""AI-007 Red Grader - 서버가 발급한 팀별 동적 플래그와 제출값 비교."""
import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ai007-dev-secret")


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"AI-007:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{pgd_evasion_{sig}}}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    submitted = submission.get("flag", "").strip()
    if submitted and submitted == dynamic_flag(team_id):
        return GradeResult(True, 220, "budget-constrained PGD evasion confirmed by server flag")
    return GradeResult(False, 0, "incorrect or empty flag")
