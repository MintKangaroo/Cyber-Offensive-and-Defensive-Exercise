import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ai000-dev-secret")


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"AI-000:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{feature_space_evasion_{sig}}}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    submitted = submission.get("flag", "").strip()
    expected = dynamic_flag(team_id)
    if submitted == expected:
        return GradeResult(True, 60, "evasion confirmed by server-issued flag")
    return GradeResult(False, 0, "incorrect or empty flag")
