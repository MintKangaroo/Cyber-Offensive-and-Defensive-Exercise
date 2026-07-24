import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "net000-dev-secret")
EXPECTED_USERNAME = "svc_operator"


def dynamic_password(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-000:{team_id}".encode(), hashlib.sha256).hexdigest()[:8]
    return f"pw_{sig}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_password = dynamic_password(team_id)

    score = 0
    detail = {}
    if submission.get("username", "").strip() == EXPECTED_USERNAME:
        score += 20
        detail["username"] = True
    else:
        detail["username"] = False
    if submission.get("password", "").strip() == expected_password:
        score += 30
        detail["password"] = True
    else:
        detail["password"] = False

    return GradeResult(score > 0, score, str(detail))
