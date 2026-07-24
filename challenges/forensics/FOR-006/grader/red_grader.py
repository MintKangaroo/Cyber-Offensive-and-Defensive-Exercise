"""FOR-006 Red Grader - 지속성(스케줄 작업) 흔적 조사(필드별 부분점수)."""
import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "for006-dev-secret")
C2_HOST = "persist.evilcdn.example"
SCHEDULE = "*/5 * * * *"


def dynamic_token(team_id: str) -> str:
    return hmac.new(CHALLENGE_SECRET.encode(), f"FOR-006:{team_id}".encode(), hashlib.sha256).hexdigest()[:14]


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_token = dynamic_token(team_id)

    schedule = submission.get("malicious_schedule", "").strip()
    host = submission.get("c2_host", "").strip()
    token = submission.get("implant_token", "").strip()

    score = 0
    detail = {}
    if schedule == SCHEDULE:
        score += 10
        detail["malicious_schedule"] = True
    else:
        detail["malicious_schedule"] = False
    if host == C2_HOST:
        score += 15
        detail["c2_host"] = True
    else:
        detail["c2_host"] = False
    if token == expected_token:
        score += 25
        detail["implant_token"] = True
    else:
        detail["implant_token"] = False

    return GradeResult(score > 0, score, str(detail))
