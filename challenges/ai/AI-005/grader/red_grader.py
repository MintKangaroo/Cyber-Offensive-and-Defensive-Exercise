"""AI-005 Red Grader - 모델 추출 API 남용 조사(필드별 부분점수)."""
import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ai005-dev-secret")
ABUSER_CLIENT = "client_zeta"
ABUSE_COUNT = 60


def dynamic_key(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"AI-005:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"sk-{sig}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_key = dynamic_key(team_id)

    client = submission.get("abusive_client", "").strip()
    key = submission.get("leaked_api_key", "").strip()
    try:
        count = int(submission.get("query_count", 0))
    except (TypeError, ValueError):
        count = 0

    score = 0
    detail = {}
    if key == expected_key:
        score += 25
        detail["leaked_api_key"] = True
    else:
        detail["leaked_api_key"] = False
    if client == ABUSER_CLIENT:
        score += 15
        detail["abusive_client"] = True
    else:
        detail["abusive_client"] = False
    if count == ABUSE_COUNT:
        score += 10
        detail["query_count"] = True
    else:
        detail["query_count"] = False

    return GradeResult(score > 0, score, str(detail))
