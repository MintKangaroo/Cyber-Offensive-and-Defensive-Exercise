"""AI-002 Red Grader - 프롬프트 인젝션 인시던트 조사(필드별 부분점수)."""
import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ai002-dev-secret")
INJECTION_TECHNIQUE = "instruction_override"


def dynamic_secret(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"AI-002:{team_id}".encode(), hashlib.sha256).hexdigest()[:14]
    return f"KEY-{sig}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_secret = dynamic_secret(team_id)

    secret = submission.get("leaked_secret", "").strip()
    technique = submission.get("injection_technique", "").strip().lower()

    score = 0
    detail = {}
    if secret == expected_secret:
        score += 40
        detail["leaked_secret"] = True
    else:
        detail["leaked_secret"] = False
    if technique == INJECTION_TECHNIQUE:
        score += 20
        detail["injection_technique"] = True
    else:
        detail["injection_technique"] = False

    return GradeResult(score > 0, score, str(detail))
