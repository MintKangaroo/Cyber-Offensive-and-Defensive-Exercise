"""ICS-001 Red Grader - 팀별 동적 플래그 비교."""
import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ics001-dev-secret")


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"ICS-001:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{opcua_anon_read_{sig}}}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    submitted = submission.get("flag", "").strip()
    if submitted and submitted == dynamic_flag(team_id):
        return GradeResult(True, 70, "anonymous OPC UA read confirmed by server flag")
    return GradeResult(False, 0, "incorrect or empty flag")
