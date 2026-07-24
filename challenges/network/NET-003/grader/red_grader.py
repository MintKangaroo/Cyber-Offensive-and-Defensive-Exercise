"""NET-003 Red Grader - C2 비콘 분석(필드별 부분점수)."""
import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "net003-dev-secret")
C2_IP = "198.51.100.50"
BEACON_INTERVAL = 60


def dynamic_implant(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-003:{team_id}".encode(), hashlib.sha256).hexdigest()[:10]
    return f"IMP-{sig}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_implant = dynamic_implant(team_id)

    c2 = submission.get("c2_ip", "").strip()
    try:
        interval = int(submission.get("beacon_interval_sec", 0))
    except (TypeError, ValueError):
        interval = 0
    implant = submission.get("implant_id", "").strip()

    score = 0
    detail = {}
    if c2 == C2_IP:
        score += 15
        detail["c2_ip"] = True
    else:
        detail["c2_ip"] = False
    if interval == BEACON_INTERVAL:
        score += 10
        detail["beacon_interval_sec"] = True
    else:
        detail["beacon_interval_sec"] = False
    if implant == expected_implant:
        score += 25
        detail["implant_id"] = True
    else:
        detail["implant_id"] = False

    return GradeResult(score > 0, score, str(detail))
