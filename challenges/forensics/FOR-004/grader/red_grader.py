"""FOR-004 Red Grader - 피싱 이메일 헤더 조사(필드별 부분점수)."""
import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "for004-dev-secret")
ORIGIN_IP = "198.51.100.77"
SPOOFED_FROM = "ceo@bigcorp.example"


def dynamic_token(team_id: str) -> str:
    return hmac.new(CHALLENGE_SECRET.encode(), f"FOR-004:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_token = dynamic_token(team_id)

    ip = submission.get("originating_ip", "").strip()
    frm = submission.get("spoofed_from", "").strip()
    token = submission.get("verification_token", "").strip()

    score = 0
    detail = {}
    if ip == ORIGIN_IP:
        score += 15
        detail["originating_ip"] = True
    else:
        detail["originating_ip"] = False
    if frm == SPOOFED_FROM:
        score += 10
        detail["spoofed_from"] = True
    else:
        detail["spoofed_from"] = False
    if token == expected_token:
        score += 25
        detail["verification_token"] = True
    else:
        detail["verification_token"] = False

    return GradeResult(score > 0, score, str(detail))
