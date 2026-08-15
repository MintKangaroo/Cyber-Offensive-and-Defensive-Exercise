"""
WEB-007 Red Grader (11번 문서 2절 채점 계약)
동적 플래그(HMAC)와 제출값 비교. deploy/main.py의 dynamic_flag()와 동일 로직.
"""
import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET")
if not CHALLENGE_SECRET:
    raise RuntimeError(
        "CHALLENGE_SECRET 미설정 — 동적 플래그 HMAC 키는 기본값 없이 fail-fast. "
        "배포/채점 환경에 CHALLENGE_SECRET 을 주입하세요.")


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"WEB-007:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"flag{{upload_bypass_{sig}}}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    submitted_flag = submission.get("flag", "").strip()
    expected = dynamic_flag(team_id)
    if submitted_flag == expected:
        return GradeResult(True, 150, "flag correct")
    return GradeResult(False, 0, f"incorrect or empty flag (expected pattern for team={team_id})")
