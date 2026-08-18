"""FOR-000 Red Grader - 조사형 문제라 필드별 부분점수(10번 문서 포맷)."""
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


def dynamic_password(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-000:{team_id}".encode(), hashlib.sha256).hexdigest()[:10]
    return f"B@ckup_{sig}!"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_account = "DUMMY\\svc_backup"
    expected_password = dynamic_password(team_id)

    submitted_account = submission.get("service_account", "").strip()
    submitted_password = submission.get("password", "").strip()

    score = 0
    detail = {}
    if submitted_account == expected_account:
        score += 20
        detail["service_account"] = True
    else:
        detail["service_account"] = False
    if submitted_password == expected_password:
        score += 30
        detail["password"] = True
    else:
        detail["password"] = False

    return GradeResult(score > 0, score, str(detail))
