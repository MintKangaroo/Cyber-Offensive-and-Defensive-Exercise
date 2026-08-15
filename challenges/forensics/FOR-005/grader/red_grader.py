"""FOR-005 Red Grader - 메모리 덤프 자격증명 조사(필드별 부분점수)."""
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
SOURCE_PROCESS = "mysqld"


def dynamic_password(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-005:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"Db!{sig}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected = dynamic_password(team_id)

    cred = submission.get("leaked_credential", "").strip()
    proc = submission.get("source_process", "").strip()

    score = 0
    detail = {}
    if cred == expected:
        score += 35
        detail["leaked_credential"] = True
    else:
        detail["leaked_credential"] = False
    if proc == SOURCE_PROCESS:
        score += 15
        detail["source_process"] = True
    else:
        detail["source_process"] = False

    return GradeResult(score > 0, score, str(detail))
