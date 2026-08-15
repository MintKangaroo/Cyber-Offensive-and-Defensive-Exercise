"""REV-002 Red Grader - 복원한 팀별 플래그가 정답과 일치하는지 확인."""
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
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"REV-002:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{rvx_{sig}}}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    submitted = submission.get("flag", "").strip()
    expected = dynamic_flag(team_id)
    if submitted == expected:
        return GradeResult(True, 120, "flag correct")
    return GradeResult(False, 0, "incorrect or empty flag")
