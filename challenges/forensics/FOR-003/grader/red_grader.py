"""FOR-003 Red Grader - 세션 하이재킹 조사(필드별 부분점수)."""
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
ATTACKER_IP = "203.0.113.9"
SENSITIVE_ACTION = "/admin/export"


def dynamic_session(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-003:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"sess_{sig}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_session = dynamic_session(team_id)

    ip = submission.get("attacker_ip", "").strip()
    session = submission.get("session_id", "").strip()
    action = submission.get("sensitive_action", "").strip()

    score = 0
    detail = {}
    if ip == ATTACKER_IP:
        score += 15
        detail["attacker_ip"] = True
    else:
        detail["attacker_ip"] = False
    if session == expected_session:
        score += 25
        detail["session_id"] = True
    else:
        detail["session_id"] = False
    if action == SENSITIVE_ACTION:
        score += 10
        detail["sensitive_action"] = True
    else:
        detail["sensitive_action"] = False

    return GradeResult(score > 0, score, str(detail))
