"""AI-003 Red Grader - 데이터 포이즈닝 인시던트 조사(필드별 부분점수)."""
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
INJECTED_SOURCE = "external_upload"
POISONED_LABEL = "benign"


def dynamic_trigger(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"AI-003:{team_id}".encode(), hashlib.sha256).hexdigest()[:10]
    return f"tgz{sig}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_trigger = dynamic_trigger(team_id)

    source = submission.get("injected_source", "").strip()
    trigger = submission.get("trigger_token", "").strip()
    label = submission.get("poisoned_label", "").strip().lower()

    score = 0
    detail = {}
    if trigger == expected_trigger:
        score += 30
        detail["trigger_token"] = True
    else:
        detail["trigger_token"] = False
    if source == INJECTED_SOURCE:
        score += 15
        detail["injected_source"] = True
    else:
        detail["injected_source"] = False
    if label == POISONED_LABEL:
        score += 10
        detail["poisoned_label"] = True
    else:
        detail["poisoned_label"] = False

    return GradeResult(score > 0, score, str(detail))
