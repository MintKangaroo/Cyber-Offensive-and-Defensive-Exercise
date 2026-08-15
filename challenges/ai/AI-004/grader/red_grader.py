"""AI-004 Red Grader - RAG 간접 인젝션 인시던트 조사(필드별 부분점수)."""
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
POISONED_SOURCE = "web_scrape"
INJECTION_TYPE = "indirect_prompt_injection"


def dynamic_secret(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"AI-004:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"ADM-{sig}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_secret = dynamic_secret(team_id)

    source = submission.get("poisoned_doc_source", "").strip()
    secret = submission.get("leaked_secret", "").strip()
    itype = submission.get("injection_type", "").strip().lower()

    score = 0
    detail = {}
    if secret == expected_secret:
        score += 30
        detail["leaked_secret"] = True
    else:
        detail["leaked_secret"] = False
    if source == POISONED_SOURCE:
        score += 15
        detail["poisoned_doc_source"] = True
    else:
        detail["poisoned_doc_source"] = False
    if itype == INJECTION_TYPE:
        score += 10
        detail["injection_type"] = True
    else:
        detail["injection_type"] = False

    return GradeResult(score > 0, score, str(detail))
