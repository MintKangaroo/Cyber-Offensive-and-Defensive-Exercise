"""AI-009 Red Grader - 적대적 회피 3필드(부분점수, 최종 통과는 flag 일치)."""
import hashlib
import hmac
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
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"AI-009:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{transfer_evasion_{sig}}}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_flag = dynamic_flag(team_id)

    f_flag = str(submission.get("flag", "")).strip()
    f_qid = str(submission.get("evasion_query_id", "")).strip()
    f_pert = submission.get("perturbed_features", None)

    score = 0
    detail = {}
    detail["evasion_query_id_present"] = bool(f_qid)
    detail["perturbed_features_present"] = bool(f_pert)
    detail["flag"] = (f_flag == expected_flag)
    if detail["evasion_query_id_present"]:
        score += 60
    if detail["perturbed_features_present"]:
        score += 60
    if detail["flag"]:
        score += 180

    return GradeResult(detail["flag"], score, str(detail))
