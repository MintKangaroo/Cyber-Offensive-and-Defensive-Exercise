"""FOR-009 Red Grader - 안티포렌식 3단계(필드별 부분점수, 최종 통과는 flag 일치).

blank/오답 제출은 flag 불일치 -> passed=False. 정답은 세 필드 모두 일치 -> passed=True.
"""
import hashlib
import hmac
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "for009-dev-secret")
TAMPERED_NAME = "Users/svc/AppData/Roaming/.sync/agent.cfg"


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-009:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{antiforensic_{sig}}}"


def channel_id(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-009-chan:{team_id}".encode(), hashlib.sha256).hexdigest()[:8]
    return f"ch_{sig}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_flag = dynamic_flag(team_id)
    expected_chid = channel_id(team_id)

    f_file = submission.get("timestomped_file", "").strip()
    f_chid = submission.get("channel_id", "").strip()
    f_flag = submission.get("flag", "").strip()

    score = 0
    detail = {}
    detail["timestomped_file"] = (f_file == TAMPERED_NAME)
    if detail["timestomped_file"]:
        score += 60
    detail["channel_id"] = (f_chid == expected_chid)
    if detail["channel_id"]:
        score += 90
    detail["flag"] = (f_flag == expected_flag)
    if detail["flag"]:
        score += 150

    # 최종 통과 기준: 플래그 일치(체인 전체를 풀어야만 나옴)
    return GradeResult(detail["flag"], score, str(detail))
