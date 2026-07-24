"""NET-007 Red Grader - 진입 IP + 복호 flag 일치 검사(팀별 동적)."""
import base64
import hashlib
import hmac
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "net007-dev-secret")


def _hmac(tag: str, team_id: str, n: int) -> str:
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team_id}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team_id: str) -> str:
    return f"flag{{pivot_chain_{_hmac('NET-007', team_id, 12)}}}"


def entry_ip(team_id: str) -> str:
    octet = int(_hmac("NET-007-entry", team_id, 4), 16) % 200 + 20
    return f"203.0.113.{octet}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    entry = submission.get("entry_ip", "").strip()
    flag = submission.get("flag", "").strip()

    score = 0
    detail = {"entry_ip": entry == entry_ip(team_id), "flag": flag == dynamic_flag(team_id)}
    if detail["entry_ip"]:
        score += 60
    if detail["flag"]:
        score += 120
    # 최종 통과 기준: flag 일치(체인 복원+토큰 복호를 모두 해야 나옴)
    return GradeResult(detail["flag"], score, str(detail))
