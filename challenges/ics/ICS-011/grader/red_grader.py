"""ICS-011 Red Grader - 공격자 IP + 복호 flag 일치(팀별 동적)."""
import hashlib
import hmac
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "ics-011-dev-secret")


def _hmac(tag, team, n): return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]
def dynamic_flag(team): return f"flag{{s7comm_safety_db_write_{_hmac('ICS-011', team, 12)}}}"
def attacker_ip(team): return f"10.85.0.{int(_hmac('ICS-011-ip', team, 4), 16) % 200 + 30}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team = submission.get("team_id", "")
    a = submission.get("attacker_ip", "").strip()
    f = submission.get("flag", "").strip()
    score = 0
    detail = {"attacker_ip": a == attacker_ip(team), "flag": f == dynamic_flag(team)}
    if detail["attacker_ip"]:
        score += 50
    if detail["flag"]:
        score += 90
    return GradeResult(detail["flag"], score, str(detail))
