"""ICS-010 Red Grader - 공격자 IP + 복호 flag 일치(팀별 동적)."""
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


def _hmac(tag, team, n): return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team}".encode(), hashlib.sha256).hexdigest()[:n]
def dynamic_flag(team): return f"flag{{ethernetip_cip_safety_tamper_{_hmac('ICS-010', team, 12)}}}"
def attacker_ip(team): return f"10.80.0.{int(_hmac('ICS-010-ip', team, 4), 16) % 200 + 30}"


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
