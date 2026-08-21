"""ICS-005 Red Grader - 공격자 MAC + 복호 flag 일치(팀별 동적)."""
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
def dynamic_flag(team): return f"flag{{profinet_dcp_spoof_{_hmac('ICS-005', team, 12)}}}"


def attacker_mac(team):
    h = _hmac("ICS-005-mac", team, 8)
    return "de:ad:" + ":".join(h[i:i+2] for i in range(0, 8, 2))


def grade_red(submission: dict, context: dict) -> GradeResult:
    team = submission.get("team_id", "")
    m = submission.get("attacker_mac", "").strip().lower()
    f = submission.get("flag", "").strip()
    score = 0
    detail = {"attacker_mac": m == attacker_mac(team), "flag": f == dynamic_flag(team)}
    if detail["attacker_mac"]:
        score += 40
    if detail["flag"]:
        score += 80
    return GradeResult(detail["flag"], score, str(detail))
