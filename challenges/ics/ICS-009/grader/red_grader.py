"""ICS-009 Red Grader - 공격자 FF 링크주소 + 복호 flag 일치(팀별 동적)."""
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
def dynamic_flag(team): return f"flag{{ff_mode_blk_oos_sabotage_{_hmac('ICS-009', team, 12)}}}"
def attacker_addr(team): return "0x%02x" % (int(_hmac('ICS-009-addr', team, 4), 16) % 200 + 32)


def grade_red(submission: dict, context: dict) -> GradeResult:
    team = submission.get("team_id", "")
    a = submission.get("attacker_addr", "").strip().lower()
    f = submission.get("flag", "").strip()
    score = 0
    detail = {"attacker_addr": a == attacker_addr(team), "flag": f == dynamic_flag(team)}
    if detail["attacker_addr"]:
        score += 50
    if detail["flag"]:
        score += 90
    return GradeResult(detail["flag"], score, str(detail))
