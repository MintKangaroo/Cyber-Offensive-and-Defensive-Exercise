"""NET-006 Red Grader - TCP 재조립 유출 조사(필드별 부분점수)."""
import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "net006-dev-secret")
ATTACKER_IP = "10.9.9.9"
ATTACK_TECHNIQUE = "T1041"   # Exfiltration Over C2 Channel


def dynamic_secret(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-006:{team_id}".encode(), hashlib.sha256).hexdigest()[:16]
    return f"SEC-{sig}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_secret = dynamic_secret(team_id)

    ip = submission.get("attacker_ip", "").strip()
    secret = submission.get("reassembled_secret", "").strip()
    technique = submission.get("attack_technique", "").strip().upper()

    score = 0
    detail = {}
    if secret == expected_secret:
        score += 25
        detail["reassembled_secret"] = True
    else:
        detail["reassembled_secret"] = False
    if ip == ATTACKER_IP:
        score += 15
        detail["attacker_ip"] = True
    else:
        detail["attacker_ip"] = False
    if technique == ATTACK_TECHNIQUE:
        score += 10
        detail["attack_technique"] = True
    else:
        detail["attack_technique"] = False

    return GradeResult(score > 0, score, str(detail))
