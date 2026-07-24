"""NET-005 Red Grader - 포트 노킹 시퀀스 조사(필드별 부분점수)."""
import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "net005-dev-secret")
ATTACKER_IP = "203.0.113.42"
PROTECTED_PORT = 22


def knock_sequence(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-005:{team_id}".encode(), hashlib.sha256).hexdigest()
    seq = [10000 + int(sig[i:i + 4], 16) % 50000 for i in range(0, 12, 4)]
    return ",".join(str(p) for p in seq)


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_seq = knock_sequence(team_id)

    ip = submission.get("attacker_ip", "").strip()
    seq = submission.get("knock_sequence", "").replace(" ", "").strip()
    try:
        port = int(submission.get("protected_port", 0))
    except (TypeError, ValueError):
        port = 0

    score = 0
    detail = {}
    if seq == expected_seq:
        score += 30
        detail["knock_sequence"] = True
    else:
        detail["knock_sequence"] = False
    if ip == ATTACKER_IP:
        score += 10
        detail["attacker_ip"] = True
    else:
        detail["attacker_ip"] = False
    if port == PROTECTED_PORT:
        score += 10
        detail["protected_port"] = True
    else:
        detail["protected_port"] = False

    return GradeResult(score > 0, score, str(detail))
