"""NET-004 Red Grader - ARP 스푸핑 조사(필드별 부분점수)."""
import hmac
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "net004-dev-secret")
GATEWAY_IP = "10.0.0.1"
ATTACK_TECHNIQUE = "T1557"   # Adversary-in-the-Middle


def dynamic_mac(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-004:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return ":".join(sig[i:i + 2] for i in range(0, 12, 2))


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_mac = dynamic_mac(team_id)

    mac = submission.get("attacker_mac", "").strip().lower()
    ip = submission.get("spoofed_ip", "").strip()
    technique = submission.get("attack_technique", "").strip().upper()

    score = 0
    detail = {}
    if mac == expected_mac:
        score += 25
        detail["attacker_mac"] = True
    else:
        detail["attacker_mac"] = False
    if ip == GATEWAY_IP:
        score += 15
        detail["spoofed_ip"] = True
    else:
        detail["spoofed_ip"] = False
    if technique == ATTACK_TECHNIQUE:
        score += 10
        detail["attack_technique"] = True
    else:
        detail["attack_technique"] = False

    return GradeResult(score > 0, score, str(detail))
