"""NET-001 Red Grader - DNS 터널링 유출 조사(필드별 부분점수).

C2 도메인, 복원한 비밀(팀별 동적), 사용 기법을 필드별 채점. 동적 비밀은 HMAC 패턴.
"""
import hmac
import hashlib
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
C2_DOMAIN = "tunnel.c2dns.net"
ATTACK_TECHNIQUE = "T1071.004"   # Application Layer Protocol: DNS


def dynamic_secret(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"NET-001:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"DNS-{sig}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_secret = dynamic_secret(team_id)

    domain = submission.get("c2_domain", "").strip()
    data = submission.get("decoded_data", "").strip()
    technique = submission.get("attack_technique", "").strip().upper()

    score = 0
    detail = {}
    if domain == C2_DOMAIN:
        score += 15
        detail["c2_domain"] = True
    else:
        detail["c2_domain"] = False
    if data == expected_secret:
        score += 25
        detail["decoded_data"] = True
    else:
        detail["decoded_data"] = False
    if technique == ATTACK_TECHNIQUE:
        score += 10
        detail["attack_technique"] = True
    else:
        detail["attack_technique"] = False

    return GradeResult(score > 0, score, str(detail))
