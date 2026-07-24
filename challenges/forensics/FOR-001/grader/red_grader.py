"""FOR-001 Red Grader - 조사형 문제(필드별 부분점수, 10번 문서 포맷).

셸 명령 이력에서 (1) 공격에 쓰인 exfil 호스트, (2) base64로 유출된 비밀(팀별 동적),
(3) 사용된 ATT&CK 기법을 맞혔는지 필드별로 채점한다. 팀별 동적 비밀은 FOR-000과 동일한
HMAC 패턴으로 생성해 정답 공유를 막는다.
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


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "for001-dev-secret")
EXFIL_HOST = "exfil.darknode.io"
ATTACK_TECHNIQUE = "T1048"   # Exfiltration Over Alternative Protocol


def dynamic_secret(team_id: str) -> str:
    """팀별 유출 비밀. 이력에는 base64('FLAG:'+이 값) 형태로 심어져 있다."""
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-001:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"S3cr3t-{sig}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_secret = dynamic_secret(team_id)

    host = submission.get("exfil_host", "").strip()
    secret = submission.get("decoded_secret", "").strip()
    technique = submission.get("attack_technique", "").strip().upper()

    score = 0
    detail = {}
    if host == EXFIL_HOST:
        score += 15
        detail["exfil_host"] = True
    else:
        detail["exfil_host"] = False
    if secret == expected_secret:
        score += 25
        detail["decoded_secret"] = True
    else:
        detail["decoded_secret"] = False
    if technique == ATTACK_TECHNIQUE:
        score += 10
        detail["attack_technique"] = True
    else:
        detail["attack_technique"] = False

    return GradeResult(score > 0, score, str(detail))
