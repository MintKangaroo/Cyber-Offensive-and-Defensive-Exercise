"""FOR-002 Red Grader - 4개 필드 각 50점, 조사형 부분점수(10번 문서 포맷)."""
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
ATTACKER_IP = "10.13.37.66"
EXPLOITED_ENDPOINT = "/api/telemetry"
ATTACK_TECHNIQUE = "T1190"


def dynamic_flag(team_id: str) -> str:
    sig = hmac.new(CHALLENGE_SECRET.encode(), f"FOR-002:{team_id}".encode(), hashlib.sha256).hexdigest()[:12]
    return f"flag{{pcap_carved_{sig}}}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    expected_flag = dynamic_flag(team_id)

    fields = {
        "attacker_ip": submission.get("attacker_ip") == ATTACKER_IP,
        "exploited_endpoint": submission.get("exploited_endpoint") == EXPLOITED_ENDPOINT,
        "exfiltrated_flag": submission.get("exfiltrated_flag") == expected_flag,
        "attack_technique": submission.get("attack_technique") == ATTACK_TECHNIQUE,
    }
    score = sum(50 for ok in fields.values() if ok)
    return GradeResult(score > 0, score, str(fields))
