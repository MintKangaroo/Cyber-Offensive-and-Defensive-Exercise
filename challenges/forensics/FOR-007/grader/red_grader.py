"""FOR-007 Red Grader - 할로잉된 프로세스명 + 복호 flag 일치 검사(팀별 동적)."""
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

ROSTER = [
    "svchost.exe", "explorer.exe", "RuntimeBroker.exe", "OneDrive.exe",
    "msedge.exe", "Teams.exe", "notepad.exe", "SearchApp.exe",
]


def _hmac(tag: str, team_id: str, n: int) -> str:
    return hmac.new(CHALLENGE_SECRET.encode(), f"{tag}:{team_id}".encode(), hashlib.sha256).hexdigest()[:n]


def dynamic_flag(team_id: str) -> str:
    return f"flag{{process_hollowing_{_hmac('FOR-007', team_id, 12)}}}"


def hollowed_name(team_id: str) -> str:
    idx = int(_hmac("FOR-007-pick", team_id, 8), 16) % len(ROSTER)
    return ROSTER[idx]


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    proc = submission.get("process", "").strip()
    flag = submission.get("flag", "").strip()

    score = 0
    detail = {"process": proc == hollowed_name(team_id), "flag": flag == dynamic_flag(team_id)}
    if detail["process"]:
        score += 60
    if detail["flag"]:
        score += 120
    # 최종 통과 기준: flag 일치(주입영역 탐지+복호를 모두 해야 나옴)
    return GradeResult(detail["flag"], score, str(detail))
