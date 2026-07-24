"""REV-001 Red Grader - checker.py의 validate()를 그대로 사용해 채점(신뢰 원본)."""
import sys
from pathlib import Path
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).parent.parent / "deploy"))
from checker import validate  # noqa: E402


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


def grade_red(submission: dict, context: dict) -> GradeResult:
    team_id = submission.get("team_id", "")
    serial = submission.get("flag", "").strip()  # 시리얼 자체가 flag 역할(challenge.yaml 참고)
    if validate(serial, team_id):
        return GradeResult(True, 150, "serial valid")
    return GradeResult(False, 0, "invalid or empty serial")
