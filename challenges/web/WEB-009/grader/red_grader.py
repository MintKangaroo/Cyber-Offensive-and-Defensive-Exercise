"""WEB-009 Red Grader - 정적 플래그(CHALLENGE_SECRET 기반)와 제출값 비교."""
import hashlib
import os
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CHALLENGE_SECRET = os.environ.get("CHALLENGE_SECRET", "web009-dev-secret")


def static_flag() -> str:
    sig = hashlib.sha256(f"WEB-009:{CHALLENGE_SECRET}".encode()).hexdigest()[:16]
    return f"flag{{waf_blind_sqli_{sig}}}"


def grade_red(submission: dict, context: dict) -> GradeResult:
    submitted = submission.get("flag", "").strip()
    if submitted == static_flag():
        return GradeResult(True, 300, "flag correct")
    return GradeResult(False, 0, "incorrect or empty flag")
