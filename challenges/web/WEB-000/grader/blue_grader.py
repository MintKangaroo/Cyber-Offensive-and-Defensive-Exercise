import requests
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


def grade_blue(context: dict) -> GradeResult:
    base_url = context.get("base_url", "http://localhost:8101")
    try:
        r = requests.get(f"{base_url}/api/debug/config", timeout=5)
        patched_ok = r.status_code == 404
    except requests.exceptions.RequestException as e:
        return GradeResult(False, 0, f"could not reach deploy: {e}")
    return GradeResult(patched_ok, 50 if patched_ok else 0, f"patched={patched_ok}")
