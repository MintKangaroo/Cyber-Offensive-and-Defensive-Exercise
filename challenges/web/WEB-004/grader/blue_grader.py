"""WEB-004 Blue Grader - 패치판(PATCH_WEB_004=true)에서 순회가 막혔는지 확인."""
import os
from dataclasses import dataclass

import requests


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


def grade_blue(context: dict) -> GradeResult:
    base_url = context.get("base_url", "http://localhost:8104")
    try:
        r = requests.get(f"{base_url}/api/files/download", params={"name": "../flag.txt"}, timeout=10)
    except requests.RequestException as e:
        return GradeResult(False, 0, f"request failed: {e}")
    # 패치판: 순회 시도는 404(basename 처리로 공개 디렉토리 밖 접근 불가)
    if r.status_code == 404:
        return GradeResult(True, 50, "traversal blocked (404)")
    if r.ok and "flag{" not in r.text:
        return GradeResult(True, 50, "no flag leaked")
    return GradeResult(False, 0, "traversal still possible")
