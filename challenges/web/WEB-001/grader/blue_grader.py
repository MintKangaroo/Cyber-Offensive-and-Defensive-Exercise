"""WEB-001 Blue Grader - 패치판(PATCH_WEB_001=true)에서 주입이 막혔는지 확인.

패치되면 셸 메타문자가 든 host 는 400으로 거부되어야 한다.
"""
import os
from dataclasses import dataclass

import requests


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


def grade_blue(context: dict) -> GradeResult:
    base_url = context.get("base_url", "http://localhost:8103")
    try:
        r = requests.get(f"{base_url}/api/net/ping",
                         params={"host": "127.0.0.1; cat /app/flag.txt"}, timeout=10)
    except requests.RequestException as e:
        return GradeResult(False, 0, f"request failed: {e}")
    # 패치판: 주입 문자열은 400 거부(또는 최소한 flag 미노출)
    if r.status_code == 400:
        return GradeResult(True, 50, "injection rejected (400)")
    if r.ok and "flag{" not in r.text:
        return GradeResult(True, 50, "no flag leaked")
    return GradeResult(False, 0, "injection still possible")
