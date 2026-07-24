"""WEB-009 Blue Grader - 패치판(PATCH_WEB_009=true)에서 인젝션이 막혔는지 확인.

패치되면 비정수 id(인젝션 페이로드)는 400 으로 거부되고, 블라인드 SQLi 로 플래그를
추출할 수 없어야 한다.
"""
from dataclasses import dataclass

import requests


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


def grade_blue(context: dict) -> GradeResult:
    base_url = context.get("base_url", "http://localhost:8109")
    # 우회 페이로드(비정수) — 패치판은 400 이어야 함
    payload = "1/**/AND/**/(SELECT/**/unicode(substr(token,1,1))/**/FROM/**/secrets)>0"
    try:
        r = requests.get(f"{base_url}/api/product", params={"id": payload}, timeout=10)
    except requests.RequestException as e:
        return GradeResult(False, 0, f"request failed: {e}")
    if r.status_code == 400:
        return GradeResult(True, 150, "injection rejected (400)")
    # 400 이 아니면 최소한 플래그 추출로 이어지는 불리언 차이가 없어야 함
    if r.ok and r.json().get("found") is False:
        return GradeResult(True, 150, "injection neutralized (no boolean oracle)")
    return GradeResult(False, 0, "injection still possible")
