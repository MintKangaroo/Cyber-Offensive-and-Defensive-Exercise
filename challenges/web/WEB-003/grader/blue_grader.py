"""
WEB-003 Blue Grader (11번 문서 2절 채점 계약)
패치 후 남의 소유 기밀 계획(CLASSIFIED_ID) 접근이 403으로 거부되는지 확인.
SIEM alert 확인은 context에 siem 클라이언트가 있을 때만 시도.
"""
import requests
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


CLASSIFIED_ID = 4137


def grade_blue(context: dict) -> GradeResult:
    base_url = context.get("base_url", "http://localhost:8100")
    try:
        r = requests.get(f"{base_url}/api/mission/plan/{CLASSIFIED_ID}",
                         headers={"X-Team-Id": "attacker_team"}, timeout=5)
        patched_ok = r.status_code == 403
    except requests.exceptions.RequestException as e:
        return GradeResult(False, 0, f"could not reach deploy: {e}")

    alert_ok = False
    siem = context.get("siem_client")
    if siem is not None:
        try:
            alert_ok = siem.has_alert("WEB-IDOR-SCAN", team_id=context.get("team_id"))
        except Exception:
            alert_ok = False

    points = (80 if patched_ok else 0) + (40 if alert_ok else 0)
    return GradeResult(patched_ok or alert_ok, points, f"patch={patched_ok} detect={alert_ok}")
