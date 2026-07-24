"""
WEB-002 Blue Grader (11번 문서 2절 채점 계약)
패치 후 alg=none 위조가 거부되는지 확인. SIEM alert 확인은 context에 siem 클라이언트가
있을 때만 시도(없으면 patch 확인만으로 부분 점수).
"""
import jwt
import requests
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


def grade_blue(context: dict) -> GradeResult:
    base_url = context.get("base_url", "http://localhost:8100")
    forged = jwt.encode({"role": "admin"}, "", algorithm="none")
    try:
        r = requests.post(f"{base_url}/api/mission/approve",
                         headers={"Authorization": f"Bearer {forged}"}, timeout=5)
        patched_ok = r.status_code == 401
    except requests.exceptions.RequestException as e:
        return GradeResult(False, 0, f"could not reach deploy: {e}")

    alert_ok = False
    siem = context.get("siem_client")
    if siem is not None:
        try:
            alert_ok = siem.has_alert("WEB-JWT-FORGE", team_id=context.get("team_id"))
        except Exception:
            alert_ok = False

    points = (100 if patched_ok else 0) + (50 if alert_ok else 0)
    return GradeResult(patched_ok or alert_ok, points, f"patch={patched_ok} detect={alert_ok}")
