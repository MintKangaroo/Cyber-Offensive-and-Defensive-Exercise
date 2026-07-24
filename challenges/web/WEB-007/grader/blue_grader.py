"""
WEB-007 Blue Grader (11번 문서 2절 채점 계약)
패치 후 content_type을 image/png로 위조해도 스크립트 확장자(.py) 업로드가 400으로
거부되는지 확인. SIEM alert 확인은 context에 siem 클라이언트가 있을 때만 시도.
"""
import requests
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


def grade_blue(context: dict) -> GradeResult:
    base_url = context.get("base_url", "http://localhost:8100")
    forged = {"filename": "shell.py", "content_type": "image/png", "content": "print(1)"}
    try:
        r = requests.post(f"{base_url}/api/upload", json=forged, timeout=5)
        patched_ok = r.status_code == 400
    except requests.exceptions.RequestException as e:
        return GradeResult(False, 0, f"could not reach deploy: {e}")

    alert_ok = False
    siem = context.get("siem_client")
    if siem is not None:
        try:
            alert_ok = siem.has_alert("WEB-UPLOAD-BYPASS", team_id=context.get("team_id"))
        except Exception:
            alert_ok = False

    points = (100 if patched_ok else 0) + (50 if alert_ok else 0)
    return GradeResult(patched_ok or alert_ok, points, f"patch={patched_ok} detect={alert_ok}")
