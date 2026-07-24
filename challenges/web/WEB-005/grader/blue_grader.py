"""
WEB-005 Blue Grader (11번 문서 2절 채점 계약)
패치(JSON 전환) 후 pickle 페이로드가 코드 실행 없이 거부(비200)되는지 확인.
SIEM alert 확인은 context에 siem 클라이언트가 있을 때만 시도.
"""
import base64
import pickle
import subprocess
import requests
from dataclasses import dataclass


@dataclass
class GradeResult:
    passed: bool
    points: int
    detail: str = ""


class _Probe:
    """무해한 프로브: 실제 위험 명령 대신 'echo' 결과만 반환하도록 __reduce__ 구성."""
    def __reduce__(self):
        return (subprocess.check_output, (["echo", "web005-blue-probe"],))


def grade_blue(context: dict) -> GradeResult:
    base_url = context.get("base_url", "http://localhost:8100")
    payload = base64.b64encode(pickle.dumps(_Probe())).decode()
    try:
        r = requests.post(f"{base_url}/api/historian/import", json={"data": payload}, timeout=5)
        # 패치되면 pickle은 JSON 파싱 실패로 400. 코드 실행 흔적(프로브 문자열)도 없어야 함.
        body = r.text
        patched_ok = (r.status_code != 200) and ("web005-blue-probe" not in body)
    except requests.exceptions.RequestException as e:
        return GradeResult(False, 0, f"could not reach deploy: {e}")

    alert_ok = False
    siem = context.get("siem_client")
    if siem is not None:
        try:
            alert_ok = siem.has_alert("WEB-PICKLE-RCE", team_id=context.get("team_id"))
        except Exception:
            alert_ok = False

    points = (170 if patched_ok else 0) + (80 if alert_ok else 0)
    return GradeResult(patched_ok or alert_ok, points, f"patch={patched_ok} detect={alert_ok}")
