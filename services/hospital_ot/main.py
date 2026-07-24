"""
Hospital OT Digital Twin (병원 OT 트윈)
=======================================
PACS + HIS + 의료기기 VLAN(주입펌프 등) + Building Automation 을 모사.
훈련용 시뮬레이션(더미 값) — 실제 환자/의료기기와 무관, 모든 PHI는 합성.

취약점:
  HSP-001 PACS Study IDOR      (GET  /api/pacs/study)          — 미인증 영상 스터디 열람(PHI, IDOR)
  HSP-002 HIS Patient SQLi     (GET  /api/his/patient)         — 환자 조회 SQL 인젝션
  HSP-003 Infusion Pump Unauth (POST /api/device/infusion)     — 주입펌프 투여율 무단 변경(안전 임팩트)
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402

STUDIES = {"ST-1001": "CT Chest — DUMMY", "ST-1002": "MRI Brain — DUMMY"}
PATIENTS = {"P001": "Hong G.D. (dummy)", "P002": "Kim Y.H. (dummy)"}


def pacs_study(patched, p, emit):
    sid = p.get("id", "")
    if patched and p.get("authorization") != "Bearer radiology-user-token":
        deny(401, "PACS access requires authenticated radiology user")
    if not patched:
        emit({"study_id": sid, "note": "unauthenticated PACS study access (PHI IDOR)"})
    return {"study_id": sid, "study": STUDIES.get(str(sid), "unknown"), "all_studies": None if patched else STUDIES}


def his_patient(patched, p, emit):
    pid = p.get("id", "")
    if patched:
        row = PATIENTS.get(str(pid))
        return {"id": pid, "patient": row} if row else deny(404, "not found")
    if "'" in pid or "or" in pid.lower() or "union" in pid.lower():
        emit({"id_input": pid, "note": "HIS patient SQL injection"})
        return {"id": pid, "patients": PATIENTS, "note": "injection returned all patients"}
    return {"id": pid, "patient": PATIENTS.get(str(pid))}


def infusion_rate(patched, p, emit):
    if patched and p.get("authorization") != "Bearer clinical-eng-token":
        deny(401, "infusion pump control requires clinical engineering auth")
    if not patched:
        emit({"device": p.get("device", "PUMP-07"), "rate_mlh": p.get("rate"),
              "note": "infusion pump rate changed without auth (patient safety)"})
    return {"device": p.get("device", "PUMP-07"), "rate_mlh": p.get("rate"), "status": "rate applied"}


VULNS = [
    Vuln("HSP-001", "/api/pacs/study", "GET", "PACS study IDOR",
         "flag_exfiltrated", "data_exfiltration", pacs_study),
    Vuln("HSP-002", "/api/his/patient", "GET", "HIS patient SQLi",
         "flag_exfiltrated", "data_exfiltration", his_patient),
    Vuln("HSP-003", "/api/device/infusion", "POST", "Infusion pump unauth",
         "red_objective_success", "objective", infusion_rate),
]

app = make_ics_twin("hospital_ot", "Hospital PACS/HIS/Medical Device Twin", VULNS)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8208)
