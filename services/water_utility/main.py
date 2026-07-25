"""
Water Utility Digital Twin (수도 시설 트윈)
===========================================
정수장 + 배수장 + 펌프 + 염소 투입 + 유량/압력 계측을 모사. SCADA/Modbus.
훈련용 시뮬레이션(더미 값) — 실제 정수 공정과 무관.

취약점:
  WTR-001 Chlorine Dosing Tamper  (POST /api/dosing/chlorine) — 염소 투입량 무단 변경(공중보건 임팩트)
  WTR-002 Pump Control Unauth     (POST /api/pump/control)    — 취수/배수 펌프 무단 기동/정지
  WTR-003 SCADA HMI Default Creds (POST /api/hmi/login)       — 기본 자격증명 로그인
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402

HMI_ACCOUNTS = {"operator": "operator", "scada": "scada123"}


def chlorine_dosing(patched, p, emit):
    if patched and p.get("authorization") != "Bearer plant-operator-token":
        deny(401, "dosing setpoint change requires operator auth")
    ppm = p.get("ppm")
    if not patched:
        emit({"ppm": ppm, "note": "chlorine dosing setpoint changed without auth"})
    return {"chlorine_ppm": ppm, "status": "dosing setpoint applied"}


def pump_control(patched, p, emit):
    if patched and p.get("authorization") != "Bearer plant-operator-token":
        deny(401, "pump control requires operator auth")
    if not patched:
        emit({"pump": p.get("pump", "INTAKE-1"), "action": p.get("action"),
              "note": "unauthenticated pump start/stop"})
    return {"pump": p.get("pump", "INTAKE-1"), "action": p.get("action", "stop"), "status": "command sent"}


def hmi_login(patched, p, emit):
    u, pw = p.get("username", ""), p.get("password", "")
    if patched and u in HMI_ACCOUNTS and HMI_ACCOUNTS[u] == pw:
        deny(403, "default password must be changed on first login")
    if HMI_ACCOUNTS.get(u) == pw:
        if not patched:
            emit({"username": u, "note": "default HMI credentials"})
        return {"status": "login_success", "role": u}
    return deny(401, "invalid credentials")



def wtr_setpoint(patched, p, emit):
    if patched and p.get("authorization") != "Bearer scada-op":
        deny(401, "reservoir setpoint change requires operator auth")
    if not patched:
        emit({"note": "unauthenticated reservoir level setpoint tamper"})
    return {"status": "ok", "vuln": "WTR-004"}

def wtr_report_ssrf(patched, p, emit):
    if patched and p.get("authorization") != "Bearer report-svc":
        deny(400, "fetch URL blocked (allowlist)")
    if not patched:
        emit({"note": "report fetch SSRF to internal metadata"})
    return {"status": "ok", "vuln": "WTR-005"}


VULNS = [
    Vuln("WTR-001", "/api/dosing/chlorine", "POST", "Chlorine dosing tamper",
         "red_objective_success", "objective", chlorine_dosing),
    Vuln("WTR-002", "/api/pump/control", "POST", "Pump control unauth",
         "red_attack_started", "lateral_movement", pump_control),
    Vuln("WTR-003", "/api/hmi/login", "POST", "SCADA HMI default creds",
         "red_attack_started", "initial_access", hmi_login),
    Vuln("WTR-004", "/api/tank/setpoint", "POST", "Reservoir setpoint tamper",
         "red_objective_success", "objective", wtr_setpoint),
    Vuln("WTR-005", "/api/report/fetch", "POST", "Report fetch SSRF",
         "red_attack_started", "lateral_movement", wtr_report_ssrf),
]

app = make_ics_twin("water_utility", "Water Treatment SCADA Twin", VULNS)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8203)
