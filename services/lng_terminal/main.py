"""
LNG Terminal Digital Twin (LNG 터미널 트윈)
===========================================
Storage Tank + BOG Compressor + Cryogenic Pump + Fire&Gas + ESD 를 모사.
훈련용 시뮬레이션(더미 값) — 실제 극저온 설비와 무관.

취약점:
  LNG-001 ESD Trigger/Bypass Unauth  (POST /api/esd/trigger)        — 비상정지(ESD) 무단 조작(안전 임팩트)
  LNG-002 BOG Compressor Setpoint     (POST /api/bog/compressor)     — BOG 압축기 설정치 변조
  LNG-003 Fire&Gas Alarm Suppress     (POST /api/firegas/suppress)   — 화재/가스 감지 알람 억제
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402


def esd_trigger(patched, p, emit):
    if patched and p.get("approver_token") != "esd-supervisor-approval":
        deny(403, "ESD actuation requires supervisor approval")
    action = p.get("action", "trip")
    if not patched:
        emit({"action": action, "note": "ESD (emergency shutdown) actuated/bypassed without approval"})
    return {"esd_action": action, "status": "ESD state changed"}


def bog_compressor(patched, p, emit):
    if patched and p.get("authorization") != "Bearer control-room-token":
        deny(401, "BOG compressor setpoint requires control room auth")
    if not patched:
        emit({"setpoint_bar": p.get("setpoint"), "note": "BOG compressor setpoint tampered"})
    return {"compressor": "BOG-1", "setpoint_bar": p.get("setpoint"), "status": "setpoint applied"}


def firegas_suppress(patched, p, emit):
    if patched and p.get("authorization") != "Bearer safety-engineer-token":
        deny(403, "Fire&Gas suppression requires safety engineer auth")
    if not patched:
        emit({"zone": p.get("zone", "TANK-AREA"), "note": "Fire&Gas detection alarm suppressed"})
    return {"zone": p.get("zone", "TANK-AREA"), "firegas_alarm": "suppressed"}


VULNS = [
    Vuln("LNG-001", "/api/esd/trigger", "POST", "ESD trigger/bypass unauth",
         "red_objective_success", "objective", esd_trigger),
    Vuln("LNG-002", "/api/bog/compressor", "POST", "BOG compressor setpoint tamper",
         "red_attack_started", "lateral_movement", bog_compressor),
    Vuln("LNG-003", "/api/firegas/suppress", "POST", "Fire&Gas alarm suppress",
         "red_objective_success", "objective", firegas_suppress),
]

app = make_ics_twin("lng_terminal", "LNG Terminal ESD/BOG Twin", VULNS)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8204)
