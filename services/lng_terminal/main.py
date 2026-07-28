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



def lng_tank_gauge(patched, p, emit):
    if patched and p.get("authorization") != "Bearer eng-station":
        deny(401, "HART tank gauge write requires engineering auth")
    if not patched:
        emit({"note": "LNG tank gauge spoof (overfill risk)"})
    return {"status": "ok", "vuln": "LNG-004"}

def lng_compressor_fw(patched, p, emit):
    if patched and p.get("signature") != "vendor-signed":
        deny(403, "firmware image signature invalid")
    if not patched:
        emit({"note": "unsigned BOG compressor firmware upload"})
    return {"status": "ok", "vuln": "LNG-005"}


VULNS = [
    Vuln("LNG-001", "/api/esd/trigger", "POST", "ESD trigger/bypass unauth",
         "red_objective_success", "objective", esd_trigger),
    Vuln("LNG-002", "/api/bog/compressor", "POST", "BOG compressor setpoint tamper",
         "red_attack_started", "lateral_movement", bog_compressor),
    Vuln("LNG-003", "/api/firegas/suppress", "POST", "Fire&Gas alarm suppress",
         "red_objective_success", "objective", firegas_suppress),
    Vuln("LNG-004", "/api/tank/gauge", "POST", "LNG tank gauge spoof",
         "red_attack_started", "lateral_movement", lng_tank_gauge),
    Vuln("LNG-005", "/api/compressor/firmware", "POST", "BOG compressor firmware upload",
         "red_objective_success", "objective", lng_compressor_fw),
]

app = make_ics_twin("lng_terminal", "LNG Terminal ESD/BOG Twin", VULNS)

# 실제 Modbus/TCP(P1-1) — LNG 탱크 압력. HR0=탱크압력설정(mbar)·HR1=BOG압축기율·HR2=ACTUAL·HR4=DAMAGE.
# coil0=ESD(긴급차단 인터록). ESD 해제 + 과압(>200) 지속 → 탱크 파열/증기운(asset_compromised).
from shared.ics.twin_modbus import attach_modbus_ics, ModbusIcsConfig  # noqa: E402
from shared.ics.safety import SafetyProfile  # noqa: E402
from shared.ics.anomaly import IcsBaseline, RegBand  # noqa: E402
from shared.ics.process_sim import ProcessParams  # noqa: E402

attach_modbus_ics(app, ModbusIcsConfig(
    asset="lng_terminal", vuln_id="LNG-001",
    reg_names={0: "TANK_PRESSURE", 1: "BOG_COMPRESSOR"},
    holding_init=[120, 60], coils_init=[True],
    cmd_reg=0, actual_reg=2, damage_reg=4, interlock_coil=0,
    safety=SafetyProfile(name="lng_terminal",
                         limits={0: {"name": "TANK_PRESSURE", "max": 200}}, interlock_coil=0),
    anomaly=IcsBaseline(name="lng_terminal",
                        registers={0: RegBand("TANK_PRESSURE", 80, 200, protected=True),
                                   1: RegBand("BOG_COMPRESSOR", 0, 100)}, safety_coils={0}),
    proc=ProcessParams(slew_rpm_per_s=20, nominal_rpm=0, ambient_temp=0, k_heat=0.0, k_cool=0.0,
                       redline_rpm=200, crit_temp=1e9, damage_rpm_rate=0.1, damage_temp_rate=0.0,
                       failure_threshold=100),
    impact="lng_tank_rupture_vapor_cloud", defense_label="esd_rearmed"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8204)
