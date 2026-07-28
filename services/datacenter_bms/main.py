"""
Data Center BMS Digital Twin (데이터센터 BMS 트윈)
==================================================
UPS + CRAC(정밀공조) + Generator + BMS + DCIM 을 모사.
훈련용 시뮬레이션(더미 값) — 실제 시설과 무관.

취약점:
  DCX-001 CRAC Setpoint Tamper   (POST /api/crac/setpoint)  — 냉방 설정치 변조(과열 유도)
  DCX-002 UPS Shutdown Unauth    (POST /api/ups/command)    — UPS 무단 셧다운 명령
  DCX-003 DCIM SSRF              (POST /api/dcim/fetch)     — DCIM 원격 URL 조회(SSRF)
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402


def _is_internal(url: str) -> bool:
    u = (url or "").lower()
    return (u.startswith("file://") or any(n in u for n in
            ("169.254.169.254", "localhost", "127.0.0.1", "10.", "192.168.", "internal", "metadata")))


def crac_setpoint(patched, p, emit):
    if patched and p.get("authorization") != "Bearer facility-ops-token":
        deny(401, "CRAC setpoint change requires facility ops auth")
    if not patched:
        emit({"unit": p.get("unit", "CRAC-3"), "temp_c": p.get("temp_c"),
              "note": "CRAC cooling setpoint tampered (overheat risk)"})
    return {"unit": p.get("unit", "CRAC-3"), "setpoint_c": p.get("temp_c"), "status": "setpoint applied"}


def ups_command(patched, p, emit):
    cmd = p.get("command", "")
    if patched and cmd not in ("STATUS", "SELFTEST"):
        deny(403, "UPS command requires privileged auth")
    if not patched:
        emit({"command": cmd, "note": "unauthenticated UPS shutdown/command"})
    return {"command": cmd, "status": "UPS command accepted"}


def dcim_fetch(patched, p, emit):
    url = p.get("url", "")
    internal = _is_internal(url)
    if patched and (internal or not url.startswith("https://")):
        deny(400, "target not allowed")
    if not patched and internal:
        emit({"url": url, "note": "DCIM SSRF reached internal/metadata resource"})
        return {"url": url, "internal_response": {"bmc_cred": "DUMMY_ADMIN", "note": "SSRF"}}
    return {"url": url, "title": "external asset metadata"}



def dcx_generator(patched, p, emit):
    if patched and p.get("approver_token") != "facilities-approval":
        deny(403, "generator control requires facilities approval")
    if not patched:
        emit({"note": "unauthenticated generator start/stop"})
    return {"status": "ok", "vuln": "DCX-004"}

def dcx_door(patched, p, emit):
    if patched and p.get("authorization") != "Bearer pacs-badge":
        deny(401, "door control requires badge auth")
    if not patched:
        emit({"note": "physical access control door unlock"})
    return {"status": "ok", "vuln": "DCX-005"}


VULNS = [
    Vuln("DCX-001", "/api/crac/setpoint", "POST", "CRAC setpoint tamper",
         "red_objective_success", "objective", crac_setpoint),
    Vuln("DCX-002", "/api/ups/command", "POST", "UPS shutdown unauth",
         "red_objective_success", "objective", ups_command),
    Vuln("DCX-003", "/api/dcim/fetch", "POST", "DCIM SSRF",
         "red_attack_started", "lateral_movement", dcim_fetch),
    Vuln("DCX-004", "/api/generator/control", "POST", "Generator start/stop",
         "red_objective_success", "objective", dcx_generator),
    Vuln("DCX-005", "/api/access/door", "POST", "Access control door unlock",
         "red_attack_started", "lateral_movement", dcx_door),
]

app = make_ics_twin("datacenter_bms", "Data Center UPS/CRAC/DCIM Twin", VULNS)

# 실제 Modbus/TCP(P1-1) — 랙 온도. HR0=RACK_TEMP(°C)·HR2=ACTUAL·HR4=DAMAGE. coil0=열 인터록.
# CRAC 설정 변조로 열 인터록 우회 + 과열(>35°C) 지속 → 열 폭주/장비 손상(asset_compromised).
from shared.ics.twin_modbus import attach_modbus_ics, ModbusIcsConfig  # noqa: E402
from shared.ics.safety import SafetyProfile  # noqa: E402
from shared.ics.anomaly import IcsBaseline, RegBand  # noqa: E402
from shared.ics.process_sim import ProcessParams  # noqa: E402
attach_modbus_ics(app, ModbusIcsConfig(
    asset="datacenter_bms", vuln_id="DCX-001", reg_names={0: "RACK_TEMP", 1: "CRAC_LOAD"},
    holding_init=[24, 50], coils_init=[True], cmd_reg=0, actual_reg=2, damage_reg=4, interlock_coil=0,
    safety=SafetyProfile(name="datacenter_bms", limits={0: {"name": "RACK_TEMP", "max": 35}}, interlock_coil=0),
    anomaly=IcsBaseline(name="datacenter_bms", registers={0: RegBand("RACK_TEMP", 18, 35, protected=True)}, safety_coils={0}),
    proc=ProcessParams(slew_rpm_per_s=2, nominal_rpm=0, k_heat=0.0, k_cool=0.0, redline_rpm=35,
                       crit_temp=1e9, damage_rpm_rate=2.0, damage_temp_rate=0.0, failure_threshold=100),
    impact="datacenter_thermal_runaway", defense_label="thermal_interlock_rearmed"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8207)
