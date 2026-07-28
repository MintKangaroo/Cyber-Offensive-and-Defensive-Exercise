"""
Railway Signaling Digital Twin (철도 신호 트윈)
===============================================
신호 시스템 + ATS + ATP + CTC + 전력공급 을 모사.
훈련용 시뮬레이션(더미 값) — 실제 신호설비와 무관.

취약점:
  RWY-001 Signal Aspect Override    (POST /api/signal/set)          — 신호기 현시 무단 변경(안전 임팩트)
  RWY-002 Interlocking Bypass       (POST /api/interlocking/override) — 연동장치 무단 우회
  RWY-003 ATS Command Injection     (POST /api/ats/command)         — 열차자동제어 임의 명령
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402


def signal_set(patched, p, emit):
    if patched and p.get("authorization") != "Bearer ctc-dispatcher-token":
        deny(401, "signal aspect change requires CTC dispatcher auth")
    if not patched:
        emit({"signal": p.get("signal", "S12"), "aspect": p.get("aspect"),
              "note": "signal aspect overridden without authorization"})
    return {"signal": p.get("signal", "S12"), "aspect": p.get("aspect", "clear"), "status": "aspect set"}


def interlocking_override(patched, p, emit):
    if patched and p.get("approver_token") != "interlocking-2man-approval":
        deny(403, "interlocking override requires 2-person approval")
    if not patched:
        emit({"route": p.get("route"), "note": "safety interlocking bypassed"})
    return {"route": p.get("route", "R7"), "interlocking": "bypassed"}


def ats_command(patched, p, emit):
    cmd = p.get("command", "")
    if patched and cmd not in ("STATUS", "SYNC"):
        deny(403, "ATS command not in allowlist")
    if not patched:
        emit({"command": cmd, "note": "arbitrary ATS command"})
    return {"command": cmd, "status": "ATS command dispatched"}



def rwy_balise(patched, p, emit):
    if patched and p.get("authorization") != "Bearer signaling-eng":
        deny(401, "balise telegram write requires signaling auth")
    if not patched:
        emit({"note": "unauthenticated balise telegram write"})
    return {"status": "ok", "vuln": "RWY-004"}

def rwy_timetable_idor(patched, p, emit):
    if patched and p.get("authorization") != "Bearer ctc-token":
        deny(401, "timetable access requires CTC auth")
    if not patched:
        emit({"note": "timetable IDOR (schedule disclosure)"})
    return {"status": "ok", "vuln": "RWY-005"}


VULNS = [
    Vuln("RWY-001", "/api/signal/set", "POST", "Signal aspect override",
         "red_objective_success", "objective", signal_set),
    Vuln("RWY-002", "/api/interlocking/override", "POST", "Interlocking bypass",
         "red_objective_success", "objective", interlocking_override),
    Vuln("RWY-003", "/api/ats/command", "POST", "ATS command injection",
         "red_attack_started", "privilege_escalation", ats_command),
    Vuln("RWY-004", "/api/balise/telegram", "POST", "Balise telegram write",
         "red_objective_success", "objective", rwy_balise),
    Vuln("RWY-005", "/api/timetable/get", "GET", "Timetable IDOR",
         "red_attack_started", "data_exfiltration", rwy_timetable_idor),
]

app = make_ics_twin("railway_signaling", "Railway Signaling/ATS Twin", VULNS)

# 실제 Modbus/TCP(P1-1) — 열차 속도. HR0=TRAIN_SPEED(km/h)·HR2=ACTUAL·HR4=DAMAGE. coil0=연동(interlocking).
# 연동 우회 + 과속(>120) 지속 → 탈선/충돌(asset_compromised).
from shared.ics.twin_modbus import attach_modbus_ics, ModbusIcsConfig  # noqa: E402
from shared.ics.safety import SafetyProfile  # noqa: E402
from shared.ics.anomaly import IcsBaseline, RegBand  # noqa: E402
from shared.ics.process_sim import ProcessParams  # noqa: E402
attach_modbus_ics(app, ModbusIcsConfig(
    asset="railway_signaling", vuln_id="RWY-002", reg_names={0: "TRAIN_SPEED", 1: "BRAKE_LEVEL"},
    holding_init=[80, 0], coils_init=[True], cmd_reg=0, actual_reg=2, damage_reg=4, interlock_coil=0,
    safety=SafetyProfile(name="railway_signaling", limits={0: {"name": "TRAIN_SPEED", "max": 120}}, interlock_coil=0),
    anomaly=IcsBaseline(name="railway_signaling", registers={0: RegBand("TRAIN_SPEED", 0, 120, protected=True)}, safety_coils={0}),
    proc=ProcessParams(slew_rpm_per_s=10, nominal_rpm=0, k_heat=0.0, k_cool=0.0, redline_rpm=120,
                       crit_temp=1e9, damage_rpm_rate=0.5, damage_temp_rate=0.0, failure_threshold=100),
    impact="train_derailment_collision", defense_label="interlocking_rearmed"))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8205)
