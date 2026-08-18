"""
Refinery / Petrochemical Plant Digital Twin (정유·석유화학 플랜트 트윈)
=====================================================================
DCS + SIS(Safety Instrumented System) + Tank Farm 을 모사. 프로토콜: OPC UA / Modbus / HART.
훈련용 시뮬레이션 — 실제 플랜트/장비와 무관하며 모든 값은 더미다.

취약점:
  REF-001 OPC UA Anonymous Read    (GET  /api/opcua/read)      — 미인증 DCS 태그 열람
  REF-002 SIS Safety Bypass        (POST /api/sis/bypass)      — 안전계장 트립 무단 우회(ICS)
  REF-003 HART Tank Gauge Spoof    (POST /api/tankfarm/gauge)  — 탱크 레벨 위조(오버필 유도)
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402

TAGS = {
    "ns=2;s=CDU.Furnace.TempC": 385.0,
    "ns=2;s=SIS.HH_Trip.Setpoint": 420.0,   # 안전 계장 트립 설정치(민감)
    "ns=2;s=TankFarm.T101.LevelPct": 63.2,
}


def opcua_read(patched, p, emit):
    if patched and p.get("token") != "opcua-signed-session":
        deny(401, "OPC UA anonymous access disabled; signed session required")
    node = p.get("node", "")
    if not patched:
        emit({"node": node, "note": "anonymous OPC UA read of DCS/SIS tags"})
    return {"node": node, "value": TAGS.get(node, "unknown-node"), "tags": TAGS}


def sis_bypass(patched, p, emit):
    if patched and p.get("approver_token") != "sis-4eyes-approval":
        deny(403, "SIS bypass requires 2-person (4-eyes) approval")
    if not patched:
        emit({"function": "SIS_HH_TRIP", "note": "safety instrumented trip bypassed without approval"})
    return {"sis_trip_enabled": False, "status": "safety interlock bypassed"}


def tank_gauge(patched, p, emit):
    if patched and p.get("authorization") != "Bearer engineering-station-token":
        deny(401, "HART write requires engineering workstation auth")
    if not patched:
        emit({"tank": p.get("tank", "T101"), "spoofed_level": p.get("level"), "note": "HART tank gauge spoofed"})
    return {"tank": p.get("tank", "T101"), "level_pct": p.get("level"), "status": "gauge updated"}



def ref_modbus_coil(patched, p, emit):
    if patched and p.get("authorization") != "Bearer eng-station":
        deny(401, "engineering workstation auth required for Modbus write")
    if not patched:
        emit({"note": "unauthenticated Modbus coil write to pump/valve"})
    return {"status": "ok", "vuln": "REF-004"}

def ref_historian_export(patched, p, emit):
    if patched and p.get("token") != "hist-signed":
        deny(403, "export path must be within allowlist")
    if not patched:
        emit({"note": "historian export path traversal (arbitrary file read)"})
    return {"status": "ok", "vuln": "REF-005"}


VULNS = [
    Vuln("REF-001", "/api/opcua/read", "GET", "OPC UA anonymous read",
         "red_attack_started", "initial_access", opcua_read),
    Vuln("REF-002", "/api/sis/bypass", "POST", "SIS safety bypass",
         "red_objective_success", "objective", sis_bypass),
    Vuln("REF-003", "/api/tankfarm/gauge", "POST", "HART tank gauge spoof",
         "red_attack_started", "lateral_movement", tank_gauge),
    Vuln("REF-004", "/api/modbus/coil-write", "POST", "Modbus coil write (pump/valve)",
         "red_objective_success", "objective", ref_modbus_coil),
    Vuln("REF-005", "/api/historian/export", "GET", "Historian export path traversal",
         "red_attack_started", "data_exfiltration", ref_historian_export),
]

app = make_ics_twin("refinery_plant", "Refinery/Petrochemical DCS/SIS Twin", VULNS)

# 실제 Modbus/TCP(P1-1) — 증류탑 압력 제어. HR0=압력설정(bar)·HR1=피드율·HR2=ACTUAL·HR4=DAMAGE.
# coil0=SIS(과압 릴리프 인터록). 인터록 해제 + 과압(>8bar) 지속 → 과압 폭발(asset_compromised).
from shared.ics.twin_modbus import attach_modbus_ics, ModbusIcsConfig  # noqa: E402
from shared.ics.safety import SafetyProfile  # noqa: E402
from shared.ics.anomaly import IcsBaseline, RegBand  # noqa: E402
from shared.ics.process_sim import ProcessParams  # noqa: E402

attach_modbus_ics(app, ModbusIcsConfig(
    asset="refinery_plant", vuln_id="REF-004",
    reg_names={0: "COLUMN_PRESSURE", 1: "FEED_RATE"},
    holding_init=[4, 50], coils_init=[True],
    cmd_reg=0, actual_reg=2, damage_reg=4, interlock_coil=0,
    safety=SafetyProfile(name="refinery_plant",
                         limits={0: {"name": "COLUMN_PRESSURE", "max": 8}}, interlock_coil=0),
    anomaly=IcsBaseline(name="refinery_plant",
                        registers={0: RegBand("COLUMN_PRESSURE", 3, 8, protected=True),
                                   1: RegBand("FEED_RATE", 0, 100)}, safety_coils={0}),
    proc=ProcessParams(slew_rpm_per_s=1, nominal_rpm=0, ambient_temp=0, k_heat=0.0, k_cool=0.0,
                       redline_rpm=8, crit_temp=1e9, damage_rpm_rate=2.0, damage_temp_rate=0.0,
                       failure_threshold=100),
    impact="overpressure_explosion"))

# 실 OPC UA/TCP(§5 실 프로토콜 확장) — DCS/SIS OPC UA 서버(포트 4840). HTTP 목업(REF-001)은
# 앱계층 태그 읽기를, 여기 실 OPC UA는 전송/보안채널 핸드셰이크(정찰·무단 접속)를 담당한다.
from shared.ics.twin_opcua import attach_opcua  # noqa: E402
attach_opcua(app, asset="refinery_plant", vuln_id="REF-001")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8201)
