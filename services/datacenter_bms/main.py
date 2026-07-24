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


VULNS = [
    Vuln("DCX-001", "/api/crac/setpoint", "POST", "CRAC setpoint tamper",
         "red_objective_success", "objective", crac_setpoint),
    Vuln("DCX-002", "/api/ups/command", "POST", "UPS shutdown unauth",
         "red_objective_success", "objective", ups_command),
    Vuln("DCX-003", "/api/dcim/fetch", "POST", "DCIM SSRF",
         "red_attack_started", "lateral_movement", dcim_fetch),
]

app = make_ics_twin("datacenter_bms", "Data Center UPS/CRAC/DCIM Twin", VULNS)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8207)
