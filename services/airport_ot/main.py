"""
Airport OT Digital Twin (공항 OT 트윈)
======================================
BHS(수하물처리) + 활주로 조명 + Fuel Farm + ATC Network + Terminal OT 를 모사.
훈련용 시뮬레이션(더미 값) — 실제 공항 설비와 무관.

취약점:
  AIR-001 Runway Lighting Control  (POST /api/runway/lighting)  — 활주로 조명 무단 제어(안전 임팩트)
  AIR-002 BHS Route Tamper (SQLi)  (GET  /api/bhs/route)        — 수하물 경로 SQL 인젝션
  AIR-003 Fuel Farm Valve Unauth   (POST /api/fuelfarm/valve)   — 급유 밸브 무단 조작
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402

BAG_ROUTES = {"BAG1001": "Gate-A12", "BAG1002": "Gate-B7"}


def runway_lighting(patched, p, emit):
    if patched and p.get("authorization") != "Bearer tower-ops-token":
        deny(401, "runway lighting control requires tower ops auth")
    if not patched:
        emit({"runway": p.get("runway", "15L"), "state": p.get("state"),
              "note": "runway lighting controlled without authorization"})
    return {"runway": p.get("runway", "15L"), "lighting": p.get("state", "off"), "status": "applied"}


def bhs_route(patched, p, emit):
    bid = p.get("bag_id", "")
    if patched:
        row = BAG_ROUTES.get(str(bid))
        return {"bag_id": bid, "route": row} if row else deny(404, "not found")
    if "'" in bid or "or" in bid.lower() or "union" in bid.lower():
        emit({"bag_id_input": bid, "note": "BHS routing SQL injection"})
        return {"bag_id": bid, "routes": BAG_ROUTES, "note": "injection returned all routes"}
    return {"bag_id": bid, "route": BAG_ROUTES.get(str(bid))}


def fuelfarm_valve(patched, p, emit):
    if patched and p.get("authorization") != "Bearer fuel-supervisor-token":
        deny(401, "fuel valve control requires supervisor auth")
    if not patched:
        emit({"valve": p.get("valve", "FV-3"), "action": p.get("action"),
              "note": "fuel farm valve operated without auth"})
    return {"valve": p.get("valve", "FV-3"), "action": p.get("action", "close"), "status": "valve command sent"}


VULNS = [
    Vuln("AIR-001", "/api/runway/lighting", "POST", "Runway lighting control",
         "red_objective_success", "objective", runway_lighting),
    Vuln("AIR-002", "/api/bhs/route", "GET", "BHS route SQLi",
         "flag_exfiltrated", "data_exfiltration", bhs_route),
    Vuln("AIR-003", "/api/fuelfarm/valve", "POST", "Fuel farm valve unauth",
         "red_attack_started", "lateral_movement", fuelfarm_valve),
]

app = make_ics_twin("airport_ot", "Airport BHS/Runway/Fuel Twin", VULNS)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8206)
