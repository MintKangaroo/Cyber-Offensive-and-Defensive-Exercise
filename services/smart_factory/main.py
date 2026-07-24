"""
Smart Factory Digital Twin (스마트팩토리 트윈)
==============================================
PLC + Robot + MES + Conveyor 를 모사. 프로토콜: Profinet / S7 / OPC UA.
Vendor 예시: Siemens/Rockwell/Mitsubishi. 훈련용 시뮬레이션(더미 값).

취약점:
  FAC-001 PLC Program Download    (POST /api/plc/program-download) — 미인증 PLC 프로그램 다운로드(ICS)
  FAC-002 Robot Command Injection (POST /api/robot/exec)           — 로봇 컨트롤러 임의 명령
  FAC-003 MES Work-Order SQLi     (GET  /api/mes/workorder)        — MES 작업지시 SQL 인젝션
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402

WORKORDERS = {"1001": "Line-A Bracket x500", "1002": "Line-B Gearbox x120"}


def plc_program_download(patched, p, emit):
    if patched and p.get("authorization") != "Bearer engineering-station-token":
        deny(401, "PLC program download requires engineering workstation auth")
    if not patched:
        emit({"plc": p.get("plc", "S7-1500"), "block": p.get("block", "OB1"),
              "note": "unauthenticated PLC program (logic) download"})
    return {"plc": p.get("plc", "S7-1500"), "status": "program block downloaded to controller"}


def robot_exec(patched, p, emit):
    cmd = p.get("command", "")
    if patched and cmd not in ("HOME", "PAUSE", "STATUS"):
        deny(403, "robot command not in allowlist")
    if not patched:
        emit({"command": cmd, "note": "arbitrary robot controller command"})
    return {"command": cmd, "status": "executed on robot controller"}


def mes_workorder(patched, p, emit):
    wid = p.get("id", "")
    if patched:
        row = WORKORDERS.get(str(wid))
        return {"id": wid, "workorder": row} if row else deny(404, "not found")
    # 취약: id를 쿼리에 문자열 결합 -> ' OR '1'='1 로 전체 덤프
    if "'" in wid or "or" in wid.lower() or "union" in wid.lower():
        emit({"id_input": wid, "note": "MES work-order SQL injection"})
        return {"id": wid, "workorders": WORKORDERS, "note": "injection returned all rows"}
    return {"id": wid, "workorder": WORKORDERS.get(str(wid))}


VULNS = [
    Vuln("FAC-001", "/api/plc/program-download", "POST", "PLC program download",
         "red_attack_started", "lateral_movement", plc_program_download),
    Vuln("FAC-002", "/api/robot/exec", "POST", "Robot command injection",
         "red_attack_started", "privilege_escalation", robot_exec),
    Vuln("FAC-003", "/api/mes/workorder", "GET", "MES work-order SQLi",
         "flag_exfiltrated", "data_exfiltration", mes_workorder),
]

app = make_ics_twin("smart_factory", "Smart Factory PLC/Robot/MES Twin", VULNS)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8202)
