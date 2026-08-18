"""
Safe Probe for Patch Verification Manager
------------------------------------------
각 디지털 트윈의 취약점이 patched / vulnerable 상태인지 안전하게 판정합니다.
실제 익스플로잇 페이로드를 던지지 않고, 응답 코드/필드로만 상태를 추론합니다.
(제안서 6장 "Safe Probe: HTTP 상태 확인, 서비스 응답 확인, 인증 요구 여부 확인"에 대응)

패치가 확인되면 Event Collector에 blue_patch_verified 이벤트를 발행하여
Scoring Engine이 Blue Team 점수를 자동으로 적립하도록 합니다.

사용법:
    TEAM_ID=team_alpha python safe_probe.py
"""

import os
import time
import uuid
import requests

# 프로브 타깃은 env 주입으로 결정한다. 과거 고정 호스트 리터럴을 박아 두어 컨테이너/원격
# 호스트에서 무조건 '도달 불가'가 되던 문제(허위 안전 보증의 한 축)를 제거한다.
# PROBE_HOST 로 호스트를 바꾸고(기본 127.0.0.1), 필요하면 서비스별 *_URL 로 개별 오버라이드한다.
PROBE_HOST = os.environ.get("PROBE_HOST", "127.0.0.1").strip() or "127.0.0.1"


def _u(port: int) -> str:
    return f"http://{PROBE_HOST}:{port}"


GS = os.environ.get("GS_URL", "").strip() or _u(8001)
PP = os.environ.get("PP_URL", "").strip() or _u(8002)
DN = os.environ.get("DN_URL", "").strip() or _u(8003)
EVENT_COLLECTOR = os.environ.get("EVENT_COLLECTOR_URL", "").strip() or _u(8010)
TEAM_ID = os.environ.get("TEAM_ID", "default")

# 구조화 결과 캡처(프로그램 API/요약/테스트용) — status()가 각 판정을 여기에 누적.
# _EMIT_ENABLED=False면 blue_patch_verified 발행을 억제(재검증 dry-run·테스트 격리).
_RESULTS: list[dict] = []
_EMIT_ENABLED = True


def report_patch_verified(vuln_id: str, target_asset: str):
    if not _EMIT_ENABLED:
        return
    event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{TEAM_ID}:{target_asset}:{vuln_id}:patch_verified"))
    payload = {
        "event_id": event_id,
        "event_type": "blue_patch_verified",
        "timestamp": time.time(),
        "actor": "blue",
        "team_id": TEAM_ID,
        "scenario_id": "default",
        "target_asset": target_asset,
        "vuln_id": vuln_id,
        "phase": None,
        "metadata": {"verified_by": "safe_probe"},
    }
    try:
        requests.post(f"{EVENT_COLLECTOR}/events", json=payload, timeout=2.0)
    except requests.exceptions.RequestException:
        pass  # Event Collector 다운이어도 probe 결과 자체는 출력


def status(name, ok, vuln_id=None, target_asset=None):
    if vuln_id and target_asset:
        _RESULTS.append({"name": name, "vuln_id": vuln_id, "asset": target_asset,
                         "patched": bool(ok), "reachable": True})
    if ok and vuln_id and target_asset:
        report_patch_verified(vuln_id, target_asset)
    return f"[{'PATCHED' if ok else 'VULNERABLE':<10}] {name}"


def check_gs_001_sqli():
    # 안전한 방식: 실제 injection payload 대신 sensor_id에 작은따옴표만 넣어 500 여부만 확인
    r = requests.get(f"{GS}/api/telemetry", params={"sensor_id": "SOL-PANEL-1' --"})
    patched = r.status_code == 200 and r.json().get("results") == []
    return status("GS-001 Telemetry SQLi", patched, "GS-001", "ground_station")


def check_gs_002_hardcoded():
    r = requests.post(f"{GS}/api/login", json={"username": "admin", "password": "admin123"})
    patched = r.status_code == 401
    return status("GS-002 Hardcoded Admin Creds", patched, "GS-002", "ground_station")


def check_gs_003_idor():
    r = requests.get(f"{GS}/api/mission-plan/2", headers={"Authorization": "Bearer invalid"})
    patched = r.status_code in (401, 403)
    return status("GS-003 Mission Plan IDOR", patched, "GS-003", "ground_station")


def check_gs_004_traversal():
    r = requests.get(f"{GS}/api/download", params={"file": "../secret/satellite_key_dummy.txt"})
    patched = r.status_code in (400, 404)
    return status("GS-004 Download Path Traversal", patched, "GS-004", "ground_station")


def check_gs_005_debug():
    r = requests.get(f"{GS}/api/debug/config")
    patched = r.status_code == 404
    return status("GS-005 Debug Config Exposure", patched, "GS-005", "ground_station")


def check_gs_006_ssrf():
    r = requests.post(f"{GS}/api/tle/import", json={"url": "http://169.254.169.254/latest/meta-data"})
    patched = r.status_code == 400
    return status("GS-006 TLE Import SSRF", patched, "GS-006", "ground_station")


def check_gs_007_xxe():
    xml = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
    r = requests.post(f"{GS}/api/config/xml-import", json={"xml": xml})
    patched = r.status_code == 400
    return status("GS-007 Config XML XXE", patched, "GS-007", "ground_station")


def check_pp_001_plc():
    r = requests.post(f"{PP}/api/plc/write", json={"register": "TURBINE_RPM", "value": 9999})
    patched = r.status_code == 401
    return status("PP-001 Unauth PLC Write", patched, "PP-001", "power_plant")


def check_pp_002_default_creds():
    r = requests.post(f"{PP}/api/hmi/login", json={"username": "operator", "password": "operator"})
    patched = r.status_code == 403
    return status("PP-002 Default HMI Creds", patched, "PP-002", "power_plant")


def check_pp_003_cmdi():
    r = requests.post(f"{PP}/api/diagnostics/ping", json={"host": "127.0.0.1; echo PROBE"})
    patched = r.status_code == 400
    return status("PP-003 Diagnostics Cmd Injection", patched, "PP-003", "power_plant")


def check_pp_004_deserialize():
    import base64
    payload = base64.b64encode(b"not-a-real-pickle").decode()
    r = requests.post(f"{PP}/api/historian/export", json={"payload_b64": payload})
    patched = r.status_code == 400 and "disabled" in r.text
    return status("PP-004 Historian Deserialization", patched, "PP-004", "power_plant")


def check_pp_005_safety():
    r = requests.post(f"{PP}/api/safety/override", json={"override": True})
    patched = r.status_code == 403
    return status("PP-005 Safety Override Bypass", patched, "PP-005", "power_plant")


def check_pp_006_modbus():
    r = requests.post(f"{PP}/api/modbus/write-register", json={"register": "EMERGENCY_SHUTDOWN", "value": True})
    patched = r.status_code in (401, 403)
    return status("PP-006 Unauth Modbus Write", patched, "PP-006", "power_plant")


def check_pp_007_firmware():
    import base64
    fw = base64.b64encode(b"MALICIOUS_FW").decode()
    r = requests.post(f"{PP}/api/plc/firmware-update", json={"version": "9.9.9", "firmware_b64": fw})
    patched = r.status_code in (401, 403)
    return status("PP-007 Unsigned Firmware Update", patched, "PP-007", "power_plant")


def check_dn_001_smb():
    r = requests.get(f"{DN}/api/smb/shares")
    patched = r.status_code == 401
    return status("DN-001 SMB Anonymous Access", patched, "DN-001", "defense_network")


def check_dn_002_kerberoast():
    r = requests.get(f"{DN}/api/ad/service-accounts")
    patched = r.status_code == 401
    return status("DN-002 Kerberoastable Account", patched, "DN-002", "defense_network")


def check_dn_003_backup():
    r = requests.get(f"{DN}/api/fileserver/backup-config")
    patched = r.status_code == 404
    return status("DN-003 Backup Config Exposure", patched, "DN-003", "defense_network")


def check_dn_004_relay():
    r = requests.post(f"{DN}/api/mail/relay", json={
        "mail_from": "attacker@evil.dummy", "mail_to": "victim@internal.dummy",
        "subject": "test", "body": "test", "authenticated": False,
    })
    patched = r.status_code == 401
    return status("DN-004 Open Mail Relay", patched, "DN-004", "defense_network")


def check_dn_005_ldap():
    r = requests.get(f"{DN}/api/directory/search", params={"q": "*)(uid=*"})
    patched = r.status_code == 400
    return status("DN-005 Directory LDAP Injection", patched, "DN-005", "defense_network")


def check_dn_006_ssrf():
    r = requests.post(f"{DN}/api/webhook/preview", json={"url": "http://169.254.169.254/latest/meta-data"})
    patched = r.status_code == 400
    return status("DN-006 URL Preview SSRF", patched, "DN-006", "defense_network")


# ---------------------------------------------------------------------------
# ICS/OT 확장 섹터 트윈 프로브(데이터 기반) — 정유/스마트팩토리/수도/LNG/철도/공항/데이터센터/병원
# 각 항목: (base, method, path, params_or_json, patched_status, vuln_id, asset, name)
# 취약(unpatched) 기본 상태는 200을 반환, 패치 시 patched_status(401/403/400/404)로 거부.
# ---------------------------------------------------------------------------
SECTOR_PROBES = [
    (_u(8201), "GET", "/api/opcua/read", {"node": "ns=2;s=SIS.HH_Trip.Setpoint"}, 401, "REF-001", "refinery_plant", "REF-001 OPC UA Anonymous Read"),
    (_u(8201), "POST", "/api/sis/bypass", {}, 403, "REF-002", "refinery_plant", "REF-002 SIS Safety Bypass"),
    (_u(8201), "POST", "/api/tankfarm/gauge", {"level": 99}, 401, "REF-003", "refinery_plant", "REF-003 HART Tank Gauge Spoof"),
    (_u(8202), "POST", "/api/plc/program-download", {}, 401, "FAC-001", "smart_factory", "FAC-001 PLC Program Download"),
    (_u(8202), "POST", "/api/robot/exec", {"command": "MOVE 1 2"}, 403, "FAC-002", "smart_factory", "FAC-002 Robot Command Injection"),
    (_u(8202), "GET", "/api/mes/workorder", {"id": "' OR '1'='1"}, 404, "FAC-003", "smart_factory", "FAC-003 MES Work-Order SQLi"),
    (_u(8203), "POST", "/api/dosing/chlorine", {"ppm": 9}, 401, "WTR-001", "water_utility", "WTR-001 Chlorine Dosing Tamper"),
    (_u(8203), "POST", "/api/pump/control", {"action": "stop"}, 401, "WTR-002", "water_utility", "WTR-002 Pump Control Unauth"),
    (_u(8203), "POST", "/api/hmi/login", {"username": "operator", "password": "operator"}, 403, "WTR-003", "water_utility", "WTR-003 SCADA HMI Default Creds"),
    (_u(8204), "POST", "/api/esd/trigger", {"action": "trip"}, 403, "LNG-001", "lng_terminal", "LNG-001 ESD Trigger/Bypass"),
    (_u(8204), "POST", "/api/bog/compressor", {"setpoint": 9}, 401, "LNG-002", "lng_terminal", "LNG-002 BOG Compressor Setpoint"),
    (_u(8204), "POST", "/api/firegas/suppress", {}, 403, "LNG-003", "lng_terminal", "LNG-003 Fire&Gas Alarm Suppress"),
    (_u(8205), "POST", "/api/signal/set", {"aspect": "clear"}, 401, "RWY-001", "railway_signaling", "RWY-001 Signal Aspect Override"),
    (_u(8205), "POST", "/api/interlocking/override", {"route": "R7"}, 403, "RWY-002", "railway_signaling", "RWY-002 Interlocking Bypass"),
    (_u(8205), "POST", "/api/ats/command", {"command": "STOP"}, 403, "RWY-003", "railway_signaling", "RWY-003 ATS Command Injection"),
    (_u(8206), "POST", "/api/runway/lighting", {"state": "off"}, 401, "AIR-001", "airport_ot", "AIR-001 Runway Lighting Control"),
    (_u(8206), "GET", "/api/bhs/route", {"bag_id": "' OR '1'='1"}, 404, "AIR-002", "airport_ot", "AIR-002 BHS Route SQLi"),
    (_u(8206), "POST", "/api/fuelfarm/valve", {"action": "open"}, 401, "AIR-003", "airport_ot", "AIR-003 Fuel Farm Valve Unauth"),
    (_u(8207), "POST", "/api/crac/setpoint", {"temp_c": 40}, 401, "DCX-001", "datacenter_bms", "DCX-001 CRAC Setpoint Tamper"),
    (_u(8207), "POST", "/api/ups/command", {"command": "SHUTDOWN"}, 403, "DCX-002", "datacenter_bms", "DCX-002 UPS Shutdown Unauth"),
    (_u(8207), "POST", "/api/dcim/fetch", {"url": "http://169.254.169.254/latest/meta-data"}, 400, "DCX-003", "datacenter_bms", "DCX-003 DCIM SSRF"),
    (_u(8208), "GET", "/api/pacs/study", {"id": "ST-1001"}, 401, "HSP-001", "hospital_ot", "HSP-001 PACS Study IDOR"),
    (_u(8208), "GET", "/api/his/patient", {"id": "' OR '1'='1"}, 404, "HSP-002", "hospital_ot", "HSP-002 HIS Patient SQLi"),
    (_u(8208), "POST", "/api/device/infusion", {"rate": 999}, 401, "HSP-003", "hospital_ot", "HSP-003 Infusion Pump Unauth"),

    (_u(8201), "POST", "/api/modbus/coil-write", {}, 401, "REF-004", "refinery_plant", "REF-004 Modbus coil write (pump/valve)"),
    (_u(8201), "GET", "/api/historian/export", {"id": "1"}, 403, "REF-005", "refinery_plant", "REF-005 Historian export path traversal"),
    (_u(8202), "POST", "/api/robot/estop-override", {}, 403, "FAC-004", "smart_factory", "FAC-004 Robot E-stop override"),
    (_u(8202), "GET", "/api/recipe/get", {"id": "1"}, 404, "FAC-005", "smart_factory", "FAC-005 MES recipe SQL injection"),
    (_u(8203), "POST", "/api/tank/setpoint", {}, 401, "WTR-004", "water_utility", "WTR-004 Reservoir setpoint tamper"),
    (_u(8203), "POST", "/api/report/fetch", {}, 400, "WTR-005", "water_utility", "WTR-005 Report fetch SSRF"),
    (_u(8204), "POST", "/api/tank/gauge", {}, 401, "LNG-004", "lng_terminal", "LNG-004 LNG tank gauge spoof"),
    (_u(8204), "POST", "/api/compressor/firmware", {}, 403, "LNG-005", "lng_terminal", "LNG-005 BOG compressor firmware upload"),
    (_u(8205), "POST", "/api/balise/telegram", {}, 401, "RWY-004", "railway_signaling", "RWY-004 Balise telegram write"),
    (_u(8205), "GET", "/api/timetable/get", {"id": "1"}, 401, "RWY-005", "railway_signaling", "RWY-005 Timetable IDOR"),
    (_u(8206), "POST", "/api/jetbridge/control", {}, 401, "AIR-004", "airport_ot", "AIR-004 Jet bridge control"),
    (_u(8206), "POST", "/api/fids/message", {}, 403, "AIR-005", "airport_ot", "AIR-005 FIDS content injection"),
    (_u(8207), "POST", "/api/generator/control", {}, 403, "DCX-004", "datacenter_bms", "DCX-004 Generator start/stop"),
    (_u(8207), "POST", "/api/access/door", {}, 401, "DCX-005", "datacenter_bms", "DCX-005 Access control door unlock"),
    (_u(8208), "POST", "/api/dicom/store", {}, 401, "HSP-004", "hospital_ot", "HSP-004 DICOM C-STORE overwrite"),
    (_u(8208), "POST", "/api/nursecall/override", {}, 403, "HSP-005", "hospital_ot", "HSP-005 Nurse call override"),
]


def _sector_check(base, method, path, data, patched_status, vuln_id, asset, name):
    def _run():
        if method == "GET":
            r = requests.get(f"{base}{path}", params=data, timeout=3)
        else:
            r = requests.post(f"{base}{path}", json=data, timeout=3)
        patched = r.status_code == patched_status
        return status(name, patched, vuln_id, asset)
    _run.__name__ = f"check_{vuln_id.replace('-', '_').lower()}"
    _run.meta = (vuln_id, asset, name)  # 연결 실패 시 UNREACHABLE 결과 조립용
    return _run


# ---------------------------------------------------------------------------
# 섹터별 체크 레지스트리 — blue 팀이 "자기 섹터만" 재검증할 수 있게 자산 키로 그룹핑.
# 핵심 3종(GS/PP/DN)은 개별 함수, 신규 8섹터는 SECTOR_PROBES에서 자산별로 자동 분류.
# ---------------------------------------------------------------------------
CHECKS_BY_ASSET: dict[str, list] = {
    "ground_station": [check_gs_001_sqli, check_gs_002_hardcoded, check_gs_003_idor,
                       check_gs_004_traversal, check_gs_005_debug, check_gs_006_ssrf, check_gs_007_xxe],
    "power_plant": [check_pp_001_plc, check_pp_002_default_creds, check_pp_003_cmdi,
                    check_pp_004_deserialize, check_pp_005_safety, check_pp_006_modbus, check_pp_007_firmware],
    "defense_network": [check_dn_001_smb, check_dn_002_kerberoast, check_dn_003_backup,
                        check_dn_004_relay, check_dn_005_ldap, check_dn_006_ssrf],
}
for _spec in SECTOR_PROBES:
    CHECKS_BY_ASSET.setdefault(_spec[6], []).append(_sector_check(*_spec))

# 핵심 3종(GS/PP/DN)은 개별 함수라 meta를 별도로 부착한다(연결 실패 시 UNREACHABLE 조립용).
_CORE_META = {
    check_gs_001_sqli: ("GS-001", "ground_station", "GS-001 Telemetry SQLi"),
    check_gs_002_hardcoded: ("GS-002", "ground_station", "GS-002 Hardcoded Admin Creds"),
    check_gs_003_idor: ("GS-003", "ground_station", "GS-003 Mission Plan IDOR"),
    check_gs_004_traversal: ("GS-004", "ground_station", "GS-004 Download Path Traversal"),
    check_gs_005_debug: ("GS-005", "ground_station", "GS-005 Debug Config Exposure"),
    check_gs_006_ssrf: ("GS-006", "ground_station", "GS-006 TLE Import SSRF"),
    check_gs_007_xxe: ("GS-007", "ground_station", "GS-007 Config XML XXE"),
    check_pp_001_plc: ("PP-001", "power_plant", "PP-001 Unauth PLC Write"),
    check_pp_002_default_creds: ("PP-002", "power_plant", "PP-002 Default HMI Creds"),
    check_pp_003_cmdi: ("PP-003", "power_plant", "PP-003 Diagnostics Cmd Injection"),
    check_pp_004_deserialize: ("PP-004", "power_plant", "PP-004 Historian Deserialization"),
    check_pp_005_safety: ("PP-005", "power_plant", "PP-005 Safety Override Bypass"),
    check_pp_006_modbus: ("PP-006", "power_plant", "PP-006 Unauth Modbus Write"),
    check_pp_007_firmware: ("PP-007", "power_plant", "PP-007 Unsigned Firmware Update"),
    check_dn_001_smb: ("DN-001", "defense_network", "DN-001 SMB Anonymous Access"),
    check_dn_002_kerberoast: ("DN-002", "defense_network", "DN-002 Kerberoastable Account"),
    check_dn_003_backup: ("DN-003", "defense_network", "DN-003 Backup Config Exposure"),
    check_dn_004_relay: ("DN-004", "defense_network", "DN-004 Open Mail Relay"),
    check_dn_005_ldap: ("DN-005", "defense_network", "DN-005 Directory LDAP Injection"),
    check_dn_006_ssrf: ("DN-006", "defense_network", "DN-006 URL Preview SSRF"),
}
for _fn, _m in _CORE_META.items():
    _fn.meta = _m

# 안정적 자산 순서(핵심 3종 → 신규 8섹터).
ASSET_ORDER = ["ground_station", "power_plant", "defense_network", "refinery_plant",
               "smart_factory", "water_utility", "lng_terminal", "railway_signaling",
               "airport_ot", "datacenter_bms", "hospital_ot"]


def run(asset: str | None = None, emit: bool = True) -> dict:
    """섹터 스코프 자동 패치검증. asset=None이면 전체 11섹터.
    emit=False면 blue_patch_verified 발행을 억제(재검증 dry-run). 구조화 결과를 반환.

    반환: {"results": [{name,vuln_id,asset,patched,reachable}...], "errors": [...],
           "summary": {"total","patched","vulnerable","unreachable",
                       "by_asset":{asset:{patched,total,unreachable}}}}

    ⚠️ 연결 실패(트윈/서비스 다운·미배포)한 항목은 결과에서 조용히 빠지지 않고
    patched=None·reachable=False 인 **UNREACHABLE 결과**로 편입된다. 이것이 있으면
    verify-baseline 이 '검증 불가'로 실패해야 한다(도달성을 확인하지 못한 걸 통과로 위장 금지).
    """
    global _EMIT_ENABLED
    prev, _EMIT_ENABLED = _EMIT_ENABLED, emit
    _RESULTS.clear()
    errors: list[str] = []
    assets = [asset] if asset else ASSET_ORDER
    try:
        for a in assets:
            for check in CHECKS_BY_ASSET.get(a, []):
                try:
                    check()
                except requests.exceptions.RequestException:
                    meta = getattr(check, "meta", None)
                    if meta:
                        vid, ast, nm = meta
                    else:  # meta 미부착(방어적) — 함수명으로 대체
                        vid, ast, nm = getattr(check, "__name__", "?"), a, getattr(check, "__name__", "?")
                    _RESULTS.append({"name": nm, "vuln_id": vid, "asset": ast,
                                     "patched": None, "reachable": False})
                    errors.append(f"{a}:{vid} 연결 불가(UNREACHABLE)")
    finally:
        _EMIT_ENABLED = prev
    results = list(_RESULTS)
    by_asset: dict[str, dict] = {}
    for r in results:
        b = by_asset.setdefault(r["asset"], {"patched": 0, "total": 0, "unreachable": 0})
        b["total"] += 1
        if r.get("reachable", True):
            b["patched"] += int(bool(r["patched"]))
        else:
            b["unreachable"] += 1
    patched = sum(1 for r in results if r.get("reachable", True) and r["patched"])
    unreachable = sum(1 for r in results if not r.get("reachable", True))
    # vulnerable = 도달했으나 패치 안 됨(UNREACHABLE은 vulnerable도 patched도 아님).
    vulnerable = sum(1 for r in results if r.get("reachable", True) and not r["patched"])
    return {"results": results, "errors": errors,
            "summary": {"total": len(results), "patched": patched,
                        "vulnerable": vulnerable, "unreachable": unreachable,
                        "by_asset": by_asset}}


def _print_watch_cycle(cycle: int, out: dict, newly: set, regressed: set) -> None:
    ts = time.strftime("%H:%M:%S")
    s = out["summary"]
    line = f"[{ts}] #{cycle} 패치 {s['patched']}/{s['total']}"
    if newly:
        line += f" · ✅신규패치 {','.join(sorted(newly))}"
    if regressed:
        line += f" · ⚠️회귀 {','.join(sorted(regressed))}"
    if s.get("unreachable"):
        line += f" · ⛔UNREACHABLE {s['unreachable']}"
    print(line, flush=True)


def watch(interval: float = 30.0, asset: str | None = None, emit: bool = True,
          iterations: int | None = None, on_cycle=None) -> int:
    """주기적 재검증 데몬(호스트 사이드). blue 패치가 반영되면 그 사이클에서
    blue_patch_verified(+50)를 발행하고, 직전 사이클 대비 **새로 patched/회귀**된 취약점을
    델타로 보고한다. iterations=None이면 무한(Ctrl-C까지), 정수면 그 횟수만(테스트/유한 실행).
    on_cycle(cycle, out, newly)가 주어지면 각 사이클마다 호출(연동/테스트용). 실행 사이클 수 반환.

    참고: 연결 실패(서비스 다운)한 취약점은 결과에서 빠지므로 '회귀'로 오탐하지 않도록,
    회귀는 이번 사이클에 실제로 probe된 취약점에 한해 판정한다."""
    prev_patched: set[str] = set()
    i = 0
    while iterations is None or i < iterations:
        i += 1
        out = run(asset=asset, emit=emit)
        # UNREACHABLE(도달 실패)은 '이번에 판정 못 함'이므로 probed에서 제외 → 회귀 오탐 방지.
        probed = {r["vuln_id"] for r in out["results"] if r.get("reachable", True)}
        now_patched = {r["vuln_id"] for r in out["results"] if r.get("reachable", True) and r["patched"]}
        newly = now_patched - prev_patched
        regressed = (prev_patched & probed) - now_patched
        # prev는 probe된 것만 갱신(다운된 취약점의 이전 상태는 보존)
        prev_patched = (prev_patched - probed) | now_patched
        if on_cycle:
            on_cycle(i, out, newly)
        else:
            _print_watch_cycle(i, out, newly, regressed)
        if iterations is None or i < iterations:
            time.sleep(interval)
    return i


if __name__ == "__main__":
    import argparse
    import json as _json
    import sys

    ap = argparse.ArgumentParser(description="섹터별 blue 자동 패치검증(Safe Probe)")
    ap.add_argument("--asset", choices=ASSET_ORDER, help="특정 섹터만 재검증(미지정 시 전체)")
    ap.add_argument("--no-emit", action="store_true", help="blue_patch_verified 발행 억제(dry-run)")
    ap.add_argument("--summary", action="store_true", help="줄별 결과 대신 섹터 요약만 출력")
    ap.add_argument("--json", action="store_true", help="JSON으로 출력(자동화/대시보드 연동용)")
    ap.add_argument("--watch", type=float, metavar="SEC",
                    help="주기적 재검증 데몬 모드(SEC초 간격). 패치 반영 시 실시간 발행+델타 보고")
    ap.add_argument("--max-iterations", type=int, default=None,
                    help="--watch 사이클 수 제한(미지정 시 무한, Ctrl-C까지)")
    args = ap.parse_args()

    if args.watch is not None:
        emoji = "dry-run" if args.no_emit else "발행"
        scope = args.asset or "전체 11섹터"
        print(f"🔁 자동 재검증 데몬 시작 — {scope}, {args.watch}s 간격, blue_patch_verified {emoji}. Ctrl-C 종료.")
        try:
            watch(interval=args.watch, asset=args.asset, emit=not args.no_emit,
                  iterations=args.max_iterations)
        except KeyboardInterrupt:
            print("\n종료.")
        sys.exit(0)

    out = run(asset=args.asset, emit=not args.no_emit)

    if args.json:
        print(_json.dumps(out, ensure_ascii=False, indent=2))
    else:
        if not args.summary:
            for r in out["results"]:
                lbl = "UNREACHABLE" if not r.get("reachable", True) else ("PATCHED" if r["patched"] else "VULNERABLE")
                print(f"[{lbl:<11}] {r['name']}")
        s = out["summary"]
        print("=" * 62)
        for a in ASSET_ORDER:
            b = s["by_asset"].get(a)
            if b:
                extra = f" · ⛔{b['unreachable']} unreachable" if b.get("unreachable") else ""
                print(f"  {a:<18} 패치 {b['patched']}/{b['total']}{extra}")
        print(f"  전체 {s['patched']}/{s['total']} patched · {s['vulnerable']} vulnerable · "
              f"{s['unreachable']} unreachable")
        for e in out["errors"]:
            print(f"  [ERROR] {e}")
        print("=" * 62)

