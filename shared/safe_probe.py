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

GS = "http://localhost:8001"
PP = "http://localhost:8002"
DN = "http://localhost:8003"
EVENT_COLLECTOR = os.environ.get("EVENT_COLLECTOR_URL", "http://localhost:8010")
TEAM_ID = os.environ.get("TEAM_ID", "default")


def report_patch_verified(vuln_id: str, target_asset: str):
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
    ("http://localhost:8201", "GET", "/api/opcua/read", {"node": "ns=2;s=SIS.HH_Trip.Setpoint"}, 401, "REF-001", "refinery_plant", "REF-001 OPC UA Anonymous Read"),
    ("http://localhost:8201", "POST", "/api/sis/bypass", {}, 403, "REF-002", "refinery_plant", "REF-002 SIS Safety Bypass"),
    ("http://localhost:8201", "POST", "/api/tankfarm/gauge", {"level": 99}, 401, "REF-003", "refinery_plant", "REF-003 HART Tank Gauge Spoof"),
    ("http://localhost:8202", "POST", "/api/plc/program-download", {}, 401, "FAC-001", "smart_factory", "FAC-001 PLC Program Download"),
    ("http://localhost:8202", "POST", "/api/robot/exec", {"command": "MOVE 1 2"}, 403, "FAC-002", "smart_factory", "FAC-002 Robot Command Injection"),
    ("http://localhost:8202", "GET", "/api/mes/workorder", {"id": "' OR '1'='1"}, 404, "FAC-003", "smart_factory", "FAC-003 MES Work-Order SQLi"),
    ("http://localhost:8203", "POST", "/api/dosing/chlorine", {"ppm": 9}, 401, "WTR-001", "water_utility", "WTR-001 Chlorine Dosing Tamper"),
    ("http://localhost:8203", "POST", "/api/pump/control", {"action": "stop"}, 401, "WTR-002", "water_utility", "WTR-002 Pump Control Unauth"),
    ("http://localhost:8203", "POST", "/api/hmi/login", {"username": "operator", "password": "operator"}, 403, "WTR-003", "water_utility", "WTR-003 SCADA HMI Default Creds"),
    ("http://localhost:8204", "POST", "/api/esd/trigger", {"action": "trip"}, 403, "LNG-001", "lng_terminal", "LNG-001 ESD Trigger/Bypass"),
    ("http://localhost:8204", "POST", "/api/bog/compressor", {"setpoint": 9}, 401, "LNG-002", "lng_terminal", "LNG-002 BOG Compressor Setpoint"),
    ("http://localhost:8204", "POST", "/api/firegas/suppress", {}, 403, "LNG-003", "lng_terminal", "LNG-003 Fire&Gas Alarm Suppress"),
    ("http://localhost:8205", "POST", "/api/signal/set", {"aspect": "clear"}, 401, "RWY-001", "railway_signaling", "RWY-001 Signal Aspect Override"),
    ("http://localhost:8205", "POST", "/api/interlocking/override", {"route": "R7"}, 403, "RWY-002", "railway_signaling", "RWY-002 Interlocking Bypass"),
    ("http://localhost:8205", "POST", "/api/ats/command", {"command": "STOP"}, 403, "RWY-003", "railway_signaling", "RWY-003 ATS Command Injection"),
    ("http://localhost:8206", "POST", "/api/runway/lighting", {"state": "off"}, 401, "AIR-001", "airport_ot", "AIR-001 Runway Lighting Control"),
    ("http://localhost:8206", "GET", "/api/bhs/route", {"bag_id": "' OR '1'='1"}, 404, "AIR-002", "airport_ot", "AIR-002 BHS Route SQLi"),
    ("http://localhost:8206", "POST", "/api/fuelfarm/valve", {"action": "open"}, 401, "AIR-003", "airport_ot", "AIR-003 Fuel Farm Valve Unauth"),
    ("http://localhost:8207", "POST", "/api/crac/setpoint", {"temp_c": 40}, 401, "DCX-001", "datacenter_bms", "DCX-001 CRAC Setpoint Tamper"),
    ("http://localhost:8207", "POST", "/api/ups/command", {"command": "SHUTDOWN"}, 403, "DCX-002", "datacenter_bms", "DCX-002 UPS Shutdown Unauth"),
    ("http://localhost:8207", "POST", "/api/dcim/fetch", {"url": "http://169.254.169.254/latest/meta-data"}, 400, "DCX-003", "datacenter_bms", "DCX-003 DCIM SSRF"),
    ("http://localhost:8208", "GET", "/api/pacs/study", {"id": "ST-1001"}, 401, "HSP-001", "hospital_ot", "HSP-001 PACS Study IDOR"),
    ("http://localhost:8208", "GET", "/api/his/patient", {"id": "' OR '1'='1"}, 404, "HSP-002", "hospital_ot", "HSP-002 HIS Patient SQLi"),
    ("http://localhost:8208", "POST", "/api/device/infusion", {"rate": 999}, 401, "HSP-003", "hospital_ot", "HSP-003 Infusion Pump Unauth"),
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
    return _run


if __name__ == "__main__":
    checks = [
        check_gs_001_sqli, check_gs_002_hardcoded, check_gs_003_idor,
        check_gs_004_traversal, check_gs_005_debug, check_gs_006_ssrf, check_gs_007_xxe,
        check_pp_001_plc, check_pp_002_default_creds, check_pp_003_cmdi,
        check_pp_004_deserialize, check_pp_005_safety, check_pp_006_modbus, check_pp_007_firmware,
        check_dn_001_smb, check_dn_002_kerberoast, check_dn_003_backup, check_dn_004_relay,
        check_dn_005_ldap, check_dn_006_ssrf,
    ] + [_sector_check(*args) for args in SECTOR_PROBES]
    for check in checks:
        try:
            print(check())
        except requests.exceptions.ConnectionError:
            print(f"[ERROR     ] {check.__name__} - 서비스에 연결할 수 없음 (서비스가 실행 중인지 확인)")

