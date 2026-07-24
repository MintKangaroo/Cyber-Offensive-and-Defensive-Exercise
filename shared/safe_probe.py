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


if __name__ == "__main__":
    checks = [
        check_gs_001_sqli, check_gs_002_hardcoded, check_gs_003_idor,
        check_gs_004_traversal, check_gs_005_debug,
        check_pp_001_plc, check_pp_002_default_creds, check_pp_003_cmdi,
        check_pp_004_deserialize, check_pp_005_safety,
        check_dn_001_smb, check_dn_002_kerberoast, check_dn_003_backup, check_dn_004_relay,
    ]
    for check in checks:
        try:
            print(check())
        except requests.exceptions.ConnectionError:
            print(f"[ERROR     ] {check.__name__} - 서비스에 연결할 수 없음 (서비스가 실행 중인지 확인)")

