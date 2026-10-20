"""ICS 트윈 라이브파이어 텔레메트리 회귀 테스트.

livefire-ops 작전 콘솔이 발전소뿐 아니라 병원·상수도 등 연속 물리 트윈의 게이지도 라이브로
움직이려면 각 트윈이 /api/telemetry(통일 규약)를 내고, HTTP 공격이 실제 물리 명령 레지스터에
도달해야 한다. 대표 트윈 2개(hospital_ot·water_utility)로 고정한다.

통일 규약: {asset, cmd, cmd_name, actual, actual_name, damage, interlock, failed, redline, registers[]}
  - attach_modbus_ics 기반 6개 트윈(hospital/refinery/lng/smart_factory/airport/datacenter)은
    공유 헬퍼가 /api/telemetry 를 자동 노출 → hospital_ot 로 대표 검증.
  - water_utility 는 전용 뱅크 → 자체 /api/telemetry.
"""
import os

os.environ.setdefault("MODBUS_ENABLED", "0")          # 테스트에서 502 리스너 불필요
os.environ.setdefault("RBAC_ALLOW_INSECURE_DEV", "true")

import pytest
from fastapi.testclient import TestClient

from services.hospital_ot import main as hospital
from services.water_utility import main as water

_REQUIRED_KEYS = {"asset", "cmd", "cmd_name", "actual", "actual_name",
                  "damage", "interlock", "failed", "redline", "registers"}

# (모듈, 공격 경로, 공격 바디, cmd 로 기대되는 값, 예상 cmd_name)
CASES = [
    (hospital, "/api/device/infusion", {"device": "PUMP-07", "rate": 900}, 900, "INFUSION_RATE"),
    (water, "/api/dosing/chlorine", {"ppm": 12}, 12, "CHLORINE_PPM"),
]


@pytest.mark.parametrize("mod,_p,_b,_v,cmd_name", CASES)
def test_telemetry_uniform_contract(mod, _p, _b, _v, cmd_name):
    c = TestClient(mod.app)
    t = c.get("/api/telemetry").json()
    assert _REQUIRED_KEYS.issubset(t.keys()), f"누락 키: {_REQUIRED_KEYS - set(t.keys())}"
    assert t["cmd_name"] == cmd_name
    assert isinstance(t["registers"], list) and len(t["registers"]) >= 2
    for r in t["registers"]:
        assert {"addr", "name", "value"}.issubset(r.keys())
    assert isinstance(t["interlock"], bool)


@pytest.mark.parametrize("mod,path,body,expected_cmd,_n", CASES)
def test_http_attack_drives_physics_cmd(mod, path, body, expected_cmd, _n):
    """HTTP 공격(미인증) → 물리 명령 레지스터(cmd) 반영 → 콘솔 게이지가 움직인다."""
    c = TestClient(mod.app)
    r = c.post(path, json=body)
    assert r.status_code == 200, r.text
    after = c.get("/api/telemetry").json()
    assert after["cmd"] == expected_cmd, "미인증 공격이 물리 cmd 레지스터를 구동해야 한다"
    # 물리 브리지는 핸들러의 `if not patched:` 분기 안에서만 실행된다(패치 시 자동 무구동) —
    # 패치 상태 거부/안전응답은 기존 Safe Probe·트윈 계약 테스트가 담당.
