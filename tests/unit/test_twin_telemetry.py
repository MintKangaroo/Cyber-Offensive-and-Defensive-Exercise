"""ICS 트윈 라이브파이어 텔레메트리 회귀 테스트.

livefire-ops 작전 콘솔이 발전소뿐 아니라 병원·상수도·정유 등 연속 물리 트윈의 게이지도 라이브로
움직이려면 각 트윈이 /api/telemetry(통일 규약)를 내고, HTTP 공격이 실제 물리 명령 레지스터에
도달해야 한다.

통일 규약: {asset, cmd, cmd_name, actual, actual_name, damage, interlock, failed, redline, registers[]}
  - attach_modbus_ics 기반 확장 섹터 트윈(hospital/refinery/smart_factory/lng/railway/airport/
    datacenter)은 공유 헬퍼가 /api/telemetry 를 자동 노출한다.
  - water_utility 는 전용 뱅크 → 자체 /api/telemetry.

과거엔 "hospital_ot 로 대표 검증" 지름길을 썼으나, 그러면 나머지 6개 확장 트윈의 cmd_name/스키마가
드리프트해도(예: reg_names 오타, cmd_reg 변경) 콘솔 fetchSectorTelemetry 가 조용히 null → 폴백(mock)
으로 떨어지고 어떤 테스트도 못 잡는다(섹터 트윈 라이브 연결 실증에서 드러난 공백). 이제 콘솔이 소비하는
7개 통일 트윈 전부의 /api/telemetry 계약을 실제 HTTP 로 고정한다(콘솔 소비 쪽은
dashboards/livefire-ops/src/sector-telemetry.test.ts 가 짝으로 가드).
"""
import os

os.environ.setdefault("MODBUS_ENABLED", "0")          # 테스트에서 502 리스너 불필요
os.environ.setdefault("RBAC_ALLOW_INSECURE_DEV", "true")
# 확장 트윈이 얹는 실 프로토콜 서버(OPC UA/S7/Profinet/HART/IEC61850)는 import→startup 시 실제
# 포트를 바인드한다(각자 *_ENABLED 기본 on). 유닛/CI 에선 /api/telemetry HTTP 계약만 보면 되므로 전부 끈다.
for _g in ("OPCUA_ENABLED", "S7_ENABLED", "PROFINET_ENABLED", "HART_ENABLED", "IEC61850_ENABLED"):
    os.environ.setdefault(_g, "0")

import pytest
from fastapi.testclient import TestClient

from services.hospital_ot import main as hospital
from services.water_utility import main as water
from services.refinery_plant import main as refinery
from services.smart_factory import main as factory
from services.lng_terminal import main as lng
from services.railway_signaling import main as railway
from services.airport_ot import main as airport
from services.datacenter_bms import main as datacenter

_REQUIRED_KEYS = {"asset", "cmd", "cmd_name", "actual", "actual_name",
                  "damage", "interlock", "failed", "redline", "registers"}

# (모듈, 공격 경로, 공격 바디, cmd 로 기대되는 값, 예상 cmd_name)
# HTTP 공격이 apply_command 로 cmd 레지스터를 직접 구동하는 트윈(콘솔 EXECUTE STRIKE 라이브 배선 대상).
CASES = [
    (hospital, "/api/device/infusion", {"device": "PUMP-07", "rate": 900}, 900, "INFUSION_RATE"),
    (water, "/api/dosing/chlorine", {"ppm": 12}, 12, "CHLORINE_PPM"),
]

# 콘솔이 /api/telemetry 로 라이브 연결 가능한 통일 트윈 전부(섹터키 → 트윈). 스키마/ cmd_name 계약 고정.
# 확장 6종은 cmd 를 Modbus/실프로토콜 쓰기로 구동(HTTP apply_command 경로 없음)하므로 스키마만 검증한다.
UNIFORM_CASES = [
    ("hospital", hospital, "INFUSION_RATE"),
    ("water", water, "CHLORINE_PPM"),
    ("refinery", refinery, "COLUMN_PRESSURE"),
    ("factory", factory, "ROBOT_SPEED"),
    ("lng", lng, "TANK_PRESSURE"),
    ("railway", railway, "TRAIN_SPEED"),
    ("airport", airport, "FUEL_PRESSURE"),
    ("datacenter", datacenter, "RACK_TEMP"),
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


@pytest.mark.parametrize("sector,mod,cmd_name", UNIFORM_CASES, ids=[c[0] for c in UNIFORM_CASES])
def test_sector_twin_telemetry_console_contract(sector, mod, cmd_name):
    """콘솔 fetchSectorTelemetry 가 소비하는 통일 /api/telemetry 계약을 섹터별로 전수 고정한다.

    과거 'hospital 대표' 지름길이 가렸던 나머지 섹터 트윈(refinery/factory/lng/railway/airport/
    datacenter)까지 각 트윈의 cmd_name·registers·interlock 타입을 실제로 검증 → 콘솔이 그 섹터를
    라이브로 연결할 수 있음을 트윈 쪽에서 보증(소비 쪽은 sector-telemetry.test.ts).
    """
    c = TestClient(mod.app)
    t = c.get("/api/telemetry").json()
    # 1) 콘솔 SectorTelemetry 인터페이스 전 필드 존재
    assert _REQUIRED_KEYS.issubset(t.keys()), f"[{sector}] 누락 키: {_REQUIRED_KEYS - set(t.keys())}"
    # 2) cmd_name 이 그 섹터의 제어 변수(콘솔 레지스터 테이블 라벨·SET 하이라이트 기준)
    assert t["cmd_name"] == cmd_name, f"[{sector}] cmd_name 드리프트: {t['cmd_name']}"
    # 3) fetchSectorTelemetry 가 Array.isArray(registers) 로 거르므로 registers 는 반드시 배열+행계약
    assert isinstance(t["registers"], list) and len(t["registers"]) >= 2, f"[{sector}] registers 부족"
    reg_names = {r["name"] for r in t["registers"]}
    assert cmd_name in reg_names, f"[{sector}] cmd 레지스터({cmd_name})가 registers 에 없음"
    for r in t["registers"]:
        assert {"addr", "name", "value"}.issubset(r.keys()), f"[{sector}] 레지스터 행 계약 위반"
    # 4) interlock 은 bool(콘솔 SAFETY_INTERLOCK coil0 ON/ARMED vs OFF/BYPASS 토글 기준)
    assert isinstance(t["interlock"], bool), f"[{sector}] interlock 타입"
