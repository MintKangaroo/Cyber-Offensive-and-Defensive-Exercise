"""확장 트윈 HTTP 물리 명령 라우트(`POST /api/command`) 회귀 — 브라우저발 게이지 파국.

#150 가 정직하게 남긴 한계: lng/railway/airport/datacenter/smart_factory/refinery 등 attach_modbus_ics
확장 트윈은 /api/safety/override(SIS 무력화)만 HTTP 로 열려 있어, 콘솔 EXECUTE STRIKE 가 인터록은
풀어도 **물리 명령(cmd) 레지스터를 구동할 길이 없어** ACTUAL 게이지가 안 움직였다(full-config 트윈만
/api/plc/write·/api/device/infusion 등으로 cmd 를 브라우저에서 밀 수 있었다). 이제 attach_modbus_ics
가 `POST /api/command {value}` 를 공통으로 노출해, 공격 setpoint 를 **실 Modbus FC6 쓰기와 동일 경로**
(`command_write`→`_on_write`)로 cmd 레지스터에 반영한다 → 연속 물리 루프가 ACTUAL 을 끌어올린다.

2026-11-09 라이브 E2E(airport_ot:8206, MODBUS_ENABLED=1, 실 sim loop):
  POST /api/command {value:90}  (SIS 걸림)     → actual 가 redline 50 에서 트립·damage 0·failed false
  POST /api/safety/override {override:true}      → interlock OFF
  (cmd 90 유지, 3초 간격 폴링)                    → actual 65→80→90(>50)·damage 26→97→100·failed TRUE
즉 full-config 수준 파국이 전부 HTTP(브라우저 도달)로 구동되며, **파국은 SIS 선-우회를 요구**한다
(SIS 가 걸려 있으면 트립만, 손상 없음). 이 파일이 (1) 라우트→cmd 구동, (2) 미인가 쓰기 이벤트 발화
(Blue 탐지 듀얼리티), (3) 2단 요구(SIS 선-우회 없이는 파국 불가) 세 경계를 고정한다.
"""
import os

os.environ.setdefault("MODBUS_ENABLED", "0")          # sim loop/502 리스너 불필요(물리는 순수 step 으로 가드)
os.environ.setdefault("RBAC_ALLOW_INSECURE_DEV", "true")
for _g in ("OPCUA_ENABLED", "S7_ENABLED", "PROFINET_ENABLED", "HART_ENABLED", "IEC61850_ENABLED"):
    os.environ.setdefault(_g, "0")

import pytest
from fastapi.testclient import TestClient

import shared.ics.twin_modbus as twin_modbus
from shared.ics.process_sim import ProcessParams, ProcessState, step, has_failed

from services.airport_ot import main as airport
from services.lng_terminal import main as lng
from services.railway_signaling import main as railway

# (섹터, 모듈, cmd_name, redline, redline 초과 공격값)
ROUTE_CASES = [
    ("airport", airport, "FUEL_PRESSURE", 50, 90),
    ("lng", lng, "TANK_PRESSURE", 200, 260),
    ("railway", railway, "TRAIN_SPEED", 120, 160),
]


@pytest.mark.parametrize("sector,mod,cmd_name,redline,value", ROUTE_CASES,
                         ids=[c[0] for c in ROUTE_CASES])
def test_command_route_drives_cmd_register(sector, mod, cmd_name, redline, value):
    """POST /api/command → cmd 레지스터가 공격값으로 구동되고 ack/telemetry 에 반영된다."""
    c = TestClient(mod.app)
    r = c.post("/api/command", json={"value": value})
    assert r.status_code == 200, r.text
    ack = r.json()
    assert isinstance(ack["asset"], str) and ack["asset"]
    assert ack["cmd"] == value
    assert ack["cmd_name"] == cmd_name
    assert ack["redline"] == redline
    # 통일 텔레메트리에도 cmd 가 반영돼 콘솔 게이지가 그 값을 읽는다
    t = c.get("/api/telemetry").json()
    assert t["cmd"] == value
    assert t["cmd_name"] == cmd_name


def test_command_route_fires_unauthorized_write_event(monkeypatch):
    """command_write 는 실 FC6 쓰기와 동일하게 미인가 쓰기 이벤트를 발화한다(Blue 탐지·채점 듀얼리티).
    SIEM access 로그·안전평가도 같은 `_on_write` 경로에서 함께 나간다."""
    captured = []
    monkeypatch.setattr(twin_modbus, "emit_event", lambda **kw: captured.append(kw))
    c = TestClient(airport.app)
    c.post("/api/command", json={"value": 90})
    # cmd 레지스터(FUEL_PRESSURE) 대상의 red 공격 이벤트가 register 쓰기로 발화
    writes = [e for e in captured
              if e.get("actor") == "red" and (e.get("metadata") or {}).get("register") == "FUEL_PRESSURE"]
    assert writes, f"미인가 cmd 쓰기 이벤트가 없음: {captured}"
    md = writes[0]["metadata"]
    assert md["protocol"] == "modbus"
    assert md["fc_kind"] == "register"
    assert md["values"] == [90]


# 순수 물리로 2단 요구(SIS 선-우회)를 결정론적으로 고정 — 라우트가 cmd 를 밀어도 SIS 가 걸려 있으면
# 트립만 되고 손상이 안 난다. slew 20/dt 0.5, redline 50, cmd 90(초과 40).
_P = ProcessParams(slew_rpm_per_s=20, nominal_rpm=0, ambient_temp=0, k_heat=0.0, k_cool=0.0,
                   redline_rpm=50, crit_temp=1e9, damage_rpm_rate=0.1, damage_temp_rate=0.0,
                   failure_threshold=100.0, heal_rate=2.0)


def _run(interlock_engaged, steps=120):
    s = ProcessState(actual_rpm=30.0, coolant_temp=0.0)
    for _ in range(steps):
        s = step(s, cmd_rpm=90.0, coolant_flow=0.0, dt=0.5, p=_P, interlock_engaged=interlock_engaged)
    return s


def test_sis_engaged_trips_at_redline_without_damage():
    # SIS 걸린 채 cmd 를 redline 초과로 밀어도 → actual 은 redline 에서 캡·손상 0·파국 없음.
    s = _run(interlock_engaged=True)
    assert s.actual_rpm <= _P.redline_rpm
    assert s.damage == 0
    assert not has_failed(s, _P)


def test_sis_bypassed_accrues_damage_to_catastrophe():
    # SIS 우회 상태에서 같은 cmd → actual 이 redline 을 넘고 손상이 누적돼 파국(failure_threshold)에 도달.
    s = _run(interlock_engaged=False)
    assert s.actual_rpm > _P.redline_rpm
    assert s.damage > 0
    assert has_failed(s, _P)
