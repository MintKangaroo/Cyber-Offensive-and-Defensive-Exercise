"""Blue '차단 성공'(blue_block_success) 발행 경계 회귀 — 방어 점수가 켜지는 바로 그 조건.

라이브파이어 콘솔 DEFENSE 열의 '차단 성공(+30)'은, 공격으로 위험에 빠진 공정을 Blue 가
안전계통(SIS) 코일을 되살려(coil0→ON) 막았을 때만 켜져야 한다. 그 이벤트를 만드는 유일한 곳은
발전소 트윈의 Modbus 쓰기 콜백 `_on_modbus_write` 안의 재무장 분기다(services/power_plant/main.py:307):

    if kind == "coil" and addr == 0 and vals and bool(vals[0]) \
            and not _proc_failed and _in_danger(_proc_state, _PROC_PARAMS):
        emit blue_block_success

기존 커버리지의 공백(실측 확인):
  - test_twin_safety_override 는 override 해제/재무장과 인터록 게이트 파국만 본다(MODBUS_ENABLED=0,
    Modbus 콜백 미경유) → blue_block_success 발행은 어떤 유닛도 보지 않았다.
  - test_scoring_engine 은 'blue_block_success 가 들어오면 +30' 을(scoring 쪽만) 본다.
  → 그 사이의 연결고리, 즉 "실 Modbus 코일 재무장 → 정확히 그 조건에서만 blue_block_success 발행"
     은 미가드였다. 이 조건이 느슨해지면(예: 위험 아님에도 발행, 파국 후 발행, 코일 OFF 에도 발행)
     일상적 SIS 토글이 방어 점수를 남발하거나, 이미 파괴된 자산을 '막았다'고 허위 가점한다.
     반대로 조건이 끊기면 콘솔 DEFENSE 의 '차단 성공'이 조용히 멈춘다(블록 라이브 E2E 로 실증한 경로).

이 테스트는 실제 트윈 모듈의 `_on_modbus_write` 를 (그리고 FC5 와이어 프레임을 handle_pdu 로)
구동해 blue_block_success 발행이 "위험 중 + 미파국 + 코일 ON" 에서만 일어남을 고정한다.
emit_event 만 가로채고 나머지(물리/SIEM 로그)는 실제 코드 경로를 그대로 탄다.
"""
import os
import struct

os.environ.setdefault("MODBUS_ENABLED", "0")      # 콜백만 직접 구동 — 502 리스너 불필요
os.environ.setdefault("DNP3_ENABLED", "0")
os.environ.setdefault("RBAC_ALLOW_INSECURE_DEV", "true")

import pytest

from services.power_plant import main as pp
from shared.ics import modbus as mb

_DANGER = pp.ProcessState(actual_rpm=5000.0, coolant_temp=40.0, damage=4.0)   # redline 4500 초과 + 손상 진행
_NOMINAL = pp.ProcessState(actual_rpm=3000.0, coolant_temp=40.0, damage=0.0)  # 밴드 내, 위험 아님


@pytest.fixture
def captured(monkeypatch):
    """emit_event 를 가로채 발행 이벤트를 모은다(나머지 물리/로그 경로는 실제 그대로)."""
    evs: list = []
    monkeypatch.setattr(pp, "emit_event", lambda **kw: evs.append(kw))
    return evs


def _blocks(evs):
    return [e for e in evs if str(getattr(e.get("event_type"), "value", e.get("event_type"))) == "blue_block_success"]


def _set_state(monkeypatch, state, failed):
    monkeypatch.setattr(pp, "_proc_state", state)
    monkeypatch.setattr(pp, "_proc_failed", failed)


def test_rearm_during_danger_emits_block_success(captured, monkeypatch):
    """위험 중(과속+손상) + 미파국 + 코일0 ON → 정확히 1건 blue_block_success(actor=blue)."""
    _set_state(monkeypatch, _DANGER, failed=False)
    pp._on_modbus_write("coil", 0, [True])

    blocks = _blocks(captured)
    assert len(blocks) == 1, f"위험 중 재무장은 정확히 1건 차단성공이어야: {[e.get('event_type') for e in captured]}"
    b = blocks[0]
    assert b["actor"] == "blue"
    assert b["target_asset"] == "power_plant"
    assert b["vuln_id"] == "PP-006"
    # 콘솔 Solve Log·AAR 가 읽는 방어 메타(재무장 라벨 + 당시 물리 스냅샷)
    assert b["metadata"]["defense"] == "safety_interlock_rearmed"
    assert b["metadata"]["actual_rpm"] == 5000
    assert b["metadata"]["damage"] == 4


def test_rearm_when_not_in_danger_emits_no_block(captured, monkeypatch):
    """위험이 아니면(공칭 상태) 코일0 ON 재무장이라도 차단성공 아님 — 일상 SIS 토글 남발 방지."""
    _set_state(monkeypatch, _NOMINAL, failed=False)
    pp._on_modbus_write("coil", 0, [True])
    assert _blocks(captured) == [], "위험이 없는데 방어 점수를 주면 안 된다"


def test_rearm_after_catastrophe_emits_no_block(captured, monkeypatch):
    """이미 파국(_proc_failed)이면 재무장해도 차단성공 아님 — 파괴된 자산을 '막았다'고 허위가점 금지."""
    _set_state(monkeypatch, _DANGER, failed=True)
    pp._on_modbus_write("coil", 0, [True])
    assert _blocks(captured) == [], "파국 후 재무장은 블록이 아니다"


def test_disabling_sis_is_not_a_block(captured, monkeypatch):
    """코일0 OFF(SIS 무력화)는 공격이지 방어가 아니다 → 차단성공 발행 금지."""
    _set_state(monkeypatch, _DANGER, failed=False)
    pp._on_modbus_write("coil", 0, [False])
    assert _blocks(captured) == [], "SIS 를 끄는 것은 방어가 아니다"


def test_real_fc5_coil_frame_drives_block_success(captured, monkeypatch):
    """실 Modbus FC5(단일 코일 쓰기) 프레임 → handle_pdu → on_write → blue_block_success.
    라이브 E2E 가 탄 바로 그 와이어 경로(원시 FC5 재무장)를 유닛에서 고정한다."""
    _set_state(monkeypatch, _DANGER, failed=False)
    # FC5 write-single-coil PDU: addr=0, 0xFF00=ON
    pdu = struct.pack(">BHH", 5, 0, 0xFF00)
    resp = mb.handle_pdu(pp._modbus_bank, pdu)
    assert resp[0] == 5, "FC5 정상 응답(에러비트 없음)"
    assert len(_blocks(captured)) == 1, "원시 FC5 재무장 프레임이 콜백을 거쳐 차단성공을 내야"
