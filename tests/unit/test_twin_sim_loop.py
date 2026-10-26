"""ICS 트윈 배경 물리 루프(`_sim_loop`) 통합 회귀 — 라이브파이어 게이지 계약.

라이브파이어 콘솔의 게이지가 '실제로 움직이는' 것은 `attach_modbus_ics` 가 띄우는 연속
배경 루프(`_ModbusIcsTwin._sim_loop`)가 매 틱 _step 결과를 Modbus 뱅크(actual/damage)에
반영하고 파국 플래그를 올리기 때문이다. 기존 트윈 테스트는 전부 `MODBUS_ENABLED=0`(루프 OFF)
로 돌며 `sim_step` 을 직접 호출하므로, 이 루프 자체와 그 배선(_start 가 루프를 스케줄하는지)은
가드되지 않았다 — 리팩터가 루프를 끊어도 전 테스트가 통과하고 6개 통일트윈 게이지가 조용히
정지한다. 이 테스트는 (병원 섹터 라이브 E2E 에서 드러난) 그 seam 을 고정한다:
  1. 루프가 ARMED 에서 한계 초과 명령을 redline 으로 캡하고 손상 0·무파국을 유지한다.
  2. 루프가 BYPASS 에서 초과분을 손상으로 누적해 뱅크/플래그가 실제 파국에 도달한다.
  3. `_start` 는 MODBUS_ENABLED=1 일 때만 루프를 스케줄한다(=0 이면 게이지 정지).
"""
import asyncio
import os

os.environ.setdefault("RBAC_ALLOW_INSECURE_DEV", "true")

import pytest

from shared.ics import twin_modbus
from shared.ics.twin_modbus import _ModbusIcsTwin, ModbusIcsConfig
from shared.ics.safety import SafetyProfile
from shared.ics.anomaly import IcsBaseline, RegBand
from shared.ics.process_sim import ProcessParams

_REAL_SLEEP = asyncio.sleep


def _cfg(*, cmd: int, interlock_on: bool) -> ModbusIcsConfig:
    # 병원 주입펌프 프로파일과 동형: redline 200, 한계초과 시 손상 누적 → 100 에서 파국.
    return ModbusIcsConfig(
        asset="simloop_test", vuln_id="TST-SIM",
        reg_names={0: "RATE", 1: "CONC"}, holding_init=[cmd, 10], coils_init=[interlock_on],
        cmd_reg=0, actual_reg=2, damage_reg=4, interlock_coil=0,
        safety=SafetyProfile(name="t", limits={0: {"name": "RATE", "max": 200}}, interlock_coil=0),
        anomaly=IcsBaseline(name="t", registers={0: RegBand("RATE", 0, 200, protected=True)}, safety_coils={0}),
        proc=ProcessParams(slew_rpm_per_s=20, nominal_rpm=0, k_heat=0.0, k_cool=0.0, redline_rpm=200,
                           crit_temp=1e9, damage_rpm_rate=0.2, damage_temp_rate=0.0, failure_threshold=100),
        impact="overdose")


async def _spin(twin: _ModbusIcsTwin, *, until_failed: bool, max_iter: int = 6000):
    """배경 루프를 실시간 sleep 없이 결정적으로 돌린다(asyncio.sleep → 즉시 yield)."""
    async def _fast(_):
        await _REAL_SLEEP(0)

    orig = asyncio.sleep
    asyncio.sleep = _fast  # twin_modbus 가 모듈 전역 asyncio.sleep 을 호출 → 여기서 가속
    try:
        task = asyncio.create_task(twin._sim_loop())
        for _ in range(max_iter):
            await _REAL_SLEEP(0)
            if until_failed and twin.failed:
                break
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    finally:
        asyncio.sleep = orig


def test_sim_loop_bypass_drives_bank_to_catastrophe():
    """BYPASS: 루프가 actual 을 redline 초과로 올리고 damage 를 누적해 뱅크/플래그가 파국에 도달."""
    twin = _ModbusIcsTwin(_cfg(cmd=900, interlock_on=False))
    assert twin.failed is False
    asyncio.run(_spin(twin, until_failed=True))

    c = twin.cfg
    assert twin.failed is True, "BYPASS + 한계초과 지속 → 배경 루프가 파국 플래그를 올려야"
    assert twin.bank.holding[c.actual_reg] > c.proc.redline_rpm, "actual 이 redline 을 넘어야"
    assert twin.bank.holding[c.damage_reg] >= c.proc.failure_threshold, "damage 가 뱅크에 누적돼야"
    # telemetry(콘솔이 폴링하는 바로 그 표면)도 파국을 반영
    t = twin.telemetry()
    assert t["failed"] is True and t["interlock"] is False
    assert t["damage"] >= c.proc.failure_threshold


def test_sim_loop_armed_caps_at_redline_without_damage():
    """ARMED: 한계 초과 명령도 루프가 redline 으로 캡 → 손상 0·무파국(물리 모델이 스크립트 아님)."""
    twin = _ModbusIcsTwin(_cfg(cmd=900, interlock_on=True))
    asyncio.run(_spin(twin, until_failed=False, max_iter=3000))

    c = twin.cfg
    assert twin.failed is False, "ARMED 는 파국에 도달하면 안 됨"
    assert twin.bank.holding[c.actual_reg] == c.proc.redline_rpm, "actual 은 redline 에서 캡"
    assert twin.bank.holding[c.damage_reg] == 0, "ARMED 는 손상 0"


def test_start_schedules_sim_loop_only_when_modbus_enabled(monkeypatch):
    """_start 는 MODBUS_ENABLED=1 일 때만 배경 루프를 스케줄한다(=0 이면 라이브 게이지 정지)."""
    async def _fake_serve(bank, host, port):  # 실제 소켓 바인딩 회피
        return None

    monkeypatch.setattr(twin_modbus, "_modbus_serve", _fake_serve)

    async def _count_tasks(enabled: str) -> int:
        os.environ["MODBUS_ENABLED"] = enabled
        twin = _ModbusIcsTwin(_cfg(cmd=100, interlock_on=True))
        await twin._start()
        others = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for t in others:  # 생성된 루프 태스크 정리
            t.cancel()
            try:
                await t
            except asyncio.CancelledError:
                pass
        return len(others)

    prev = os.environ.get("MODBUS_ENABLED")
    try:
        assert asyncio.run(_count_tasks("1")) >= 1, "MODBUS_ENABLED=1 → 배경 루프 스케줄"
        assert asyncio.run(_count_tasks("0")) == 0, "MODBUS_ENABLED=0 → 루프 미스케줄"
    finally:
        if prev is None:
            os.environ.pop("MODBUS_ENABLED", None)
        else:
            os.environ["MODBUS_ENABLED"] = prev
