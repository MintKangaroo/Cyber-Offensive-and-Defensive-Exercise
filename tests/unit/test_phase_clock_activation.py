"""scenario_engine phase_clock '활성화 경로' 회귀 — 타이머가 켜지는 바로 그 배선.

라이브파이어 콘솔의 타이머 3종은 phase_clock 토픽으로 움직이고, 그 토픽을 미는 _phase_clock_loop
는 _active_started 에 시드가 있을 때만 발행한다. _active_started 를 채우는 유일한 경로는
POST /scenario/activate(→ activate_scenario) 다.

기존 test_phase_clock_push 는 _active_started 를 테스트에서 '수동 pre-seed' 한 뒤 루프만 검증했다
→ 활성화 라우트가 실제로 시드를 심어 루프가 돌기 시작하는 linkage 는 어떤 유닛도 보지 않았다
(이 경로는 데모 스크립트로만 돌려봤을 뿐이다). 리팩터가 activate_scenario 의 시드 주입을 끊어도
전 테스트가 통과하고 콘솔 타이머가 영구히 멈춘다. 이 테스트는 (병원/워터 라이브 실증과 같은 원칙으로)
그 활성화→틱 linkage 를 고정한다:
  1. activate_scenario 가 _active_started/_active_trackers 를 채우고 scenario_started 를 발행한다.
  2. 활성화로 심어진 시드만으로 _phase_clock_loop 가 그 시나리오의 phase_clock 을 발행한다.
  3. deactivate_scenario 가 시드를 걷어내 루프가 더는 그 시나리오를 발행하지 않는다.
"""
import asyncio
import os
import time
import types

os.environ.setdefault("RBAC_ALLOW_INSECURE_DEV", "true")

import pytest

from services.scenario_engine import api

SID = "TST-ACTIVATE-01"


class _FakeResp:
    status_code = 200


class _FakeClient:
    """httpx.AsyncClient 대체 — /internal/publish 로 간 phase_clock payload 수집."""
    sent: list = []

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None, headers=None):
        _FakeClient.sent.append({"url": url, "json": json})
        return _FakeResp()


def _fake_scenario_dict():
    return {
        "id": SID,
        "time_limit_sec": 600,
        "stages": [
            {"stage": 1, "name": "initial access", "expected_sec": 120},
            {"stage": 2, "name": "lateral", "expected_sec": 240},
            {"stage": 3, "name": "objective", "expected_sec": 240},
        ],
    }


def _fake_loaded():
    # activate_scenario 가 쓰는 표면만 갖춘 최소 LoadedScenario 대역.
    return types.SimpleNamespace(
        single=types.SimpleNamespace(target_asset="power_plant"),
        crossover=None,
        kind="single",
    )


@pytest.fixture(autouse=True)
def _wire(monkeypatch):
    _FakeClient.sent = []
    api._active_started.clear()
    api._active_trackers.clear()
    # 활성화 라우트의 외부 부작용(네트워크/러너)을 대역으로 치환 — 활성화 '배선'만 검증.
    monkeypatch.setitem(api._all_scenarios, SID, _fake_loaded())
    monkeypatch.setattr(api, "make_tracker", lambda loaded, emit_event_fn=None: object())

    async def _noop_inject(loaded, client):
        return None

    emitted: list = []

    async def _capture_emit(**kwargs):
        emitted.append(kwargs)

    monkeypatch.setattr(api, "inject_initial_state", _noop_inject)
    monkeypatch.setattr(api, "_emit_event_async", _capture_emit)
    monkeypatch.setattr(api, "_raw_scenarios", lambda: {SID: _fake_scenario_dict()})
    monkeypatch.setattr(api.httpx, "AsyncClient", _FakeClient)
    api._emitted_test = emitted  # 테스트에서 scenario_started 발행 확인용
    yield
    api._active_started.clear()
    api._active_trackers.clear()


async def _pump_loop_once():
    task = asyncio.create_task(api._phase_clock_loop())
    await asyncio.sleep(0.2)   # 1 사이클 이상
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def _phase_clock_frames():
    return [s for s in _FakeClient.sent
            if s["url"].endswith("/internal/publish") and s["json"].get("topic") == "phase_clock"]


def test_activate_seeds_clock_and_loop_publishes():
    """activate_scenario → _active_started 시드 → 루프가 그 시나리오 phase_clock 발행(수동 seed 없음)."""
    res = asyncio.run(api.activate_scenario(
        api.ActivateRequest(scenario_id=SID, team_ids=["RED-01"]), authorization=""))
    assert res["status"] == "active" and res["scenario_id"] == SID

    # 활성화가 실제로 시드를 심었는가(루프의 유일한 트리거)
    assert SID in api._active_started, "activate 가 _active_started 를 채워야 루프가 틱"
    assert abs(api._active_started[SID] - time.time()) < 5
    assert SID in api._active_trackers
    # scenario_started 이벤트 발행도 함께(콘솔/채점 계통이 활성 사실을 받는 경로)
    assert any(e.get("event_type") == "scenario_started" for e in api._emitted_test)

    # 수동 pre-seed 없이, 오직 활성화 시드만으로 루프가 phase_clock 을 발행하는가
    asyncio.run(_pump_loop_once())
    frames = _phase_clock_frames()
    assert frames, "활성화된 시나리오가 있으면 루프가 phase_clock 을 발행해야"
    d = frames[-1]["json"]["data"]
    assert d["scenario_id"] == SID
    assert d["time_limit_sec"] == 600
    assert d["elapsed_sec"] <= 5 and 595 <= d["remaining_sec"] <= 600  # 방금 활성화 → 경과 ~0
    assert d["current_stage"] == 1


def test_deactivate_stops_clock():
    """deactivate_scenario → 시드 제거 → 루프가 더는 그 시나리오를 발행하지 않는다."""
    asyncio.run(api.activate_scenario(
        api.ActivateRequest(scenario_id=SID, team_ids=["RED-01"]), authorization=""))
    assert SID in api._active_started

    res = asyncio.run(api.deactivate_scenario(
        api.DeactivateRequest(scenario_id=SID), authorization=""))
    assert res["status"] == "ended"
    assert SID not in api._active_started, "deactivate 는 시드를 걷어내야"
    assert SID not in api._active_trackers

    _FakeClient.sent = []
    asyncio.run(_pump_loop_once())
    assert not _phase_clock_frames(), "비활성화 후에는 phase_clock 발행이 없어야"
