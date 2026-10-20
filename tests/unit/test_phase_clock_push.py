"""scenario_engine phase_clock 상황판 푸시 회귀 테스트.

라이브파이어 콘솔의 타이머 3종(잔여/다음 단계/경과)은 event_collector 의 phase_clock 토픽을
구독해 움직인다. 그 토픽에 프레임을 넣는 주체가 scenario_engine 의 _phase_clock_loop 다.
활성 시나리오가 있으면 매 주기 phase_clock(투영 타임라인)을 /internal/publish 로 민다.
"""
import asyncio
import os
import time

os.environ.setdefault("RBAC_ALLOW_INSECURE_DEV", "true")

import pytest

from services.scenario_engine import api


class _FakeResp:
    status_code = 200


class _FakeClient:
    """httpx.AsyncClient 대체 — /internal/publish 로 간 payload 를 수집한다."""
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


@pytest.fixture(autouse=True)
def _clean():
    _FakeClient.sent = []
    api._active_started.clear()
    yield
    api._active_started.clear()


def _fake_scenario():
    return {
        "id": "TST-CLOCK-01",
        "time_limit_sec": 600,
        "stages": [
            {"stage": 1, "name": "initial access", "expected_sec": 120},
            {"stage": 2, "name": "lateral", "expected_sec": 240},
            {"stage": 3, "name": "objective", "expected_sec": 240},
        ],
    }


def test_phase_clock_loop_publishes_for_active_scenario(monkeypatch):
    sid = "TST-CLOCK-01"
    monkeypatch.setattr(api, "_raw_scenarios", lambda: {sid: _fake_scenario()})
    monkeypatch.setattr(api.httpx, "AsyncClient", _FakeClient)
    # 130초 전에 활성화됐다고 가정 → stage 2 구간, 잔여 470초.
    api._active_started[sid] = time.time() - 130

    async def _run_one_iteration():
        task = asyncio.create_task(api._phase_clock_loop())
        await asyncio.sleep(0.2)   # 1 사이클 이상 돌 시간
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run_one_iteration())

    assert _FakeClient.sent, "활성 시나리오가 있으면 phase_clock 을 발행해야 한다"
    last = _FakeClient.sent[-1]
    assert last["url"].endswith("/internal/publish")
    assert last["json"]["topic"] == "phase_clock"
    d = last["json"]["data"]
    assert d["scenario_id"] == sid
    assert d["time_limit_sec"] == 600
    assert 100 <= d["elapsed_sec"] <= 160          # ~130초 경과
    assert 440 <= d["remaining_sec"] <= 500        # 600 - 경과
    assert d["current_stage"] == 2                 # 120~360초 구간


def test_phase_clock_loop_idle_when_no_active(monkeypatch):
    monkeypatch.setattr(api, "_raw_scenarios", lambda: {})
    monkeypatch.setattr(api.httpx, "AsyncClient", _FakeClient)
    # 활성 시나리오 없음 → 발행 없음.

    async def _run_one_iteration():
        task = asyncio.create_task(api._phase_clock_loop())
        await asyncio.sleep(0.2)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run_one_iteration())
    assert _FakeClient.sent == [], "활성 시나리오가 없으면 발행하지 않는다(유휴)"
