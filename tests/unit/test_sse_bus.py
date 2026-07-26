"""
SSE 허브(P0-4) 계약 고정 — 토픽 필터 / Last-Event-ID 리플레이 / 역할·지연 가시성.
폴링을 구독으로 바꾸는 상황판의 핵심 규칙을 테스트로 못박는다.
"""
import asyncio
import time

import pytest

from shared.sse_bus import SSEBus, visible_to


def test_publish_assigns_monotonic_ids():
    bus = SSEBus()
    a = bus.publish("events", {"x": 1})
    b = bus.publish("scores", {"y": 2})
    assert (a, b) == (1, 2)


def test_replay_returns_only_newer_ids():
    bus = SSEBus()
    for i in range(5):
        bus.publish("events", {"i": i})
    # Last-Event-ID=2 → id 3,4,5 만 리플레이
    got = bus.replay(last_id=2, topics=None)
    assert [m.id for m in got] == [3, 4, 5]


def test_replay_filters_by_topic():
    bus = SSEBus()
    bus.publish("events", {})      # 1
    bus.publish("scores", {})      # 2
    bus.publish("events", {})      # 3
    got = bus.replay(last_id=0, topics={"scores"})
    assert [m.id for m in got] == [2]


def test_ring_buffer_bounded():
    bus = SSEBus(buffer_size=3)
    for i in range(10):
        bus.publish("events", {"i": i})
    got = bus.replay(last_id=0, topics=None)
    assert [m.id for m in got] == [8, 9, 10]  # 최근 3개만 리플레이 가능


def test_subscription_receives_published():
    async def _run():
        bus = SSEBus()
        with bus.subscription() as q:
            bus.publish("events", {"hello": 1})
            msg = await asyncio.wait_for(q.get(), timeout=1.0)
            assert msg.topic == "events" and msg.data == {"hello": 1}
    asyncio.run(_run())


def test_slow_consumer_dropped_not_blocking():
    # 느린 구독자(큐 가득) 때문에 publish 가 막히면 안 된다 — 100명 관전자 보호.
    async def _run():
        bus = SSEBus()
        with bus.subscription(maxsize=2) as q:
            for i in range(10):
                bus.publish("events", {"i": i})  # 예외 없이 통과해야 함
            assert q.qsize() <= 2  # 큐는 maxsize 까지만
    asyncio.run(_run())


# ── 역할·지연 가시성 ────────────────────────────────────────────────
def _msg(topic="events", match_id="m1", ts=None):
    from shared.sse_bus import Message
    return Message(id=1, topic=topic, data={"match_id": match_id, "timestamp": ts or time.time()})


def test_instructor_sees_all():
    assert visible_to(_msg(match_id="m1"), role="instructor", match_id="", now=time.time())


def test_red_sees_only_own_match():
    now = time.time()
    assert visible_to(_msg(match_id="m1"), role="red", match_id="m1", now=now)
    assert not visible_to(_msg(match_id="m2"), role="red", match_id="m1", now=now)


def test_observer_delayed_hides_fresh_events():
    now = time.time()
    fresh = _msg(match_id="m1", ts=now - 5)     # 5초 전 → 30초 지연에 안 걸림
    old = _msg(match_id="m1", ts=now - 40)       # 40초 전 → 노출
    assert not visible_to(fresh, role="observer", match_id="", now=now, delay=30)
    assert visible_to(old, role="observer", match_id="", now=now, delay=30)


def test_observer_delay_not_applied_to_scores_topic_control():
    # 지연은 events/detections 등 라이브 토픽에만. phase_clock 은 지연 없이 노출(공용 시계).
    now = time.time()
    m = _msg(topic="phase_clock", match_id="", ts=now)
    assert visible_to(m, role="observer", match_id="", now=now, delay=30)
