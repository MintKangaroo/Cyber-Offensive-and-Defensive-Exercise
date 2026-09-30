"""S-8 회귀: 이벤트 유실을 조용히 삼키지 않고 가시화한다.

원 결함(audit/99_final.md S-8):
  - shared/event_client.py 가 트윈→collector 발행 실패를 `except: pass` 로 삼킴(카운터·로그 없음).
  - shared/sse_bus.py 가 느린 구독자 드롭을 `except QueueFull: pass` 로 삼킴(계측 없음).
  - collector→scoring DLQ 재전달(드레인) 경로에 전용 단위테스트 부재.

이 테스트는 (1) event_client 드롭 카운터, (2) sse_bus 드롭 카운터, (3) DLQ spool→drain
재전달을 고정한다. best-effort 보장(발행 실패해도 호출자가 죽지 않음)도 함께 검증한다.
"""
from __future__ import annotations

import asyncio
import importlib

import pytest


# ---------------------------------------------------------------------------
# (1) event_client: 발행 실패를 계측하되 호출자를 막지 않는다
# ---------------------------------------------------------------------------
def test_event_client_counts_drops_and_does_not_raise(monkeypatch):
    import shared.event_client as ec
    importlib.reload(ec)  # 모듈 전역 _dropped 초기화

    import requests

    def _boom(*a, **k):
        raise requests.exceptions.ConnectionError("collector down")

    monkeypatch.setattr(ec.requests, "post", _boom)

    base = ec.dropped_count()
    # best-effort: 예외가 호출자에게 전파되면 안 된다(트윈 응답 보호).
    ec.emit_event("e1", "red_attack_started", "red", "power_plant")
    ec.emit_event("e2", "red_attack_started", "red", "power_plant")
    assert ec.dropped_count() == base + 2, "발행 실패가 카운터에 반영되지 않았다"


def test_event_client_no_drop_on_success(monkeypatch):
    import shared.event_client as ec
    importlib.reload(ec)

    class _OK:
        status_code = 200

    monkeypatch.setattr(ec.requests, "post", lambda *a, **k: _OK())
    base = ec.dropped_count()
    ec.emit_event("e3", "red_attack_started", "red", "power_plant")
    assert ec.dropped_count() == base, "성공 발행인데 드롭으로 계측됐다"


# ---------------------------------------------------------------------------
# (2) sse_bus: 느린 구독자 드롭을 계측한다(publish 는 절대 막히지 않는다)
# ---------------------------------------------------------------------------
def test_sse_bus_counts_slow_subscriber_drops():
    from shared.sse_bus import SSEBus

    async def _run():
        bus = SSEBus(buffer_size=100)
        with bus.subscription(maxsize=2) as q:  # 작은 큐로 포화 유도
            for i in range(5):
                bus.publish("events", {"n": i})  # 큐 2칸 초과분은 드롭
            assert bus.dropped == 3, f"드롭 3건 예상, 실제 {bus.dropped}"
            # publish 는 막히지 않고 seq 는 정상 증가
            assert bus.last_id == 5
            # 큐에는 정확히 maxsize 만큼만 적재
            assert q.qsize() == 2

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# (3) event_collector DLQ: 실패 스풀 → 복구 후 드레인 재전달(0 유실)
# ---------------------------------------------------------------------------
def _load_collector(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RBAC_ALLOW_INSECURE_DEV", "true")
    monkeypatch.setenv("SCORING_ENGINE_URL", "http://127.0.0.1:9")
    import services.event_collector.main as m
    importlib.reload(m)
    m.DB_PATH = tmp_path / "events.db"
    m.init_db()
    m._writer_conn = None
    m._ingest_queue = None
    return m


def test_dlq_spool_then_drain_redelivers(tmp_path, monkeypatch):
    m = _load_collector(tmp_path, monkeypatch)

    payload = {"event_id": "d1", "team_id": "team-01", "actor": "red",
               "scenario_id": "s", "target_asset": "power_plant", "metadata": {}}

    # scoring 다운 상태를 모사: DLQ 로 스풀.
    spooled0 = m._METRICS["dlq_spooled"]
    m._spool_to_dlq("d1", payload, "HTTP 503")
    m._spool_to_dlq("d2", {**payload, "event_id": "d2"}, "HTTP 503")
    assert m._METRICS["dlq_spooled"] == spooled0 + 2

    conn = m.get_db()
    pending = conn.execute("SELECT COUNT(*) FROM scoring_dlq").fetchone()[0]
    conn.close()
    assert pending == 2, "DLQ 에 2건 스풀돼야 한다"

    # scoring 복구를 모사: _post_scoring 을 성공으로 대체하고 1회 드레인.
    async def _ok(_payload):
        return True, None
    monkeypatch.setattr(m, "_post_scoring", _ok)

    redelivered = asyncio.run(m._drain_dlq_once())
    assert redelivered == 2, f"2건 재전달 예상, 실제 {redelivered}"

    conn = m.get_db()
    pending_after = conn.execute("SELECT COUNT(*) FROM scoring_dlq").fetchone()[0]
    conn.close()
    assert pending_after == 0, "드레인 후 DLQ 잔량 0(무손실)이어야 한다"


def test_dlq_drain_keeps_rows_when_scoring_still_down(tmp_path, monkeypatch):
    m = _load_collector(tmp_path, monkeypatch)
    m._spool_to_dlq("d3", {"event_id": "d3"}, "HTTP 503")

    async def _fail(_payload):
        return False, "HTTP 503"
    monkeypatch.setattr(m, "_post_scoring", _fail)

    redelivered = asyncio.run(m._drain_dlq_once())
    assert redelivered == 0
    conn = m.get_db()
    pending = conn.execute("SELECT COUNT(*) FROM scoring_dlq").fetchone()[0]
    conn.close()
    assert pending == 1, "재전달 실패 시 DLQ 에 남아 다음 주기에 재시도돼야 한다"
