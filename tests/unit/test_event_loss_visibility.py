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
import json
import time

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


# ---------------------------------------------------------------------------
# (4) S-11 백프레셔: scoring 열화 시 fire-and-forget 포워딩 태스크가 무한 누적되지 않는다.
# ---------------------------------------------------------------------------
# 원 결함: /events 핸들러가 신규 이벤트마다 _forward_to_scoring_engine 태스크를 무조건 생성했다.
# _forward_sem(동시성 64)은 '동시 HTTP 수'만 제한할 뿐 태스크 '생성'은 막지 못해, scoring 이
# 느리거나 실패해 (유입 EPS > 세마포어 처리율)이 지속되면 _forward_tasks 가 무한 누적 → RSS 선형
# 증가. A/B 소크 실측(10%5xx+5%timeout): inflight 0→17.6k·RSS 66→179MiB·+324MiB/h vs
# 정상계층 +0.8MiB/h 평탄. 수정: 인플라이트 상한 초과분을 내구 DLQ 로 shed(무손실·bounded).
def _mk_event(m, i):
    return m.Event(event_id=f"c{i}", event_type="red_attack_started", actor="red",
                   target_asset="power_plant", phase="initial_access",
                   team_id="team-01", scenario_id="s")


def test_forward_dispatch_bounds_inflight_and_sheds_to_dlq(tmp_path, monkeypatch):
    m = _load_collector(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "_FORWARD_MAX_INFLIGHT", 5)

    async def _hang(_event):
        await asyncio.Event().wait()   # scoring 영구 지연 모사: 태스크가 끝나지 않는다.
    monkeypatch.setattr(m, "_forward_to_scoring_engine", _hang)

    async def _run():
        shed0 = m._METRICS["forward_shed_to_dlq"]
        for i in range(12):
            m._dispatch_forward(_mk_event(m, i))
        # 인플라이트는 상한을 넘지 않는다(태스크 생성이 bounded).
        assert len(m._forward_tasks) == 5, f"인플라이트 {len(m._forward_tasks)} != 상한 5"
        # 초과분(12-5=7)은 메모리에 쌓이는 대신 DLQ 로 흘렀다.
        assert m._METRICS["forward_shed_to_dlq"] == shed0 + 7
        for t in list(m._forward_tasks):   # 매달린 태스크 정리
            t.cancel()
        await asyncio.gather(*m._forward_tasks, return_exceptions=True)

    asyncio.run(_run())

    conn = m.get_db()
    pending = conn.execute("SELECT COUNT(*) FROM scoring_dlq").fetchone()[0]
    conn.close()
    assert pending == 7, "상한 초과 이벤트는 내구 DLQ 로 스풀돼 무손실이어야 한다"


def test_forward_dispatch_creates_tasks_under_cap(tmp_path, monkeypatch):
    """정상 범위(상한 미만)에서는 shed 없이 평소대로 포워딩 태스크를 만든다(거짓 shed 방지)."""
    m = _load_collector(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "_FORWARD_MAX_INFLIGHT", 512)

    async def _hang(_event):
        await asyncio.Event().wait()
    monkeypatch.setattr(m, "_forward_to_scoring_engine", _hang)

    async def _run():
        shed0 = m._METRICS["forward_shed_to_dlq"]
        for i in range(10):
            m._dispatch_forward(_mk_event(m, i))
        assert len(m._forward_tasks) == 10
        assert m._METRICS["forward_shed_to_dlq"] == shed0, "상한 미만인데 shed 가 발생했다"
        for t in list(m._forward_tasks):
            t.cancel()
        await asyncio.gather(*m._forward_tasks, return_exceptions=True)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# (5) S-11: scoring 장기 완전 중단 시 scoring_dlq on-disk 무한 성장 상한(기본 OFF·폐기 가시화).
# ---------------------------------------------------------------------------
# #138 의 DLQ shed 는 RSS 를 bounded 로 만들지만, scoring 이 장기 완전 중단되면 재전달이 안 돼
# scoring_dlq 가 on-disk 로 무한 성장(디스크 고갈)할 수 있다. _prune_dlq 가 age/row 상한으로 이를 막되,
# 행 폐기 = 미전달 이벤트 유실이므로 기본 OFF(0-유실 유지)·opt-in·폐기는 dlq_drop 으로 계측(조용한 유실 금지).
def _dlq_count(m):
    conn = m.get_db()
    try:
        return conn.execute("SELECT COUNT(*) FROM scoring_dlq").fetchone()[0]
    finally:
        conn.close()


def test_dlq_prune_disabled_by_default_keeps_all(tmp_path, monkeypatch):
    """기본값(둘 다 0)에서는 아무것도 폐기하지 않는다 — 현행 무손실 계약 유지."""
    m = _load_collector(tmp_path, monkeypatch)
    for i in range(50):
        m._spool_to_dlq(f"k{i}", {"event_id": f"k{i}"}, "HTTP 503")
    drop0 = m._METRICS["dlq_drop"]
    assert m._prune_dlq() == 0
    assert _dlq_count(m) == 50, "기본 OFF 인데 DLQ 가 폐기됐다"
    assert m._METRICS["dlq_drop"] == drop0


def test_dlq_prune_by_row_cap_drops_oldest_and_counts(tmp_path, monkeypatch):
    """row 상한: 최신 N 건만 남기고 가장 오래된 것부터 폐기, 폐기 건수는 dlq_drop 에 계측."""
    m = _load_collector(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "_DLQ_MAX_ROWS", 10)
    # created_at 을 명시적으로 증가시켜 '오래된→최신' 순서를 결정론적으로 만든다.
    conn = m.get_db()
    for i in range(30):
        conn.execute(
            "INSERT INTO scoring_dlq (event_id, payload, attempts, last_error, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (f"r{i:02d}", json.dumps({"event_id": f"r{i:02d}"}), 3, "HTTP 503", 1000.0 + i),
        )
    conn.commit(); conn.close()
    drop0 = m._METRICS["dlq_drop"]

    dropped = m._prune_dlq()
    assert dropped == 20, f"20 건 폐기 예상, 실제 {dropped}"
    assert _dlq_count(m) == 10
    assert m._METRICS["dlq_drop"] == drop0 + 20, "폐기가 dlq_drop 으로 계측돼야 한다(조용한 유실 금지)"
    # 남은 것은 '최신' 10 건(r20~r29)이어야 한다.
    conn = m.get_db()
    kept = {row["event_id"] for row in conn.execute("SELECT event_id FROM scoring_dlq").fetchall()}
    conn.close()
    assert kept == {f"r{i:02d}" for i in range(20, 30)}, f"최신 10건이 아니라 {sorted(kept)}"


def test_dlq_prune_by_age_drops_old_rows(tmp_path, monkeypatch):
    """age 상한: cutoff 보다 오래된 행만 폐기, 최신 행은 보존."""
    m = _load_collector(tmp_path, monkeypatch)
    monkeypatch.setattr(m, "_DLQ_MAX_AGE_SEC", 3600)  # 1시간
    now = time.time()
    conn = m.get_db()
    conn.execute(
        "INSERT INTO scoring_dlq (event_id, payload, attempts, last_error, created_at) VALUES (?,?,?,?,?)",
        ("old", json.dumps({"event_id": "old"}), 3, "HTTP 503", now - 7200),  # 2시간 전(폐기)
    )
    conn.execute(
        "INSERT INTO scoring_dlq (event_id, payload, attempts, last_error, created_at) VALUES (?,?,?,?,?)",
        ("fresh", json.dumps({"event_id": "fresh"}), 3, "HTTP 503", now - 60),  # 1분 전(보존)
    )
    conn.commit(); conn.close()

    dropped = m._prune_dlq()
    assert dropped == 1
    conn = m.get_db()
    kept = {row["event_id"] for row in conn.execute("SELECT event_id FROM scoring_dlq").fetchall()}
    conn.close()
    assert kept == {"fresh"}, f"오래된 행만 폐기돼야 하는데 {sorted(kept)}"
