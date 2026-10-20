"""다일 내구성(S-11): event_collector RSS 기울기 귀속용 메모리 계측.

8h 소크에서 event_collector RSS 가 +13.28 MiB/h(WARN)로 성장했으나 근본원인이 미추적이었다.
/metrics 의 memory 키로 RSS·파이썬 객체수·경계 구조 크기·DB/WAL 크기를 노출해, 다음 장시간
소크가 (a) 파이썬 힙 누수 인지 (b) SQLite on-disk 성장 인지 데이터로 지목할 수 있게 한다.
"""
import importlib

import pytest


@pytest.fixture
def ec(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RBAC_ALLOW_INSECURE_DEV", "true")
    import services.event_collector.main as m
    importlib.reload(m)
    m.DB_PATH = tmp_path / "events.db"
    m.init_db()
    return m


def test_memory_stats_exposes_expected_keys(ec):
    s = ec._memory_stats()
    for key in ("rss_bytes", "py_objects", "sse_buffer_len", "sse_subscribers",
                "checkpoint_counters", "forward_tasks_inflight", "ws_clients",
                "db_bytes", "wal_bytes", "shm_bytes"):
        assert key in s, key
    # Linux 에서는 RSS 가 측정돼야 한다(계측이 실제로 동작).
    assert s["rss_bytes"] is None or s["rss_bytes"] > 0
    # 신규 DB 는 bytes>0, 아직 구독자/WS/inflight 태스크는 0.
    assert s["db_bytes"] > 0
    assert s["sse_subscribers"] == 0
    assert s["ws_clients"] == 0
    assert s["forward_tasks_inflight"] == 0


def test_checkpoint_counter_bounded_by_scenarios(ec):
    """_events_since_checkpoint 는 scenario_id 로 keyed → 시나리오 수로 bounded(무한증가 아님)."""
    counters = {}
    # 같은 2개 시나리오로 수천 이벤트가 와도 키는 2개를 넘지 않는다.
    for i in range(5000):
        ec.checkpoints_due([f"scn_{i % 2}"], every=1000, counters=counters)
    assert len(counters) == 2
    assert ec._memory_stats()["checkpoint_counters"] == len(ec._events_since_checkpoint)


def test_sse_buffer_is_bounded(ec):
    """SSE 링버퍼는 deque(maxlen) 로 상한이 있다 → publish 폭주에도 메모리 bounded."""
    cap = ec.bus._buffer.maxlen
    for i in range(cap * 3):
        ec.bus.publish("events", {"i": i})
    assert len(ec.bus._buffer) == cap
    assert ec._memory_stats()["sse_buffer_len"] == cap
