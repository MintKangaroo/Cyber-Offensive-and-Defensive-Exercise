"""event_collector 그룹 커밋(배치 라이터) — 처리량 최적화가 내구성·중복검사·응답
시맨틱을 그대로 보존함을 고정한다(≥600 EPS 병목 해소, [[u3-saturation-finding]] 후속).

핵심 회귀 방지:
  - stored/duplicate 응답이 배치 경유에도 정확(future 로 자기 이벤트 결과 수신).
  - 동시 버스트에서 커밋이 이벤트 수보다 적다(=여러 건이 한 트랜잭션으로 그룹 커밋).
  - 같은 배치 안의 중복 event_id 는 첫 건만 저장(seen 집합).
"""
from __future__ import annotations

import concurrent.futures
import importlib

import pytest
from fastapi.testclient import TestClient


def _load(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("RBAC_ALLOW_INSECURE_DEV", "true")  # /events dev 통과(SERVICE_TOKEN 없이)
    # scoring 포워딩은 이 테스트의 관심사가 아니다. 컨테이너 DNS 이름("scoring_engine")을
    # 테스트에서 조회하면 getaddrinfo 가 워커 스레드에서 블록돼 종료가 지연되므로, 즉시
    # 연결 거부되는 로컬 주소로 돌린다(포워딩은 DLQ 로 빠지고 저장 시맨틱엔 영향 없음).
    monkeypatch.setenv("SCORING_ENGINE_URL", "http://127.0.0.1:9")
    import services.event_collector.main as m
    importlib.reload(m)
    m.DB_PATH = tmp_path / "events.db"
    m.init_db()
    # reload 로 캐시된 writer 커넥션/큐 초기화(테스트 간 격리)
    m._writer_conn = None
    m._ingest_queue = None
    return m


def _event(eid: str) -> dict:
    return {
        "event_id": eid, "event_type": "red_attack_started", "timestamp": 1.0,
        "actor": "red", "team_id": "team-01", "scenario_id": "s",
        "target_asset": "power_plant", "metadata": {},
    }


def test_stored_and_duplicate_semantics(tmp_path, monkeypatch):
    m = _load(tmp_path, monkeypatch)
    with TestClient(m.app) as c:
        assert c.post("/events", json=_event("e1")).json() == {
            "stored": True, "duplicate": False, "event_id": "e1"}
        assert c.post("/events", json=_event("e1")).json() == {
            "stored": False, "duplicate": True, "event_id": "e1"}
        assert c.post("/events", json=_event("e2")).json()["stored"] is True
        rows = c.get("/events?limit=100").json()["events"]
        assert {r["event_id"] for r in rows} == {"e1", "e2"}


def test_concurrent_burst_group_commits(tmp_path, monkeypatch):
    m = _load(tmp_path, monkeypatch)
    n = 200
    with TestClient(m.app) as c:
        def post(i):
            return c.post("/events", json=_event(f"b-{i}")).json()
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
            outs = list(ex.map(post, range(n)))
        assert sum(1 for o in outs if o["stored"]) == n         # 전부 신규 저장
        assert len(c.get("/events?limit=1000").json()["events"]) == n
        met = c.get("/metrics").json()
        assert met["ingest_committed"] == n
        # 그룹 커밋 효과: 커밋 횟수가 이벤트 수보다 유의미하게 적어야 한다.
        assert met["ingest_batches"] < n
        assert met["ingest_batch_max_observed"] >= 2


def test_same_batch_duplicate_is_deduped(tmp_path, monkeypatch):
    m = _load(tmp_path, monkeypatch)
    from shared.event_schema import Event
    a1 = Event(**_event("dup"))
    a2 = Event(**_event("dup"))   # 같은 event_id 가 한 배치에
    b = Event(**_event("uniq"))
    results = m._persist_batch([a1, a2, b])
    assert results == [True, False, True]   # 첫 dup 만 저장
    conn = m.get_db()
    ids = {r["event_id"] for r in conn.execute("SELECT event_id FROM events").fetchall()}
    conn.close()
    assert ids == {"dup", "uniq"}
