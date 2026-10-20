"""다일(48~72h) 내구성(S-11): SIEM SQLite 저장소 rollover/retention.

event_collector 의 _prune_old_events() + 백그라운드 루프 패턴을 SIEM 의 두 SQLite 저장소
(events+events_fts, alerts)로 확장했다. 안전 기본값(SIEM_RETENTION_DAYS=0)=비활성.
"""
import importlib
import time

from services.siem.storage.sqlite_backend import SqliteBackend
from services.siem.storage.alert_store import AlertStore


def test_backend_prune_by_age_keeps_fts_consistent(tmp_path):
    """events 를 age 로 프루닝하면 외부콘텐츠 FTS 인덱스도 rebuild 되어 MATCH 가 깨지지 않는다."""
    import asyncio

    from shared.siem_schema import NormalizedEvent
    from datetime import datetime, timezone

    b = SqliteBackend(str(tmp_path / "siem.db"))
    now = time.time()

    def mk(eid, ts, msg):
        return NormalizedEvent(
            event_id=eid, timestamp=datetime.fromtimestamp(ts, tz=timezone.utc),
            ingested_at=datetime.fromtimestamp(ts, tz=timezone.utc),
            source_type="twin", source_ip="10.0.0.1", host="h", asset="power_plant",
            severity=3, category="recon", action="GET", signature="sig", signature_id="s1",
            mitre=["T1046"], message=msg, raw={}, tags=[],
        )

    asyncio.run(b.index(mk("fresh", now, "freshword")))
    asyncio.run(b.index(mk("stale", now - 3 * 86400, "staleword")))

    deleted = b.prune_older_than(now - 86400)  # 1일 초과 삭제
    assert deleted == 1

    # 남은 이벤트만 조회되고, FTS MATCH 도 정상(rebuild 로 고아 인덱스 제거).
    from shared.storage_interface import SearchQuery
    remaining = asyncio.run(b.search(SearchQuery(limit=10)))
    assert {e.event_id for e in remaining} == {"fresh"}
    hit = asyncio.run(b.search(SearchQuery(text="freshword", limit=10)))
    assert {e.event_id for e in hit} == {"fresh"}
    gone = asyncio.run(b.search(SearchQuery(text="staleword", limit=10)))
    assert gone == []


def test_alert_store_prune_by_age(tmp_path):
    s = AlertStore(str(tmp_path / "alerts.db"))
    now = time.time()
    s.save("r1", "fresh alert", 4, ["T1"], now, "d", {"team_id": "t1"})
    s.save("r2", "stale alert", 4, ["T1"], now - 3 * 86400, "d", {"team_id": "t1"})
    deleted = s.prune_older_than(now - 86400)
    assert deleted == 1
    titles = {a["title"] for a in s.list_alerts(limit=10)}
    assert titles == {"fresh alert"}


def test_backend_prune_nothing_when_all_fresh(tmp_path):
    import asyncio
    from shared.siem_schema import NormalizedEvent
    from datetime import datetime, timezone
    b = SqliteBackend(str(tmp_path / "siem.db"))
    now = time.time()
    asyncio.run(b.index(NormalizedEvent(
        event_id="a", timestamp=datetime.fromtimestamp(now, tz=timezone.utc),
        ingested_at=datetime.fromtimestamp(now, tz=timezone.utc), source_type="twin",
        source_ip="1.1.1.1", host="h", asset="x", severity=1, category="c", action="a",
        signature="s", signature_id="s1", mitre=[], message="m", raw={}, tags=[])))
    assert b.prune_older_than(now - 86400) == 0


def test_retention_disabled_by_default(tmp_path, monkeypatch):
    """안전 기본값: SIEM_RETENTION_DAYS 미설정(=0) 이면 오래된 데이터도 삭제하지 않는다."""
    monkeypatch.setenv("SIEM_DB_PATH", str(tmp_path / "siem.db"))
    monkeypatch.setenv("SIEM_ALERT_DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.delenv("SIEM_RETENTION_DAYS", raising=False)
    monkeypatch.setenv("RBAC_ALLOW_INSECURE_DEV", "true")
    import services.siem.api.main as m
    importlib.reload(m)
    assert m.SIEM_RETENTION_DAYS == 0

    now = time.time()
    m.alert_store.save("r", "old", 4, ["T1"], now - 10 * 86400, "d", {"team_id": "t1"})
    res = m._prune_siem_stores()
    assert res == {"events": 0, "alerts": 0}  # 비활성 → 0건
    assert len(m.alert_store.list_alerts(limit=10)) == 1  # 오래된 알림 보존


def test_retention_enabled_prunes(tmp_path, monkeypatch):
    monkeypatch.setenv("SIEM_DB_PATH", str(tmp_path / "siem.db"))
    monkeypatch.setenv("SIEM_ALERT_DB_PATH", str(tmp_path / "alerts.db"))
    monkeypatch.setenv("SIEM_RETENTION_DAYS", "1")
    monkeypatch.setenv("RBAC_ALLOW_INSECURE_DEV", "true")
    import services.siem.api.main as m
    importlib.reload(m)
    assert m.SIEM_RETENTION_DAYS == 1.0

    now = time.time()
    m.alert_store.save("r1", "fresh", 4, ["T1"], now, "d", {"team_id": "t1"})
    m.alert_store.save("r2", "stale", 4, ["T1"], now - 3 * 86400, "d", {"team_id": "t1"})
    res = m._prune_siem_stores()
    assert res["alerts"] == 1
    assert {a["title"] for a in m.alert_store.list_alerts(limit=10)} == {"fresh"}
