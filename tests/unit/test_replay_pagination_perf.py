"""R-2 회귀(audit/103): /replay/page 가 대형 events.db 에서도 인덱스 기반으로 동작하도록
scenario 복합 인덱스 + EXISTS 스냅샷 상한을 고정한다.

8h 소크에서 ~91만 이벤트 DB의 reconcile/AAR 이 페이지당 6.5s(매 페이지 TEMP B-TREE 재정렬)로
실용 불가였다. 수정: idx_events_scn_ts(scenario_id,timestamp,event_id) + 스냅샷 상한을
event_id IN(저널 전체) → EXISTS 상관서브쿼리로 변경(결과 동일, 인덱스 정렬 사용).
"""
from __future__ import annotations

import time

from fastapi.testclient import TestClient


def _load(monkeypatch, tmp_path):
    from services.event_collector import main as mod
    monkeypatch.setattr(mod, "DB_PATH", tmp_path / "events.db")
    monkeypatch.setattr(mod, "_writer_conn", None)
    monkeypatch.setenv("RBAC_ALLOW_INSECURE_DEV", "true")
    mod.init_db()
    return mod


def _persist(mod, n, scenario):
    from shared.event_schema import Event
    evs = [
        Event(event_id=f"{scenario}-{i}", event_type="asset_compromised",
              timestamp=1000.0 + i, actor="red", team_id="alpha",
              scenario_id=scenario, target_asset="asset-a", metadata={})
        for i in range(n)
    ]
    assert all(mod._persist_batch(evs))


def test_scn_ts_index_exists(monkeypatch, tmp_path):
    mod = _load(monkeypatch, tmp_path)
    conn = mod.get_db()
    idx = {r[1] for r in conn.execute("PRAGMA index_list(events)").fetchall()}
    conn.close()
    assert "idx_events_scn_ts" in idx, f"R-2 성능 인덱스 누락: {idx}"


def test_replay_page_paginates_scenario_completely_and_in_order(monkeypatch, tmp_path):
    mod = _load(monkeypatch, tmp_path)
    _persist(mod, 25, "exercise-a")
    _persist(mod, 10, "exercise-b")  # 다른 scenario 는 섞이면 안 됨(스냅샷·스코프)
    client = TestClient(mod.app)
    seen, cursor, pages = [], "", 0
    while True:
        r = client.get("/replay/page", params={"scenario_id": "exercise-a",
                                               "cursor": cursor, "limit": 7}).json()
        seen.extend(e["event_id"] for e in r["events"])
        pages += 1
        if r.get("complete"):
            break
        cursor = r["next_cursor"]
        assert cursor, "미완인데 next_cursor 없음"
        assert pages < 50, "페이지네이션이 끝나지 않음"
    # exercise-a 25건 전부, 중복 없이, (timestamp,event_id) 순서로
    assert seen == [f"exercise-a-{i}" for i in range(25)], seen[:5]
    assert pages >= 4  # limit 7 로 25건 → 여러 페이지


def test_replay_page_does_not_use_full_journal_in_subquery(monkeypatch, tmp_path):
    # 느린 'event_id IN (SELECT event_id FROM stream_journal ...)' 패턴 재도입 방지(성능 회귀 가드).
    import inspect
    from services.event_collector import main as mod
    src = inspect.getsource(mod.replay_page)
    assert "EXISTS (SELECT 1 FROM stream_journal" in src, "EXISTS 스냅샷 상한이 사라짐"
    assert "event_id IN (SELECT event_id FROM stream_journal" not in src, \
        "느린 IN(저널 전체) 패턴이 재도입됨 — R-2 성능 회귀"
