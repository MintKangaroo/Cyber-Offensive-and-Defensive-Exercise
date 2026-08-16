"""라운드 다운타임 보정(감사 4.7) — 엔진 크래시/재기동 후 라운드 잔여시간 보존."""
from .conftest import bootstrap


def _active_round(ad, match_id="match-1"):
    r = ad.repo.current_round(match_id)
    assert r and r["status"] == "active", r
    return r


def test_downtime_extends_ends_at(ad):
    bootstrap(ad, teams=2, services=1)
    ad.engine.start_match("match-1", "operator")
    ad.engine.tick_match("match-1")            # 라운드 active화
    r = _active_round(ad)

    # 크래시 시뮬레이션: last_check_at 을 임계값보다 훨씬 과거로 되감고, ends_at 은 아직 안 지남.
    now = ad.db.server_time(ad.db.connect())
    gap = 500.0
    with ad.db.transaction(immediate=True) as conn:
        conn.execute("UPDATE rounds SET last_check_at=?, ends_at=? WHERE id=?",
                     (now - gap, now + 10.0, r["id"]))
    ends_before = now + 10.0

    ad.engine.tick_match("match-1")            # 다운타임 감지 → ends_at += gap
    r2 = ad.repo.current_round("match-1")
    # 라운드가 만료 전환되지 않고, ends_at 이 다운타임만큼 뒤로 밀렸다.
    assert r2["status"] == "active", r2
    assert float(r2["ends_at"]) >= ends_before + gap - 5, (r2["ends_at"], ends_before, gap)


def test_no_compensation_on_normal_tick(ad):
    bootstrap(ad, teams=2, services=1)
    ad.engine.start_match("match-1", "operator")
    ad.engine.tick_match("match-1")
    r = _active_round(ad)
    ends_before = float(r["ends_at"])
    # 정상 tick(방금 체크됨) → gap 작음 → 보정 없음.
    ad.engine.tick_match("match-1")
    r2 = ad.repo.current_round("match-1")
    assert abs(float(r2["ends_at"]) - ends_before) < 2, (r2["ends_at"], ends_before)
