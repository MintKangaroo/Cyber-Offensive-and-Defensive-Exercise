"""라운드 다운타임 보정(감사 4.7) — 엔진 크래시/재기동 후 라운드 잔여시간 보존.

보정은 '한 라운드 이내'의 짧은 중단에만 적용한다. gap 이 라운드 지속시간을 넘으면 라운드는
다운타임 동안 이미 만료된 것이므로 보정하지 않고 finalize 되어 새 라운드+새 플래그가 발급된다
(영구 볼륨 매치를 오래 방치했다 재기동할 때 라운드가 미래로 무한 연장되고 플래그 valid_until 이
만료된 채 고착돼 flag 제출이 거부되던 회귀를 막는다).
"""
from .conftest import bootstrap


def _active_round(ad, match_id="match-1"):
    r = ad.repo.current_round(match_id)
    assert r and r["status"] == "active", r
    return r


def test_downtime_extends_ends_at(ad):
    # 한 라운드 이내의 짧은 중단: round_duration 을 임계값보다 크게 잡아 보정이 유효한 구간을 만든다.
    # ad 픽스처: check_interval=60 → downtime_threshold=120. round_duration=600 으로 gap=200 이
    # threshold(120)<gap<=round_duration(600) 구간에 들어 보정이 적용된다.
    bootstrap(ad, teams=2, services=1, round_duration=600)
    ad.engine.start_match("match-1", "operator")
    ad.engine.tick_match("match-1")            # 라운드 active화
    r = _active_round(ad)

    now = ad.db.server_time(ad.db.connect())
    gap = 200.0
    with ad.db.transaction(immediate=True) as conn:
        conn.execute("UPDATE rounds SET last_check_at=?, ends_at=? WHERE id=?",
                     (now - gap, now + 10.0, r["id"]))
    ends_before = now + 10.0

    ad.engine.tick_match("match-1")            # 다운타임 감지 → ends_at += gap
    r2 = ad.repo.current_round("match-1")
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


def test_long_downtime_does_not_extend_and_round_rolls_over(ad):
    """gap 이 라운드 지속시간을 크게 넘으면(장기 방치) 보정하지 않고 라운드가 넘어가며,
    새 라운드가 '현재 유효한' 플래그를 발급한다(valid_until 만료 고착 회귀 방지)."""
    bootstrap(ad, teams=2, services=1, round_duration=5)
    ad.engine.start_match("match-1", "operator")
    ad.engine.tick_match("match-1")            # 라운드 1 active + 플래그 발급
    r1 = _active_round(ad)

    # 장기 다운타임 시뮬레이션: last_check 와 ends_at 을 아주 먼 과거로. (gap >> round_duration)
    now = ad.db.server_time(ad.db.connect())
    with ad.db.transaction(immediate=True) as conn:
        conn.execute("UPDATE rounds SET last_check_at=?, ends_at=? WHERE id=?",
                     (now - 1_000_000.0, now - 999_000.0, r1["id"]))

    # 재기동 후 tick: 보정으로 미래 연장되지 않고 라운드가 scoring/finalize 로 진행되어야 한다.
    ad.engine.tick_match("match-1")            # 만료 감지 → scoring → finalize
    ad.engine.tick_match("match-1")            # 새 라운드 생성 + 초기화(플래그 재발급)
    r2 = ad.repo.current_round("match-1")
    assert r2["status"] == "active", r2
    assert int(r2["sequence"]) > int(r1["sequence"]), (r2["sequence"], r1["sequence"])
    # 새 라운드의 ends_at 은 미래(무한 연장 아님, 한 라운드 이내).
    now2 = ad.db.server_time(ad.db.connect())
    assert now2 <= float(r2["ends_at"]) <= now2 + 5 + 2, (r2["ends_at"], now2)
