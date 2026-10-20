"""
Exercise Overview 전(全) 팀 집계 순수 로직 계약 고정 (대회급 격차 #3 (a)).
=========================================================================
mock 된 소스 응답으로 월보드 데이터 소스를 검증한다:
  - all-up(모든 소스 정상)
  - 일부 소스 down(graceful degradation)
  - empty(매치 없음 / 자산 미모니터링)
  - open 인시던트 집계(closed 제외)
  - availability 평균(모니터링 중인 자산만)
도커/라이브 스택 없이 순수 함수만 돌린다.
"""
from services.range_control.exercise_overview import (
    aggregate_overview, compute_weighted_total, weights_from_env, DEFAULT_WEIGHTS,
)


def _match(match_id="m1", scenario_id="s1", range_id="r1",
           red=("red-a",), blue=("blue-a",), twin_set=("power_plant", "water_utility")):
    return {
        "match_id": match_id, "scenario_id": scenario_id, "range_id": range_id,
        "red_teams": list(red), "blue_teams": list(blue), "twin_set": list(twin_set),
        "team_index": {t: {"side": "red", "match_id": match_id, "range_id": range_id} for t in red}
                    | {t: {"side": "blue", "match_id": match_id, "range_id": range_id} for t in blue},
    }


def _all_up_sources():
    scores = {"s1": {"teams": {"red-a": {"red": 120, "blue": 0}, "blue-a": {"red": 0, "blue": 80}}}}
    injects = {"s1": {"scoreboard": [
        {"team_id": "blue-a", "delivered": 4, "responded": 3, "score_pct": 75},
    ]}}
    incidents = {"s1": {"incidents": [
        {"team_id": "blue-a", "status": "new"},
        {"team_id": "blue-a", "status": "triage"},
        {"team_id": "blue-a", "status": "closed"},   # closed → open 으로 세지 않음
        {"team_id": "red-a", "status": "contained"},
    ]}}
    noc = {"assets": {
        "power_plant": {"uptime_pct_1h": 100.0, "up": True},
        "water_utility": {"uptime_pct_1h": 80.0, "up": True},
    }}
    return scores, injects, incidents, noc


def test_all_up_full_aggregation():
    scores, injects, incidents, noc = _all_up_sources()
    ss = {"scores": "ready", "injects": "ready", "incidents": "ready", "noc": "ready"}
    out = aggregate_overview([_match()], scores, injects, incidents, noc, ss)

    assert len(out["matches"]) == 1
    mrow = out["matches"][0]
    # (100 + 80) / 2 = 90.0
    assert mrow["availability_pct"] == 90.0
    assert mrow["twins_monitored"] == 2

    teams = {t["team_id"]: t for t in out["teams"]}
    assert set(teams) == {"red-a", "blue-a"}

    red = teams["red-a"]
    assert red["side"] == "red"
    assert red["red_score"] == 120 and red["blue_score"] == 0
    assert red["open_incidents"] == 1          # contained
    assert red["availability_pct"] == 90.0     # 매치 공유

    blue = teams["blue-a"]
    assert blue["blue_score"] == 80
    assert blue["inject_delivered"] == 4 and blue["inject_responded"] == 3
    assert blue["inject_score_pct"] == 75
    assert blue["open_incidents"] == 2         # new + triage (closed 제외)

    assert out["source_status"] == ss


def test_some_sources_down_degrades():
    """scores/injects/incidents 소스가 down(빈 dict) 이어도 나머지는 집계된다."""
    _, _, _, noc = _all_up_sources()
    ss = {"scores": "unavailable", "injects": "unavailable",
          "incidents": "unavailable", "noc": "ready"}
    out = aggregate_overview([_match()], {}, {}, {}, noc, ss)

    teams = {t["team_id"]: t for t in out["teams"]}
    assert set(teams) == {"red-a", "blue-a"}      # 팀은 매치 레지스트리에서 나옴
    for t in teams.values():
        assert t["red_score"] == 0 and t["blue_score"] == 0
        assert t["inject_delivered"] == 0 and t["inject_score_pct"] == 0
        assert t["open_incidents"] == 0
        assert t["availability_pct"] == 90.0      # NOC 는 살아있으므로 유지
    assert out["source_status"]["scores"] == "unavailable"


def test_noc_down_availability_none():
    """NOC 가 down(빈 dict) 이면 availability 는 None(N/A), 나머지 지표는 유지."""
    scores, injects, incidents, _ = _all_up_sources()
    out = aggregate_overview([_match()], scores, injects, incidents, {}, None)
    assert out["matches"][0]["availability_pct"] is None
    assert out["matches"][0]["twins_monitored"] == 0
    for t in out["teams"]:
        assert t["availability_pct"] is None
    # source_status 를 안 넘기면 결과에 키가 없다.
    assert "source_status" not in out


def test_partial_twin_monitoring_averages_monitored_only():
    """twin_set 중 NOC 가 모니터링하는 자산만 평균(미모니터링 자산은 무시)."""
    scores, injects, incidents, _ = _all_up_sources()
    m = _match(twin_set=("power_plant", "water_utility", "hospital_ot"))
    noc = {"assets": {"power_plant": {"uptime_pct_1h": 50.0}}}  # 1개만 모니터링
    out = aggregate_overview([m], scores, injects, incidents, noc, None)
    assert out["matches"][0]["availability_pct"] == 50.0
    assert out["matches"][0]["twins_monitored"] == 1


def test_empty_no_matches():
    out = aggregate_overview([], {}, {}, {}, {"assets": {}}, {"noc": "ready"})
    assert out["matches"] == [] and out["teams"] == []


def test_team_index_fallback_from_team_lists():
    """구버전 매치(team_index 없음)도 red_teams/blue_teams 에서 팀을 유도한다."""
    m = {"match_id": "m2", "scenario_id": "s2", "range_id": "r1",
         "red_teams": ["red-x"], "blue_teams": ["blue-x"], "twin_set": []}
    out = aggregate_overview([m], {}, {}, {}, {}, None)
    sides = {t["team_id"]: t["side"] for t in out["teams"]}
    assert sides == {"red-x": "red", "blue-x": "blue"}


def test_multiple_matches_scenario_isolation():
    """서로 다른 scenario_id 를 가진 매치는 각자의 소스 응답으로 집계된다."""
    m1 = _match(match_id="m1", scenario_id="s1", red=("r1t",), blue=())
    m2 = _match(match_id="m2", scenario_id="s2", red=("r2t",), blue=())
    scores = {"s1": {"teams": {"r1t": {"red": 10}}}, "s2": {"teams": {"r2t": {"red": 99}}}}
    out = aggregate_overview([m1, m2], scores, {}, {}, {}, None)
    byteam = {t["team_id"]: t for t in out["teams"]}
    assert byteam["r1t"]["red_score"] == 10
    assert byteam["r2t"]["red_score"] == 99
    assert byteam["r1t"]["match_id"] == "m1" and byteam["r2t"]["match_id"] == "m2"


# ── 단일 가중 총점 (대회급 격차 #3 (b)) ─────────────────────────────────────────

def test_weighted_total_folds_availability_and_components():
    """twin availability 가 가중 총점에 실제로 반영된다(기본 가중치)."""
    scores, injects, incidents, noc = _all_up_sources()
    out = aggregate_overview([_match()], scores, injects, incidents, noc, None)
    teams = {t["team_id"]: t for t in out["teams"]}
    # blue-a: blue 80 + avail 90%*300(=270) + inject 75%*200(=150) - 2*10(=20) = 480
    assert teams["blue-a"]["weighted_total"] == 480.0
    assert teams["blue-a"]["availability_scored"] is True
    # red-a: red 120 + avail 270 + inject 0 - 1*10 = 380
    assert teams["red-a"]["weighted_total"] == 380.0
    assert out["weights"] == DEFAULT_WEIGHTS


def test_ranking_sorted_desc_with_ranks():
    scores, injects, incidents, noc = _all_up_sources()
    out = aggregate_overview([_match()], scores, injects, incidents, noc, None)
    ranking = out["ranking"]
    assert [r["team_id"] for r in ranking] == ["blue-a", "red-a"]  # 480 > 380
    assert [r["rank"] for r in ranking] == [1, 2]
    assert ranking[0]["weighted_total"] == 480.0


def test_availability_unscored_when_noc_down():
    """NOC down → availability_scored False, 가용성 기여 0(총점에서 빠짐)."""
    scores, injects, incidents, _ = _all_up_sources()
    out = aggregate_overview([_match()], scores, injects, incidents, {}, None)
    blue = {t["team_id"]: t for t in out["teams"]}["blue-a"]
    assert blue["availability_scored"] is False
    # avail 기여 0: blue 80 + inject 150 - 20 = 210 (270 빠짐)
    assert blue["weighted_total"] == 210.0


def test_custom_weights_param_overrides():
    scores, injects, incidents, noc = _all_up_sources()
    w = dict(DEFAULT_WEIGHTS, availability=0.0, inject=0.0, incident_penalty=0.0)
    out = aggregate_overview([_match()], scores, injects, incidents, noc, None, weights=w)
    blue = {t["team_id"]: t for t in out["teams"]}["blue-a"]
    assert blue["weighted_total"] == 80.0  # blue_score 만 남음
    assert out["weights"]["availability"] == 0.0


def test_weights_from_env_override_and_bad_value_ignored():
    w = weights_from_env({"EXERCISE_WEIGHT_AVAILABILITY": "100", "EXERCISE_WEIGHT_RED": "oops"})
    assert w["availability"] == 100.0           # 덮어씀
    assert w["red"] == DEFAULT_WEIGHTS["red"]    # 잘못된 값은 무시(기본 유지)


def test_compute_weighted_total_incident_cap():
    """open 인시던트 페널티는 incident_cap 까지만."""
    w = dict(DEFAULT_WEIGHTS, incident_cap=3.0, incident_penalty=10.0, availability=0.0, inject=0.0)
    row = {"availability_pct": None, "inject_score_pct": 0, "open_incidents": 50,
           "red_score": 0, "blue_score": 100}
    # 50건이지만 cap 3 → -30
    assert compute_weighted_total(row, w) == 70.0
