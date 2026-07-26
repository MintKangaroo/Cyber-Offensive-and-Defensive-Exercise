"""
시나리오 저작(P1-3) 순수 로직 계약 고정.
- lint: 스키마 너머 의미 검증(중복 stage·requires 참조·최종 stage·vuln 참조)
- dry_run: 타임라인 투영 + errors/warnings 집계
- phase_clock: 경과 시간 → 현재 예상 stage/잔여
"""
from services.scenario_engine.authoring import lint_scenario, dry_run, project_timeline, phase_clock


def _base():
    return {
        "id": "T-01", "name": "테스트", "time_limit_sec": 600,
        "initial_vuln_state": {"V-1": "vulnerable", "V-2": "vulnerable", "V-3": "vulnerable"},
        "stages": [
            {"stage": 1, "name": "정찰", "objective_event": "flag_exfiltrated", "match": {"vuln_id": "V-1"}, "points": 20},
            {"stage": 2, "name": "장악", "objective_event": "red_attack_started", "match": {"vuln_id": "V-2"}, "points": 30, "requires_stage": 1},
            {"stage": 3, "name": "목표", "objective_event": "red_objective_success", "match": {"vuln_id": "V-3"}, "points": 50, "requires_stage": 2, "is_final": True},
        ],
    }


def _codes(issues):
    return {i["code"] for i in issues}


def test_clean_scenario_no_errors():
    issues = lint_scenario(_base())
    assert not [i for i in issues if i["level"] == "error"]


def test_missing_name_is_error():
    s = _base(); del s["name"]
    assert "missing_field" in _codes(lint_scenario(s))


def test_duplicate_stage_numbers_error():
    s = _base(); s["stages"][1]["stage"] = 1
    assert "duplicate_stage" in _codes([i for i in lint_scenario(s) if i["level"] == "error"])


def test_requires_unknown_stage_error():
    s = _base(); s["stages"][2]["requires_stage"] = 9
    assert "bad_requires" in _codes(lint_scenario(s))


def test_requires_forward_or_self_error():
    s = _base(); s["stages"][0]["requires_stage"] = 3   # stage1 이 stage3 요구(전방 참조)
    assert "forward_requires" in _codes(lint_scenario(s))


def test_no_final_stage_warns():
    s = _base()
    for st in s["stages"]:
        st.pop("is_final", None)
    assert "no_final_stage" in _codes([i for i in lint_scenario(s) if i["level"] == "warning"])


def test_vuln_not_in_initial_state_warns():
    s = _base(); s["stages"][0]["match"]["vuln_id"] = "V-999"
    assert "unknown_vuln" in _codes(lint_scenario(s))


def test_nonpositive_points_warns():
    s = _base(); s["stages"][0]["points"] = 0
    assert "nonpositive_points" in _codes(lint_scenario(s))


def test_project_timeline_equal_split():
    tl = project_timeline(_base())
    assert len(tl) == 3
    assert tl[0]["start_sec"] == 0 and tl[-1]["end_sec"] == 600
    # 균등 분할 200초씩
    assert tl[0]["end_sec"] == 200 and tl[1]["start_sec"] == 200


def test_project_timeline_uses_expected_sec():
    s = _base()
    s["stages"][0]["expected_sec"] = 100
    s["stages"][1]["expected_sec"] = 200
    s["stages"][2]["expected_sec"] = 300
    tl = project_timeline(s)
    assert [t["end_sec"] for t in tl] == [100, 300, 600]


def test_dry_run_aggregates():
    r = dry_run(_base())
    assert r["ok"] is True and r["total_points"] == 100 and len(r["timeline"]) == 3


def test_dry_run_reports_errors():
    s = _base(); s["stages"][1]["stage"] = 1   # 중복
    r = dry_run(s)
    assert r["ok"] is False and r["error_count"] >= 1


def test_phase_clock_midway():
    pc = phase_clock(_base(), elapsed_sec=250)   # 200~400 구간 = stage 2
    assert pc["current_stage"] == 2 and pc["remaining_sec"] == 350


def test_phase_clock_overtime():
    pc = phase_clock(_base(), elapsed_sec=999)
    assert pc["remaining_sec"] == 0 and pc["overtime"] is True


def _crossover():
    return {
        "id": "X-01", "name": "크로스오버", "time_limit_sec": 900,
        "initial_vuln_state": {"A-1": "vulnerable", "A-2": "vulnerable"},
        "phase_1_network": {"actor": "red", "stages": [
            {"stage": 1, "name": "발판", "match": {"vuln_id": "A-1"}, "points": 25},
            {"stage": 2, "name": "탈취", "match": {"vuln_id": "A-2"}, "points": 40}]},
        "phase_2_forensics": {"actor": "blue", "stages": [
            {"stage": 1, "name": "재구성", "match": {"vuln_id": "A-1"}, "points": 30}]},
        "blue_objectives": [{"name": "탐지", "match_alert": "X", "points": 10}],
    }


def test_crossover_collects_phase_stages_no_false_error():
    # phase_*.stages 를 수집 → 'stages 없음' 오탐 없어야 함. stage 번호 phase별 리셋도 중복 아님.
    errs = [i for i in lint_scenario(_crossover()) if i["level"] == "error"]
    assert errs == []


def test_crossover_timeline_across_phases():
    r = dry_run(_crossover())
    assert r["stage_count"] == 3 and r["total_points"] == 95 and len(r["timeline"]) == 3
