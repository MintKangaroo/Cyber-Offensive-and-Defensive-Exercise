"""
B0 계약 검증 테스트
====================
계약 스키마가 의도대로 동작하는지 확인. Claude Code가 계약 변경 시 회귀 방지.
실행: python -m pytest tests/ -v   (또는 python tests/test_contracts.py)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.event_schema import Event, EventType, RedPhase, Actor, RED_POINTS, BLUE_POINTS, SCHEMA_VERSION
from shared.siem_schema import NormalizedEvent, NetEndpoint, SEVERITY_MAP
from shared.challenge_schema import Challenge, Scenario, Difficulty
from shared.api_contract import ScoreAdjustRequest, GradeResult
from datetime import datetime, timezone


def test_event_deterministic_id():
    """동일 인자 → 동일 event_id (dedup 보증)."""
    a = Event.make_id("team_alpha", "ground_station", "GS-001", "step1")
    b = Event.make_id("team_alpha", "ground_station", "GS-001", "step1")
    c = Event.make_id("team_alpha", "ground_station", "GS-001", "step2")
    assert a == b
    assert a != c
    print("  ✓ deterministic event_id")


def test_event_construction():
    e = Event(
        event_id=Event.make_id("t", "ground_station", "GS-001", "x"),
        event_type=EventType.red_attack_started,
        actor=Actor.red,
        target_asset="ground_station",
        vuln_id="GS-001",
        phase=RedPhase.initial_access,
        trace_id=Event.new_trace_id(),
        challenge_id="WEB-002",
    )
    assert e.schema_version == SCHEMA_VERSION
    assert e.phase == RedPhase.initial_access
    dumped = e.model_dump(mode="json")
    assert dumped["event_type"] == "red_attack_started"
    print("  ✓ event construction + json dump")


def test_points_table():
    """점수표가 제안서 10장과 일치."""
    assert RED_POINTS[RedPhase.initial_access] == 20
    assert RED_POINTS[RedPhase.privilege_escalation] == 30
    assert RED_POINTS[RedPhase.lateral_movement] == 30
    assert RED_POINTS[RedPhase.data_exfiltration] == 50
    assert RED_POINTS[RedPhase.objective] == 100
    assert BLUE_POINTS["patch_verified"] == 50
    assert BLUE_POINTS["detection_success"] == 20
    assert BLUE_POINTS["block_success"] == 30
    print("  ✓ score table matches proposal ch.10")


def test_normalized_event():
    ne = NormalizedEvent(
        event_id="01J000000000000000000000AA",
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        source_type="suricata",
        severity=SEVERITY_MAP["high"],
        category="intrusion",
        src=NetEndpoint(ip="10.13.37.66", port=40001),
        dst=NetEndpoint(ip="10.0.0.10", port=8001),
        signature="ET WEB SQLi",
        mitre=["T1190"],
    )
    assert ne.severity == 3
    assert ne.src.ip == "10.13.37.66"
    assert ne.raw == {}  # 기본 보존 필드
    print("  ✓ normalized (SIEM) event")


def test_challenge_id_validation():
    ok = Challenge(id="WEB-002", title="t", category="web", difficulty="medium",
                   points={"red": 150, "blue": 150})
    assert ok.id == "WEB-002"
    for bad in ["web-002", "WEB2", "WEBB-02", "W-002"]:
        try:
            Challenge(id=bad, title="t", category="web", difficulty="easy",
                      points={"red": 1, "blue": 1})
            assert False, f"should reject {bad}"
        except Exception:
            pass
    print("  ✓ challenge id format validation")


def test_scenario_schema():
    sc = Scenario(
        id="SAT-KILLCHAIN-01", name="test", target_asset="ground_station",
        initial_vuln_state={"GS-001": "vulnerable", "GS-004": "patched"},
        stages=[{"stage": 1, "name": "recon", "objective_event": "red_attack_started",
                 "match": {"vuln_id": "GS-005"}, "points": 20}],
    )
    assert sc.stages[0].points == 20
    assert sc.initial_vuln_state["GS-004"] == "patched"
    print("  ✓ scenario schema")


def test_score_adjust_requires_reason():
    """교관 점수조정은 reason 필수(pydantic 필수 필드)."""
    ScoreAdjustRequest(team_id="t", actor="red", delta=10, reason="manual correction")
    try:
        ScoreAdjustRequest(team_id="t", actor="red", delta=10)  # reason 없음
        assert False, "should require reason"
    except Exception:
        pass
    print("  ✓ score adjust requires reason")


def test_grade_result():
    g = GradeResult(passed=True, points=150, detail="flag correct")
    assert g.passed and g.points == 150
    print("  ✓ grade result")


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"Running {len(tests)} contract tests...\n")
    for t in tests:
        t()
    print(f"\n✅ ALL {len(tests)} CONTRACT TESTS PASSED")
