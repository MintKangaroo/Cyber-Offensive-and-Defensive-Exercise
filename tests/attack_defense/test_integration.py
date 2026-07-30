from __future__ import annotations

import pytest

from services.attack_defense.api import build_components
from services.attack_defense.game_engine import GameEngine

from .conftest import bootstrap
from .fakes import FakeChecker, FakeInspector, FakeRuntime


def test_three_team_two_service_round_and_restart_recovery(ad):
    bootstrap(ad)
    started = ad.engine.start_match("match-1", "operator")
    assert started["status"] == "running"
    current = ad.repo.current_round("match-1")
    assert current["status"] == "active"

    conn = ad.db.connect()
    flags = [dict(r) for r in conn.execute(
        "SELECT * FROM flags WHERE round_id=?", (current["id"],)
    )]
    checks = conn.execute(
        "SELECT COUNT(*) FROM service_checks WHERE round_id=?", (current["id"],)
    ).fetchone()[0]
    conn.close()
    assert len(flags) == 6
    assert checks == 30  # 6 instances × put + four functional checks

    victim_flag = next(
        row for row in flags
        if row["team_id"] == "team-2" and row["service_id"] == "service-vulnerable-notes"
    )
    token = ad.flags.reconstruct(victim_flag)
    first = ad.flags.validate_submission("match-1", "team-1", token, "competitor-1")
    replay = ad.flags.validate_submission("match-1", "team-1", token, "competitor-1")
    assert first.accepted and not replay.accepted

    finalized = ad.engine.force_finalize("match-1", "operator")
    assert finalized["status"] == "finalized"
    board = ad.scoring.scoreboard("match-1", public=False)
    assert board[0]["team_id"] == "team-1"
    assert board[0]["attack"] == 10
    assert all(row["availability"] == 10 for row in board)

    # Simulate a process restart: build a new component graph on the same DB,
    # then replace only external adapters. The persisted finalized round causes
    # the next deterministic round to be created.
    recovered = build_components(
        ad.settings, runtime=FakeRuntime(), inspector=FakeInspector()
    )
    checker = FakeChecker()
    recovered.checker = checker
    recovered.engine = GameEngine(
        recovered.db, recovered.repo, recovered.flags, recovered.scoring,
        checker, recovered.runtime, recovered.evidence, recovered.settings,
        owner_id="recovered-engine",
    )
    state = recovered.engine.tick_match("match-1")
    assert state["round"] == 2
    assert state["status"] == "active"


def test_round_recalculation_is_stable(ad):
    bootstrap(ad)
    ad.engine.start_match("match-1", "operator")
    current = ad.repo.current_round("match-1")
    ad.engine.force_finalize("match-1", "operator")
    before = ad.scoring.scoreboard("match-1", public=False)
    ad.scoring.calculate_round(current["id"], "operator")
    after = ad.scoring.scoreboard("match-1", public=False)
    assert before == after


def test_exercise_match_is_left_to_legacy_engine(ad):
    ad.repo.create_match(
        "Legacy Exercise", 5, 3, {}, "exercise-1", "exercise"
    )
    with pytest.raises(ValueError, match="legacy range/scenario"):
        ad.engine.start_match("exercise-1", "operator")
    assert ad.repo.current_round("exercise-1") is None


def test_hybrid_round_uses_flag_defense_without_merging_categories(ad):
    bootstrap(
        ad, match_id="hybrid-round", teams=3, services=2,
        mode="hybrid_live_fire",
    )
    ad.engine.start_match("hybrid-round", "operator")
    ad.engine.force_finalize("hybrid-round", "operator")
    board = ad.scoring.scoreboard("hybrid-round", public=False)
    assert all(row["flag_defense"] == 10 for row in board)
    assert all(row["defense"] == 0 for row in board)
    assert all(row["availability"] == 10 for row in board)
