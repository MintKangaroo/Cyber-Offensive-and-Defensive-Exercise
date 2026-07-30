from __future__ import annotations

import sqlite3

import pytest

from services.attack_defense.models import PATCH_TRANSITIONS, ROUND_TRANSITIONS, assert_transition
from services.attack_defense.mode_strategies import strategy_for
from services.attack_defense.scoring import ConfigurableScoringPolicy
from services.attack_defense.utils import stable_id

from .conftest import bootstrap


def test_flag_generation_is_deterministic_and_not_stored_plaintext(ad):
    bootstrap(ad, teams=2, services=1)
    round_row = ad.repo.create_round("match-1")
    first = ad.flags.issue_flag("match-1", round_row["id"], "team-1", "service-vulnerable-notes")
    second = ad.flags.issue_flag("match-1", round_row["id"], "team-1", "service-vulnerable-notes")
    assert first.token == second.token
    conn = ad.db.connect()
    row = conn.execute("SELECT * FROM flags WHERE id=?", (first.id,)).fetchone()
    conn.close()
    assert row["encrypted_token"] is None
    assert row["secret_reference"] == "hmac:v1"
    assert first.token not in str(dict(row))


def test_flag_expiry_uses_round_window(ad):
    bootstrap(ad, teams=2, services=1)
    r1 = ad.repo.create_round("match-1")
    issued = ad.flags.issue_flag("match-1", r1["id"], "team-1", "service-vulnerable-notes")
    ad.flags.mark_injected(issued.id, True)
    assert ad.flags.expire_flags("match-1", 3) == 0
    assert ad.flags.expire_flags("match-1", 4) == 1


def test_self_flag_and_duplicate_submission(ad):
    bootstrap(ad, teams=2, services=1)
    with ad.db.transaction(immediate=True) as conn:
        conn.execute("UPDATE matches SET status='running' WHERE id='match-1'")
    round_row = ad.repo.create_round("match-1")
    ad.repo.transition_round(round_row["id"], "initializing")
    now = __import__("time").time()
    ad.repo.transition_round(
        round_row["id"], "active", {"starts_at": now, "ends_at": now + 60}
    )
    flag = ad.flags.issue_flag(
        "match-1", round_row["id"], "team-1", "service-vulnerable-notes"
    )
    ad.flags.mark_injected(flag.id, True)
    own = ad.flags.validate_submission("match-1", "team-1", flag.token, "team-one")
    assert not own.accepted and own.reason == "self_flag"
    accepted = ad.flags.validate_submission("match-1", "team-2", flag.token, "team-two")
    duplicate = ad.flags.validate_submission("match-1", "team-2", flag.token, "team-two")
    assert accepted.accepted and accepted.score_delta == 10
    assert not duplicate.accepted and duplicate.reason == "duplicate"


def test_scoring_policy():
    policy = ConfigurableScoringPolicy(10, 5, 5, 0.6)
    assert policy.attack_score() == 10
    assert policy.defense_score(True, False, True) == 5
    assert policy.defense_score(True, True, True) == 0
    assert policy.availability_score(3, 5) == 5
    assert policy.availability_score(2, 5) == 0
    assert policy.availability_score(0, 0) == 0


def test_round_and_patch_state_transitions():
    assert_transition("pending", "initializing", ROUND_TRANSITIONS)
    assert_transition("uploaded", "validating", PATCH_TRANSITIONS)
    with pytest.raises(ValueError):
        assert_transition("pending", "finalized", ROUND_TRANSITIONS)
    with pytest.raises(ValueError):
        assert_transition("uploaded", "deployed", PATCH_TRANSITIONS)


def test_match_mode_strategies_do_not_cross_apply_gameplay():
    exercise = strategy_for("exercise")
    attack_defense = strategy_for("attack_defense")
    hybrid = strategy_for("hybrid_live_fire")
    assert not exercise.attack_policy.team_to_team_enabled()
    assert not exercise.checker_policy.round_checker_enabled()
    assert exercise.inject_policy.operator_injects_enabled()
    assert attack_defense.attack_policy.team_to_team_enabled()
    assert not attack_defense.inject_policy.injects_required()
    assert hybrid.attack_policy.team_to_team_enabled()
    assert hybrid.inject_policy.operator_injects_enabled()
    assert hybrid.flag_defense_category() == "flag_defense"


def test_score_ledger_event_id_is_idempotent(ad):
    bootstrap(ad, teams=2, services=1)
    event_id = stable_id("test-ledger")
    with ad.db.transaction(immediate=True) as conn:
        first = ad.repo.insert_ledger(
            conn, event_id=event_id, match_id="match-1", round_id=None,
            team_id="team-1", service_id=None, score_type="adjustment",
            delta=3, reason="test", evidence={"x": 1},
        )
        second = ad.repo.insert_ledger(
            conn, event_id=event_id, match_id="match-1", round_id=None,
            team_id="team-1", service_id=None, score_type="adjustment",
            delta=3, reason="test", evidence={"x": 1},
        )
    assert first is True and second is False


def test_patch_policy_and_transition_to_sandbox_queue(ad):
    bootstrap(ad, teams=2, services=1)
    patch = ad.patches.submit(
        "match-1", "team-1", "service-vulnerable-notes",
        "registry.local:5000/team-01/vulnerable-notes:patch-1", "competitor-1",
    )
    validated = ad.patches.inspect_and_queue(patch["id"])
    assert validated["status"] == "validating"
    conn = ad.db.connect()
    job = conn.execute(
        "SELECT * FROM runtime_jobs WHERE operation='sandbox_validate'"
    ).fetchone()
    conn.close()
    assert job is not None


def test_digest_patch_reference_keeps_registry_port_and_repository(ad):
    bootstrap(ad, teams=2, services=1)
    digest = "sha256:" + ("b" * 64)
    ad.patches.inspector.digest = digest
    patch = ad.patches.submit(
        "match-1", "team-1", "service-vulnerable-notes",
        f"registry.local:5000/team-01/vulnerable-notes@{digest}",
        "competitor-1",
    )
    validated = ad.patches.inspect_and_queue(patch["id"])
    assert validated["image_reference"] == (
        f"registry.local:5000/team-01/vulnerable-notes@{digest}"
    )


def test_stale_runtime_job_can_be_reclaimed_after_worker_restart(ad):
    bootstrap(ad, teams=2, services=1)
    patch = ad.patches.submit(
        "match-1", "team-1", "service-vulnerable-notes",
        "registry.local:5000/team-01/vulnerable-notes:patch-retry",
        "competitor-1",
    )
    ad.patches.inspect_and_queue(patch["id"])
    first = ad.patches.claim_job("worker-before-restart")
    assert first is not None
    with ad.db.transaction(immediate=True) as conn:
        conn.execute(
            "UPDATE runtime_jobs SET started_at=0 WHERE id=?",
            (first["id"],),
        )
    reclaimed = ad.patches.claim_job("worker-after-restart")
    assert reclaimed is not None
    assert reclaimed["id"] == first["id"]
    assert '"attempt":2' in reclaimed["result"]


def test_dangerous_patch_manifest_rejected(ad):
    bootstrap(ad, teams=2, services=1)
    ad.patches.inspector.labels = {"org.cyber-range.privileged": "true"}
    patch = ad.patches.submit(
        "match-1", "team-1", "service-vulnerable-notes",
        "registry.local:5000/team-01/vulnerable-notes:patch-2", "competitor-1",
    )
    result = ad.patches.inspect_and_queue(patch["id"])
    assert result["status"] == "rejected"
    assert "dangerous_runtime_request" in result["validation_result"]


def test_failed_live_deployment_queues_and_completes_rollback(ad):
    bootstrap(ad, teams=2, services=1)
    patch = ad.patches.submit(
        "match-1", "team-1", "service-vulnerable-notes",
        "registry.local:5000/team-01/vulnerable-notes:patch-rollback",
        "competitor-1",
    )
    ad.patches.inspect_and_queue(patch["id"])
    sandbox = ad.patches.claim_job("test-runner")
    assert sandbox["operation"] == "sandbox_validate"
    approved = ad.patches.complete_job(
        sandbox["id"], True, {"runtime_id": "ad_patch_sandbox"}
    )
    assert approved["status"] == "deploying"

    deploy = ad.patches.claim_job("test-runner")
    assert deploy["operation"] == "deploy"
    rolling_back = ad.patches.complete_job(
        deploy["id"], False, {"error_code": "runtime_command_failed"}
    )
    assert rolling_back["status"] == "rollback"

    rollback = ad.patches.claim_job("test-runner")
    assert rollback["operation"] == "rollback"
    finished = ad.patches.complete_job(
        rollback["id"], True, {"runtime_id": "team-01-vulnerable-notes"}
    )
    assert finished["status"] == "failed"
    instance = ad.repo.get_instance(
        "match-1", "team-1", "service-vulnerable-notes"
    )
    assert instance["status"] == "healthy"
    assert instance["image_digest"] == instance["previous_image_digest"]


def test_hybrid_mode_keeps_categories_separate_and_applies_weights(ad):
    ad.repo.create_match(
        "Hybrid", 5, 3,
        {"score_weights": {"attack": 2.0, "detection": 0.5}},
        "hybrid-1", "hybrid_live_fire",
    )
    ad.repo.add_team("hybrid-1", "hybrid-team", "Hybrid Team", "hybrid-team")
    with ad.db.transaction(immediate=True) as conn:
        ad.repo.insert_ledger(
            conn, event_id="hybrid-attack-event", match_id="hybrid-1",
            round_id=None, team_id="hybrid-team", service_id=None,
            score_type="attack", delta=10, reason="attack", evidence={},
        )
        ad.repo.insert_ledger(
            conn, event_id="hybrid-detection-event", match_id="hybrid-1",
            round_id=None, team_id="hybrid-team", service_id=None,
            score_type="detection", delta=10, reason="detection", evidence={},
        )
    row = ad.scoring.scoreboard("hybrid-1", public=False)[0]
    assert row["attack"] == 10
    assert row["detection"] == 10
    assert row["flag_defense"] == 0
    assert row["total"] == 25


def test_disabled_score_categories_do_not_affect_total(ad):
    ad.repo.create_match(
        "Hybrid Selected", 5, 3,
        {
            "score_categories": ["detection", "penalty"],
            "score_weights": {"detection": 2.0, "penalty": 1.0},
        },
        "hybrid-selected", "hybrid_live_fire",
    )
    ad.repo.add_team(
        "hybrid-selected", "hybrid-team", "Hybrid Team", "hybrid-team"
    )
    with ad.db.transaction(immediate=True) as conn:
        ad.repo.insert_ledger(
            conn, event_id="selected-detection", match_id="hybrid-selected",
            round_id=None, team_id="hybrid-team", service_id=None,
            score_type="detection", delta=8, reason="detection", evidence={},
        )
        # Existing raw ledger data remains visible for audit but cannot silently
        # enter a total when its category is disabled.
        ad.repo.insert_ledger(
            conn, event_id="disabled-attack", match_id="hybrid-selected",
            round_id=None, team_id="hybrid-team", service_id=None,
            score_type="attack", delta=100, reason="disabled", evidence={},
        )
    row = ad.scoring.scoreboard("hybrid-selected", public=False)[0]
    assert row["attack"] == 100
    assert row["detection"] == 8
    assert row["total"] == 16

    with pytest.raises(ValueError):
        ad.repo.create_match(
            "Invalid Categories", 5, 3,
            {
                "score_categories": ["detection"],
                "score_weights": {"attack": 5.0},
            },
            "hybrid-invalid", "hybrid_live_fire",
        )
