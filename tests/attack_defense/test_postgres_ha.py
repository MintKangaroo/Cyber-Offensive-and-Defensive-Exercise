from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from services.attack_defense.api import build_components, create_app
from services.attack_defense.config import AttackDefenseSettings
from services.attack_defense.evidence import AuditContext
from services.attack_defense.game_engine import GameEngine
from services.attack_defense.rate_limit import DistributedRateLimiter

from .conftest import bootstrap
from .fakes import FakeChecker, FakeInspector, FakeRuntime


POSTGRES_URL = os.environ.get("ATTACK_DEFENSE_TEST_POSTGRES_URL", "")


def _components(settings: AttackDefenseSettings):
    value = build_components(
        settings, runtime=FakeRuntime(), inspector=FakeInspector()
    )
    checker = FakeChecker()
    value.checker = checker
    value.patches.checker = checker
    value.engine = GameEngine(
        value.db, value.repo, value.flags, value.scoring, checker,
        value.runtime, value.evidence, settings,
    )
    return value


@pytest.fixture
def pg_ad(tmp_path: Path):
    if not POSTGRES_URL:
        pytest.skip("ATTACK_DEFENSE_TEST_POSTGRES_URL is not configured")
    settings = AttackDefenseSettings(
        database_path=tmp_path / "unused.db", database_url=POSTGRES_URL,
        round_duration_seconds=5, check_interval_seconds=60,
        auto_engine=False, allow_insecure_dev_auth=True,
        allowed_registry="registry.local:5000",
    )
    value = _components(settings)
    conn = value.db.connect()
    conn.execute(
        """TRUNCATE tournament_match_teams,tournament_fixtures,
           tournament_stages,tournament_services,tournament_entries,tournaments,
           stealth_detection_reports,stealth_incidents,
           koth_leases,koth_hills,capture_releases,capture_artifacts,
           runtime_jobs,rate_limits,
           engine_locks,audit_event_stream,audit_events,score_snapshots,
           score_ledger,patch_submissions,service_checks,flag_submissions,flags,
           team_service_instances,game_services,rounds,teams,matches
           RESTART IDENTITY CASCADE"""
    )
    conn.close()
    return value


def test_postgres_migrations_clock_readiness_and_audit_sequence(pg_ad):
    assert pg_ad.db.backend_name == "postgresql"
    conn = pg_ad.db.connect()
    versions = [row[0] for row in conn.execute(
        "SELECT version FROM schema_migrations ORDER BY version"
    )]
    database_time = pg_ad.db.server_time(conn)
    conn.close()
    assert versions[-1] == "0007_tournaments"
    assert abs(time.time() - database_time) < 5

    def record(index: int):
        return pg_ad.evidence.record(AuditContext(
            actor="ha-test", event_type="replica_event", result="success",
            match_id="unassigned", metadata={"index": index},
            event_id=f"ha-audit-{index:03}",
        ))

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert len(set(pool.map(record, range(24)))) == 24
    conn = pg_ad.db.connect()
    sequences = [row[0] for row in conn.execute(
        """SELECT sequence FROM audit_event_stream s
           JOIN audit_events a ON a.event_id=s.event_id
           WHERE a.event_type='replica_event' ORDER BY sequence"""
    )]
    conn.close()
    assert len(sequences) == 24
    assert sequences == sorted(set(sequences))
    ready = TestClient(create_app(pg_ad)).get("/ready")
    assert ready.status_code == 200
    assert ready.json()["database_backend"] == "postgresql"


def test_postgres_advisory_lock_serializes_replicated_engines(pg_ad):
    bootstrap(pg_ad, teams=3, services=2)
    replica = _components(pg_ad.settings)
    replica.engine.owner_id = "replica-b"
    pg_ad.engine.owner_id = "replica-a"
    with pg_ad.db.transaction(immediate=True) as conn:
        now = pg_ad.db.server_time(conn)
        conn.execute(
            "UPDATE matches SET status='running',starts_at=?,updated_at=? WHERE id=?",
            (now, now, "match-1"),
        )

    with pg_ad.db.match_lock("match-1", "external-holder", 20) as acquired:
        assert acquired is True
        assert replica.engine.tick_match("match-1")["status"] == "locked_elsewhere"

    assert replica.engine.tick_match("match-1")["status"] == "active"
    assert pg_ad.engine.tick_match("match-1")["status"] == "active"
    conn = pg_ad.db.connect()
    assert conn.execute(
        "SELECT COUNT(*) FROM rounds WHERE match_id=?", ("match-1",)
    ).fetchone()[0] == 1
    assert conn.execute(
        "SELECT COUNT(*) FROM flags WHERE match_id=?", ("match-1",)
    ).fetchone()[0] == 6
    conn.close()


def test_postgres_rate_limit_and_flag_submission_are_replica_safe(pg_ad):
    bootstrap(pg_ad, teams=2, services=1)
    replica = _components(pg_ad.settings)
    first = DistributedRateLimiter(pg_ad.db)
    second = DistributedRateLimiter(replica.db)

    def consume(index: int):
        limiter = first if index % 2 else second
        return limiter.consume("team-1", "flag_submit", 60, 10)

    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(consume, range(24)))
    assert sorted(item.count for item in decisions) == list(range(1, 25))
    assert sum(item.allowed for item in decisions) == 10

    pg_ad.engine.start_match("match-1", "operator")
    round_row = pg_ad.repo.current_round("match-1")
    conn = pg_ad.db.connect()
    victim_flag = dict(conn.execute(
        """SELECT * FROM flags WHERE round_id=? AND team_id='team-2'
           AND service_id='service-vulnerable-notes'""",
        (round_row["id"],),
    ).fetchone())
    conn.close()
    token = pg_ad.flags.reconstruct(victim_flag)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda service: service.validate_submission(
                "match-1", "team-1", token, "replica-competitor"
            ),
            (pg_ad.flags, replica.flags),
        ))
    assert sum(item.accepted for item in results) == 1
    assert sum(item.score_delta for item in results) == 10
    conn = pg_ad.db.connect()
    assert conn.execute(
        """SELECT COUNT(*) FROM flag_submissions
           WHERE attacker_team_id='team-1' AND flag_id=?""",
        (victim_flag["id"],),
    ).fetchone()[0] == 1
    assert conn.execute(
        """SELECT COUNT(*) FROM score_ledger
           WHERE team_id='team-1' AND score_type='attack'"""
    ).fetchone()[0] == 1
    conn.close()


def test_postgres_runtime_job_claim_uses_skip_locked_and_fencing(pg_ad):
    bootstrap(pg_ad, teams=2, services=1)
    patch = pg_ad.patches.submit(
        "match-1", "team-1", "service-vulnerable-notes",
        "registry.local:5000/team-01/vulnerable-notes:ha-patch",
        "competitor",
    )
    pg_ad.patches.inspect_and_queue(patch["id"])
    replica = _components(pg_ad.settings)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(
            lambda pipeline: pipeline.claim_job("ha-runner"),
            (pg_ad.patches, replica.patches),
        ))
    claimed = next(item for item in claims if item)
    assert sum(item is not None for item in claims) == 1
    old_claim_token = json.loads(claimed["result"])["claim_token"]

    with pg_ad.db.transaction(immediate=True) as conn:
        conn.execute(
            "UPDATE runtime_jobs SET started_at=0 WHERE id=?", (claimed["id"],)
        )
    reclaimed = replica.patches.claim_job("replacement-runner")
    new_claim_token = json.loads(reclaimed["result"])["claim_token"]
    assert new_claim_token != old_claim_token
    with pytest.raises(ValueError, match="stale"):
        pg_ad.patches.complete_job(
            claimed["id"], False, {"error_code": "old-worker"},
            claim_token=old_claim_token,
        )
    completed = replica.patches.complete_job(
        reclaimed["id"], False, {"error_code": "replacement-worker"},
        claim_token=new_claim_token,
    )
    assert completed["status"] == "rejected"


def test_postgres_koth_capture_is_serialized_per_hill(pg_ad):
    bootstrap(pg_ad, teams=3, services=1)
    pg_ad.koth.configure(
        "match-1",
        enabled=True,
        service_ids=["service-vulnerable-notes"],
        lease_rounds=2,
        points_per_round=3,
        score_weight=1.0,
        actor="operator",
        reason="exercise PostgreSQL hill serialization",
    )
    replica = _components(pg_ad.settings)
    pg_ad.engine.start_match("match-1", "operator")
    round_row = pg_ad.repo.current_round("match-1")
    conn = pg_ad.db.connect()
    victim_flag = dict(conn.execute(
        """SELECT * FROM flags WHERE round_id=? AND team_id='team-2'
           AND service_id='service-vulnerable-notes'""",
        (round_row["id"],),
    ).fetchone())
    conn.close()
    token = pg_ad.flags.reconstruct(victim_flag)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(
            lambda args: args[0].validate_submission(
                "match-1", args[1], token, args[1]
            ),
            ((pg_ad.flags, "team-1"), (replica.flags, "team-3")),
        ))
    assert all(item.accepted for item in results)

    conn = pg_ad.db.connect()
    ownership_results = [row[0] for row in conn.execute(
        """SELECT result FROM audit_events
           WHERE match_id='match-1' AND event_type='koth_ownership'
           ORDER BY timestamp"""
    )]
    leases = conn.execute(
        "SELECT COUNT(*) FROM koth_leases"
    ).fetchone()[0]
    conn.close()
    assert leases == 2
    assert sorted(ownership_results) == ["acquired", "captured"]


def test_postgres_stealth_reports_match_one_incident_once(pg_ad):
    bootstrap(pg_ad, teams=3, services=1)
    pg_ad.stealth.configure(
        "match-1",
        enabled=True,
        alert_delay_rounds=2,
        detection_window_rounds=2,
        attacker_undetected_points=2,
        defender_detection_points=3,
        attack_score_weight=1,
        detection_score_weight=1,
        actor="operator",
        reason="exercise PostgreSQL Stealth report serialization",
    )
    replica = _components(pg_ad.settings)
    pg_ad.engine.start_match("match-1", "operator")
    current = pg_ad.repo.current_round("match-1")
    conn = pg_ad.db.connect()
    victim_flag = dict(conn.execute(
        """SELECT * FROM flags WHERE round_id=? AND team_id='team-2'
           AND service_id='service-vulnerable-notes'""",
        (current["id"],),
    ).fetchone())
    conn.close()
    pg_ad.flags.validate_submission(
        "match-1", "team-1", pg_ad.flags.reconstruct(victim_flag), "team-1"
    )

    def report(args):
        service, key = args
        return service.report_detection(
            "match-1", "team-2", "service-vulnerable-notes",
            "a" * 64, "concurrent SIEM correlation evidence", key, "team-2",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(
            report,
            ((pg_ad.stealth, "report-a"), (replica.stealth, "report-b")),
        ))
    assert all(item["status"] == "pending_verification" for item in responses)
    conn = pg_ad.db.connect()
    results = [row[0] for row in conn.execute(
        "SELECT internal_result FROM stealth_detection_reports ORDER BY id"
    )]
    detected = conn.execute(
        "SELECT COUNT(*) FROM stealth_incidents WHERE detected_at IS NOT NULL"
    ).fetchone()[0]
    conn.close()
    assert sorted(results) == ["matched", "no_match"]
    assert detected == 1
