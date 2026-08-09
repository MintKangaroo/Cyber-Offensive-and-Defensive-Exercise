from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from contextlib import contextmanager

from .checker import HttpWorkflowChecker, SecretFlag
from .config import AttackDefenseSettings
from .db import Database
from .evidence import AuditContext, EvidenceRecorder
from .flag_service import FlagService
from .koth import KothService
from .mode_strategies import strategy_for
from .repositories import AttackDefenseRepository
from .scoring import ScoringService
from .service_fabric import ServiceRuntime
from .utils import canonical_json, stable_id

logger = logging.getLogger("attack_defense.game_engine")


class GameEngine:
    def __init__(
        self,
        db: Database,
        repo: AttackDefenseRepository,
        flags: FlagService,
        scoring: ScoringService,
        checker: HttpWorkflowChecker,
        runtime: ServiceRuntime,
        evidence: EvidenceRecorder,
        settings: AttackDefenseSettings,
        owner_id: str | None = None,
        koth: KothService | None = None,
    ):
        self.db = db
        self.repo = repo
        self.flags = flags
        self.scoring = scoring
        self.checker = checker
        self.runtime = runtime
        self.evidence = evidence
        self.settings = settings
        self.koth = koth or KothService(db, repo, evidence)
        self.owner_id = owner_id or uuid.uuid4().hex
        self._stop = threading.Event()

    @contextmanager
    def exclusive_match(self, match_id: str):
        with self.db.match_lock(
            match_id, self.owner_id, self.settings.engine_lock_seconds
        ) as acquired:
            if not acquired:
                raise ValueError("match is busy on another worker")
            yield

    def start_match(self, match_id: str, actor: str) -> dict:
        with self.exclusive_match(match_id):
            self.repo.ensure_instances(match_id)
            with self.db.transaction(immediate=True) as conn:
                match = self.repo.get_match(match_id, conn)
                if not match:
                    raise KeyError(match_id)
                strategy = strategy_for(match["mode"])
                if match["mode"] == "exercise":
                    raise ValueError(
                        "exercise mode is controlled by the legacy range/scenario services"
                    )
                if match["status"] not in {"draft", "paused"}:
                    raise ValueError(f"cannot start match from {match['status']}")
                if strategy.deployment_policy.symmetric_services_required() and len(
                    self.repo.list_teams(match_id, conn)
                ) < 2:
                    raise ValueError("attack/defense match needs at least two teams")
                if not self.repo.list_services(match_id, conn):
                    raise ValueError("attack/defense match needs at least one service")
                if match["status"] == "draft":
                    self.koth.sync_hills(match_id, conn)
                now = self.db.server_time(conn)
                conn.execute(
                    """UPDATE matches SET status='running',starts_at=COALESCE(starts_at,?),
                       updated_at=? WHERE id=?""",
                    (now, now, match_id),
                )
                self.evidence.record(
                    AuditContext(
                        actor=actor, event_type="match_started", result="success",
                        match_id=match_id, metadata={"mode": match["mode"]},
                        event_id=stable_id("audit", "match-start", match_id),
                    ),
                    conn,
                )
            self._tick_match_locked(match_id)
            return self.repo.get_match(match_id)

    def pause_match(self, match_id: str, actor: str, reason: str) -> dict:
        with self.exclusive_match(match_id):
            with self.db.transaction(immediate=True) as conn:
                match = self.repo.get_match(match_id, conn)
                if not match or match["status"] != "running":
                    raise ValueError("only running matches can be paused")
                now = self.db.server_time(conn)
                config = json.loads(match["config"] or "{}")
                config["paused_at"] = now
                config["pause_reason"] = reason
                conn.execute(
                    "UPDATE matches SET status='paused',config=?,updated_at=? WHERE id=?",
                    (canonical_json(config), now, match_id),
                )
                self.evidence.record(
                    AuditContext(
                        actor=actor, event_type="match_paused", result="success",
                        match_id=match_id, metadata={"reason": reason},
                        event_id=stable_id("audit", "pause", match_id, now),
                    ),
                    conn,
                )
            return self.repo.get_match(match_id)

    def resume_match(self, match_id: str, actor: str, reason: str) -> dict:
        with self.exclusive_match(match_id):
            with self.db.transaction(immediate=True) as conn:
                match = self.repo.get_match(match_id, conn)
                if not match or match["status"] != "paused":
                    raise ValueError("only paused matches can be resumed")
                now = self.db.server_time(conn)
                config = json.loads(match["config"] or "{}")
                paused_at = float(config.pop("paused_at", now))
                shift = max(0.0, now - paused_at)
                config["resume_reason"] = reason
                conn.execute(
                    "UPDATE matches SET status='running',config=?,updated_at=? WHERE id=?",
                    (canonical_json(config), now, match_id),
                )
                conn.execute(
                    """UPDATE rounds SET ends_at=ends_at+? WHERE id=?
                       AND status='active' AND ends_at IS NOT NULL""",
                    (shift, match["current_round_id"]),
                )
                conn.execute(
                    """UPDATE flags SET valid_until=valid_until+? WHERE match_id=?
                       AND status IN ('issued','injected','compromised')""",
                    (shift, match_id),
                )
                self.evidence.record(
                    AuditContext(
                        actor=actor, event_type="match_resumed", result="success",
                        match_id=match_id,
                        metadata={"reason": reason, "clock_shift_seconds": shift},
                        event_id=stable_id("audit", "resume", match_id, now),
                    ),
                    conn,
                )
            return self.repo.get_match(match_id)

    def end_match(self, match_id: str, actor: str, reason: str) -> dict:
        with self.exclusive_match(match_id):
            current = self.repo.current_round(match_id)
            if current and current["status"] in {"active", "scoring"}:
                self._force_finalize_locked(match_id, actor)
            with self.db.transaction(immediate=True) as conn:
                now = self.db.server_time(conn)
                conn.execute(
                    "UPDATE matches SET status='ended',ends_at=?,updated_at=? WHERE id=?",
                    (now, now, match_id),
                )
                self.evidence.record(
                    AuditContext(
                        actor=actor, event_type="match_ended", result="success",
                        match_id=match_id, metadata={"reason": reason},
                        event_id=stable_id("audit", "end", match_id),
                    ),
                    conn,
                )
            return self.repo.get_match(match_id)

    def tick_all(self) -> list[dict]:
        results = []
        for match in self.repo.list_matches({"running"}):
            try:
                results.append(self.tick_match(match["id"]))
            except Exception as exc:  # one match must not stop other matches
                logger.exception("game engine tick failed", extra={"match_id": match["id"]})
                self.evidence.record(AuditContext(
                    actor="game_engine", event_type="game_engine_error", result="failed",
                    match_id=match["id"], metadata={"error_class": type(exc).__name__},
                    event_id=stable_id("audit", "engine-error", match["id"], type(exc).__name__, int(time.time())),
                ))
        return results

    def tick_match(self, match_id: str) -> dict:
        with self.db.match_lock(
            match_id, self.owner_id, self.settings.engine_lock_seconds
        ) as acquired:
            if not acquired:
                return {"match_id": match_id, "status": "locked_elsewhere"}
            return self._tick_match_locked(match_id)

    def _tick_match_locked(self, match_id: str) -> dict:
        match = self.repo.get_match(match_id)
        if not match or match["status"] != "running":
            return {
                "match_id": match_id,
                "status": match["status"] if match else "missing",
            }
        round_row = self.repo.current_round(match_id)
        if not round_row or round_row["status"] == "finalized":
            round_row = self.repo.create_round(match_id)
        if round_row["status"] == "pending":
            round_row = self.repo.transition_round(round_row["id"], "initializing")
            self._initialize_round(match, round_row)
            with self.db.transaction(immediate=True) as conn:
                now = self.db.server_time(conn)
            round_row = self.repo.transition_round(
                round_row["id"], "active",
                {
                    "starts_at": now,
                    "ends_at": now + match["round_duration_seconds"],
                    "last_check_at": now,
                },
            )
            self._audit_transition(round_row, "active")
        if round_row["status"] == "active":
            with self.db.transaction() as conn:
                now = self.db.server_time(conn)
            if now >= float(round_row["ends_at"]):
                round_row = self.repo.transition_round(round_row["id"], "scoring")
                self._audit_transition(round_row, "scoring")
            elif (
                now - float(round_row["last_check_at"] or 0)
                >= self.settings.check_interval_seconds
            ):
                self._run_checks(
                    match, round_row,
                    f"periodic-{int(now // self.settings.check_interval_seconds)}",
                )
                with self.db.transaction(immediate=True) as conn:
                    conn.execute(
                        "UPDATE rounds SET last_check_at=? WHERE id=?",
                        (now, round_row["id"]),
                    )
        if round_row["status"] == "scoring":
            self._finalize_round(round_row)
            round_row = self.repo.get_round(round_row["id"])
        return {
            "match_id": match_id, "round_id": round_row["id"],
            "round": round_row["sequence"], "status": round_row["status"],
        }

    def _initialize_round(self, match: dict, round_row: dict) -> None:
        instances = self.repo.ensure_instances(match["id"])
        for instance in instances:
            issued = self.flags.issue_flag(
                match["id"], round_row["id"], instance["team_id"], instance["service_id"]
            )
            secret = SecretFlag(issued.id, issued.token)
            result = self.checker.injector.put_flag(instance, secret)
            self.flags.mark_injected(issued.id, result.success, round_row["correlation_id"])
            self._record_check(
                match["id"], round_row, instance, "put_flag",
                "ok" if result.success else ("timeout" if result.error_code == "timeout" else "failed"),
                result.latency_ms, result.error_code, "initial",
            )
        self._run_checks(match, round_row, "initial")

    def _run_checks(self, match: dict, round_row: dict, slot: str) -> None:
        conn = self.db.connect()
        flags = {
            (r["team_id"], r["service_id"]): dict(r)
            for r in conn.execute("SELECT * FROM flags WHERE round_id=?", (round_row["id"],))
        }
        conn.close()
        for instance in self.repo.list_instances(match["id"]):
            flag_row = flags.get((instance["team_id"], instance["service_id"]))
            if not flag_row:
                continue
            flag = SecretFlag(flag_row["id"], self.flags.reconstruct(flag_row))
            for outcome in self.checker.run_all(instance, flag):
                self._record_check(
                    match["id"], round_row, instance, outcome.check_type,
                    outcome.status, outcome.latency_ms, outcome.error_code, slot,
                    outcome.evidence or {},
                )

    def _record_check(
        self, match_id: str, round_row: dict, instance: dict, check_type: str,
        status: str, latency_ms: float, error_code: str | None, slot: str,
        evidence: dict | None = None,
    ) -> None:
        event_id = stable_id(
            "service-check", round_row["id"], instance["team_id"],
            instance["service_id"], check_type, slot,
        )
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            conn.execute(
                """INSERT OR IGNORE INTO service_checks(
                   id,event_id,match_id,round_id,team_id,service_id,check_type,status,
                   latency_ms,error_code,evidence,checked_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    stable_id("check", event_id), event_id, match_id, round_row["id"],
                    instance["team_id"], instance["service_id"], check_type, status,
                    latency_ms, error_code, canonical_json(evidence or {}), now,
                ),
            )
            if check_type == "health" and status == "ok":
                conn.execute(
                    """UPDATE team_service_instances SET status='healthy',
                       last_health_at=?,updated_at=? WHERE id=?""",
                    (now, now, instance["id"]),
                )
            elif check_type == "health" and status not in {"checker_system_error"}:
                conn.execute(
                    "UPDATE team_service_instances SET status='degraded',updated_at=? WHERE id=?",
                    (now, instance["id"]),
                )
            self.evidence.record(
                AuditContext(
                    actor="checker", event_type="service_check", result=status,
                    correlation_id=round_row["correlation_id"], team_id=instance["team_id"],
                    match_id=match_id, round_id=round_row["id"],
                    service_id=instance["service_id"],
                    metadata={"check_type": check_type, "error_code": error_code},
                    event_id=stable_id("audit", event_id),
                ),
                conn,
            )

    def _finalize_round(self, round_row: dict) -> None:
        self.scoring.calculate_round(round_row["id"])
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
        finalized = self.repo.transition_round(
            round_row["id"], "finalized", {"finalized_at": now}
        )
        self.flags.expire_flags(round_row["match_id"], int(round_row["sequence"]))
        self._audit_transition(finalized, "finalized")

    def force_finalize(self, match_id: str, actor: str) -> dict:
        with self.exclusive_match(match_id):
            return self._force_finalize_locked(match_id, actor)

    def _force_finalize_locked(self, match_id: str, actor: str) -> dict:
        current = self.repo.current_round(match_id)
        if not current:
            raise ValueError("no current round")
        if current["status"] == "active":
            current = self.repo.transition_round(current["id"], "scoring")
        if current["status"] != "scoring":
            raise ValueError(f"cannot finalize round from {current['status']}")
        self._finalize_round(current)
        self.evidence.record(AuditContext(
            actor=actor, event_type="round_force_finalize", result="success",
            correlation_id=current["correlation_id"], match_id=match_id,
            round_id=current["id"], event_id=stable_id("audit", "force-finalize", current["id"]),
        ))
        return self.repo.get_round(current["id"])

    def _audit_transition(self, round_row: dict, target: str) -> None:
        self.evidence.record(AuditContext(
            actor="game_engine", event_type="round_transition", result=target,
            correlation_id=round_row["correlation_id"], match_id=round_row["match_id"],
            round_id=round_row["id"], metadata={"sequence": round_row["sequence"]},
            event_id=stable_id("audit", "round-transition", round_row["id"], target),
        ))

    def run_forever(self) -> None:
        while not self._stop.wait(self.settings.engine_poll_seconds):
            self.tick_all()

    def stop(self) -> None:
        self._stop.set()
