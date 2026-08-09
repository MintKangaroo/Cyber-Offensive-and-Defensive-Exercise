from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Protocol

from .config import AttackDefenseSettings
from .db import Database
from .evidence import AuditContext, EvidenceRecorder
from .koth import KothService
from .repositories import AttackDefenseRepository
from .mode_strategies import strategy_for
from .stealth import STEALTH_SCORE_TYPES, StealthService
from .utils import evidence_hash, json_load, stable_id


class ScoringPolicy(Protocol):
    def attack_score(self) -> int: ...
    def defense_score(self, injected: bool, stolen: bool, functional: bool) -> int: ...
    def availability_score(self, successful: int, eligible: int) -> int: ...


@dataclass(frozen=True)
class ConfigurableScoringPolicy:
    attack_points: int
    defense_points: int
    availability_points: int
    availability_quorum: float

    def attack_score(self) -> int:
        return self.attack_points

    def defense_score(self, injected: bool, stolen: bool, functional: bool) -> int:
        return self.defense_points if injected and not stolen and functional else 0

    def availability_score(self, successful: int, eligible: int) -> int:
        if eligible <= 0:
            return 0
        ratio = successful / eligible
        return self.availability_points if ratio >= self.availability_quorum else 0


class ScoringService:
    def __init__(
        self,
        db: Database,
        repo: AttackDefenseRepository,
        settings: AttackDefenseSettings,
        evidence: EvidenceRecorder,
        koth: KothService | None = None,
        stealth: StealthService | None = None,
    ):
        self.db = db
        self.repo = repo
        self.settings = settings
        self.evidence = evidence
        self.koth = koth
        self.stealth = stealth
        self.policy: ScoringPolicy = ConfigurableScoringPolicy(
            settings.attack_score_per_flag,
            settings.defense_score_per_flag,
            settings.availability_score_per_round,
            settings.availability_quorum,
        )

    def _apply_target(
        self,
        conn: sqlite3.Connection,
        *,
        match_id: str,
        round_id: str,
        team_id: str,
        service_id: str,
        score_type: str,
        target: int,
        evidence: dict,
    ) -> int:
        natural_key = f"{round_id}:{team_id}:{service_id}:{score_type}"
        digest = evidence_hash(evidence)
        old = conn.execute(
            "SELECT applied_value,evidence_hash FROM score_snapshots WHERE natural_key=?",
            (natural_key,),
        ).fetchone()
        previous = int(old["applied_value"]) if old else 0
        if old and previous == target and old["evidence_hash"] == digest:
            return 0
        delta = target - previous
        event_id = stable_id("score-recalc", natural_key, target, digest)
        if delta:
            self.repo.insert_ledger(
                conn,
                event_id=event_id,
                match_id=match_id,
                round_id=round_id,
                team_id=team_id,
                service_id=service_id,
                score_type=score_type,
                delta=delta,
                reason=f"deterministic {score_type} round calculation",
                evidence=evidence,
                metadata={"target": target, "previous": previous},
            )
        now = self.db.server_time(conn)
        conn.execute(
            """INSERT INTO score_snapshots(
               natural_key,match_id,round_id,team_id,service_id,score_type,
               applied_value,evidence_hash,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(natural_key) DO UPDATE SET
                 applied_value=excluded.applied_value,
                 evidence_hash=excluded.evidence_hash,
                 updated_at=excluded.updated_at""",
            (
                natural_key, match_id, round_id, team_id, service_id, score_type,
                target, digest, now,
            ),
        )
        return delta

    def calculate_round(self, round_id: str, actor: str = "game_engine") -> dict:
        changed = 0
        with self.db.transaction(immediate=True) as conn:
            round_row = self.repo.get_round(round_id, conn)
            if not round_row:
                raise KeyError(round_id)
            match_id = round_row["match_id"]
            match = self.repo.get_match(match_id, conn)
            configured_categories = set(
                json_load(match["config"]).get("score_categories", [])
            )
            defense_category = strategy_for(match["mode"]).flag_defense_category()
            for instance in self.repo.list_instances(match_id, conn=conn):
                flag = conn.execute(
                    """SELECT f.* FROM flags f WHERE f.round_id=? AND f.team_id=?
                       AND f.service_id=?""",
                    (round_id, instance["team_id"], instance["service_id"]),
                ).fetchone()
                stolen = bool(flag and conn.execute(
                    "SELECT 1 FROM flag_submissions WHERE flag_id=? AND result='accepted' LIMIT 1",
                    (flag["id"],),
                ).fetchone())
                checks = conn.execute(
                    """SELECT check_type,status FROM service_checks
                       WHERE round_id=? AND team_id=? AND service_id=?""",
                    (round_id, instance["team_id"], instance["service_id"]),
                ).fetchall()
                eligible = [c for c in checks if c["status"] != "checker_system_error"]
                successful = sum(1 for c in eligible if c["status"] == "ok")
                types_ok = {c["check_type"] for c in eligible if c["status"] == "ok"}
                functional = {"put_flag", "get_flag", "benign_workflow"}.issubset(types_ok)
                injected = bool(flag and flag["injected_at"])
                defense = self.policy.defense_score(injected, stolen, functional)
                availability = self.policy.availability_score(successful, len(eligible))
                base_evidence = {
                    "flag_id": flag["id"] if flag else None,
                    "injected": injected,
                    "stolen": stolen,
                    "functional": functional,
                    "successful_checks": successful,
                    "eligible_checks": len(eligible),
                }
                if defense_category in configured_categories:
                    changed += abs(self._apply_target(
                        conn, match_id=match_id, round_id=round_id,
                        team_id=instance["team_id"], service_id=instance["service_id"],
                        score_type=defense_category, target=defense,
                        evidence=base_evidence,
                    ))
                if "availability" in configured_categories:
                    changed += abs(self._apply_target(
                        conn, match_id=match_id, round_id=round_id,
                        team_id=instance["team_id"], service_id=instance["service_id"],
                        score_type="availability", target=availability,
                        evidence=base_evidence,
                    ))
            if "koth" in configured_categories and self.koth is not None:
                targets = self.koth.scoring_targets(conn, match_id, dict(round_row))
                teams = self.repo.list_teams(match_id, conn)
                services = self.repo.list_services(match_id, conn)
                for team in teams:
                    for service in services:
                        target = targets.get((team["id"], service["id"]), {
                            "target": 0, "hills": [],
                        })
                        changed += abs(self._apply_target(
                            conn,
                            match_id=match_id,
                            round_id=round_id,
                            team_id=team["id"],
                            service_id=service["id"],
                            score_type="koth",
                            target=int(target["target"]),
                            evidence={
                                "round_sequence": int(round_row["sequence"]),
                                "controlled_functional_hills": target["hills"],
                            },
                        ))
            if (
                STEALTH_SCORE_TYPES.issubset(configured_categories)
                and self.stealth is not None
            ):
                targets = self.stealth.scoring_targets(
                    conn, match_id, dict(round_row)
                )
                for team in self.repo.list_teams(match_id, conn):
                    for service in self.repo.list_services(match_id, conn):
                        for score_type in sorted(STEALTH_SCORE_TYPES):
                            target = targets.get(
                                (team["id"], service["id"], score_type),
                                {"target": 0, "incidents": []},
                            )
                            changed += abs(self._apply_target(
                                conn,
                                match_id=match_id,
                                round_id=round_id,
                                team_id=team["id"],
                                service_id=service["id"],
                                score_type=score_type,
                                target=int(target["target"]),
                                evidence={
                                    "decision_round": int(round_row["sequence"]),
                                    "incidents": target["incidents"],
                                },
                            ))
                self.stealth.mark_scored(
                    conn, match_id, int(round_row["sequence"])
                )
            self.evidence.record(
                AuditContext(
                    actor=actor, event_type="score_recalculation", result="success",
                    correlation_id=round_row["correlation_id"], match_id=match_id,
                    round_id=round_id, metadata={"absolute_delta": changed},
                    event_id=stable_id("audit", "round-score", round_id, changed),
                ),
                conn,
            )
        return {"round_id": round_id, "absolute_delta": changed}

    def recalculate_match(self, match_id: str, actor: str = "operator") -> dict:
        conn = self.db.connect()
        rounds = [r["id"] for r in conn.execute(
            "SELECT id FROM rounds WHERE match_id=? AND status IN ('scoring','finalized') "
            "ORDER BY sequence", (match_id,)
        )]
        conn.close()
        results = [self.calculate_round(rid, actor) for rid in rounds]
        return {"match_id": match_id, "rounds": results}

    def adjustment(
        self, match_id: str, team_id: str, delta: int, reason: str,
        actor: str, service_id: str | None = None, round_id: str | None = None,
    ) -> dict:
        if not reason.strip():
            raise ValueError("adjustment reason is required")
        event_id = str(stable_id(
            "operator-adjustment", match_id, team_id, service_id, round_id,
            delta, reason, actor,
        ))
        with self.db.transaction(immediate=True) as conn:
            inserted = self.repo.insert_ledger(
                conn, event_id=event_id, match_id=match_id, round_id=round_id,
                team_id=team_id, service_id=service_id, score_type="adjustment",
                delta=delta, reason=reason, evidence={"actor": actor, "reason": reason},
            )
            self.evidence.record(
                AuditContext(
                    actor=actor, event_type="operator_adjustment",
                    result="applied" if inserted else "duplicate", team_id=team_id,
                    match_id=match_id, round_id=round_id, service_id=service_id,
                    metadata={"delta": delta, "reason": reason},
                    event_id=stable_id("audit", "adjustment", event_id),
                ),
                conn,
            )
        return {"event_id": event_id, "applied": inserted, "delta": delta if inserted else 0}

    def scoreboard(self, match_id: str, public: bool = True) -> list[dict]:
        conn = self.db.connect()
        match = self.repo.get_match(match_id, conn)
        if not match:
            conn.close()
            raise KeyError(match_id)
        current = self.repo.current_round(match_id, conn)
        config = json_load(match["config"])
        configured_delay = int(config.get(
            "scoreboard_delay_rounds", self.settings.scoreboard_delay_rounds
        ))
        stealth_config = (
            self.stealth.normalized_config(config.get("stealth", {}))
            if self.stealth is not None else {"enabled": False}
        )
        if stealth_config["enabled"]:
            configured_delay = max(
                configured_delay,
                int(stealth_config["alert_delay_rounds"]),
            )
        delay = int(
            strategy_for(match["mode"]).visibility_policy.public_delay_rounds(configured_delay)
            if public else 0
        )
        max_sequence = max(0, int(current["sequence"] if current else 0) - delay)
        teams = [dict(r) for r in conn.execute(
            "SELECT id AS team_id,name AS team,slug FROM teams WHERE match_id=?",
            (match_id,),
        )]
        ledger = conn.execute(
            """SELECT l.team_id,l.score_type,SUM(l.delta) value,
                      COALESCE(MAX(r.sequence),0) last_updated_round
               FROM score_ledger l LEFT JOIN rounds r ON r.id=l.round_id
               WHERE l.match_id=? AND (l.round_id IS NULL OR r.sequence<=?)
               GROUP BY l.team_id,l.score_type""",
            (match_id, max_sequence),
        ).fetchall()
        conn.close()
        categories = [
            "attack", "defense", "flag_defense", "availability", "detection",
            "containment", "recovery", "incident_response", "mission_inject",
            "koth", "stealth_attack", "stealth_detection", "penalty",
            "adjustment",
        ]
        weights = {
            str(k): float(v) for k, v in (config.get("score_weights") or {}).items()
            if isinstance(v, (int, float))
        }
        enabled_categories = set(config.get("score_categories") or [])
        by_team: dict[str, dict[str, int]] = {}
        last_round: dict[str, int] = {}
        for row in ledger:
            by_team.setdefault(row["team_id"], {})[row["score_type"]] = int(row["value"])
            last_round[row["team_id"]] = max(
                last_round.get(row["team_id"], 0), int(row["last_updated_round"])
            )
        result = []
        for team in teams:
            scores = by_team.get(team["team_id"], {})
            item = {**team, **{category: scores.get(category, 0) for category in categories}}
            item["total"] = round(sum(
                value * weights.get(category, 1.0)
                for category, value in scores.items()
                if category in enabled_categories
            ), 3)
            item["last_updated_round"] = last_round.get(team["team_id"], 0)
            result.append(item)
        result.sort(
            key=lambda row: (-row["total"], -row["attack"], -row["availability"], row["slug"])
        )
        for rank, item in enumerate(result, 1):
            item["rank"] = rank
        return result
