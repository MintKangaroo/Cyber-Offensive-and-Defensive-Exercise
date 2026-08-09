from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Any

from .db import Database
from .evidence import AuditContext, EvidenceRecorder
from .utils import canonical_json, json_load, stable_id

if TYPE_CHECKING:
    from .repositories import AttackDefenseRepository


KOTH_SUPPORTED_MODES = {"attack_defense", "hybrid_live_fire"}


class KothService:
    """Optional flag-backed ownership leases for symmetric live-fire modes.

    A hill represents one victim team/service instance. An accepted opponent
    flag submission acquires or renews its lease in the same transaction as the
    submission. Raw flags and token hashes never enter KOTH state or responses.
    """

    def __init__(
        self,
        db: Database,
        repo: "AttackDefenseRepository",
        evidence: EvidenceRecorder,
    ):
        self.db = db
        self.repo = repo
        self.evidence = evidence

    @staticmethod
    def normalized_config(value: object) -> dict[str, Any]:
        raw = value if isinstance(value, dict) else {}
        enabled = raw.get("enabled", False)
        if not isinstance(enabled, bool):
            raise ValueError("koth.enabled must be a boolean")
        service_ids = raw.get("service_ids", [])
        if not isinstance(service_ids, list) or any(
            not isinstance(item, str) or not item for item in service_ids
        ):
            raise ValueError("koth.service_ids must be a list of service IDs")
        lease_rounds = raw.get("lease_rounds", 2)
        points = raw.get("points_per_round", 3)
        weight = raw.get("score_weight", 1.0)
        if isinstance(lease_rounds, bool) or not isinstance(lease_rounds, int):
            raise ValueError("koth.lease_rounds must be an integer")
        if isinstance(points, bool) or not isinstance(points, int):
            raise ValueError("koth.points_per_round must be an integer")
        if isinstance(weight, bool) or not isinstance(weight, (int, float)):
            raise ValueError("koth.score_weight must be numeric")
        if not 1 <= lease_rounds <= 20:
            raise ValueError("koth.lease_rounds must be between 1 and 20")
        if not 0 <= points <= 100_000:
            raise ValueError("koth.points_per_round is outside policy")
        if not 0 <= float(weight) <= 100:
            raise ValueError("koth.score_weight is outside policy")
        return {
            "enabled": enabled,
            "service_ids": sorted(set(service_ids)),
            "lease_rounds": lease_rounds,
            "points_per_round": points,
            "score_weight": float(weight),
        }

    def configure(
        self,
        match_id: str,
        *,
        enabled: bool,
        service_ids: list[str],
        lease_rounds: int,
        points_per_round: int,
        score_weight: float,
        actor: str,
        reason: str,
    ) -> dict[str, Any]:
        if not reason or not reason.strip():
            raise ValueError("KOTH configuration reason is required")
        requested = self.normalized_config({
            "enabled": enabled,
            "service_ids": service_ids,
            "lease_rounds": lease_rounds,
            "points_per_round": points_per_round,
            "score_weight": score_weight,
        })
        with self.db.transaction(immediate=True) as conn:
            match = self.repo.get_match(match_id, conn)
            if not match:
                raise KeyError(match_id)
            if match["mode"] not in KOTH_SUPPORTED_MODES:
                raise ValueError("KOTH is only available in symmetric live-fire modes")
            if match["status"] not in {"draft", "paused"}:
                raise ValueError("KOTH configuration requires a draft or paused match")

            services = self.repo.list_services(match_id, conn)
            known = {service["id"] for service in services}
            selected = requested["service_ids"] or sorted(known)
            if requested["enabled"] and not selected:
                raise ValueError("KOTH requires at least one enabled service")
            if set(selected) - known:
                raise ValueError("KOTH service must belong to the match")
            requested["service_ids"] = selected

            config = json_load(match["config"])
            categories = list(config.get("score_categories") or [])
            weights = dict(config.get("score_weights") or {})
            if requested["enabled"]:
                if "koth" not in categories:
                    categories.append("koth")
                weights["koth"] = requested["score_weight"]
            else:
                categories = [item for item in categories if item != "koth"]
                weights.pop("koth", None)
            config.update({
                "score_categories": categories,
                "score_weights": weights,
                "koth": requested,
            })
            now = self.db.server_time(conn)
            conn.execute(
                "UPDATE matches SET config=?,updated_at=? WHERE id=?",
                (canonical_json(config), now, match_id),
            )
            self.sync_hills(match_id, conn, config=config)
            self.evidence.record(
                AuditContext(
                    actor=actor,
                    event_type="koth_configuration",
                    result="enabled" if enabled else "disabled",
                    match_id=match_id,
                    metadata={
                        "reason": reason,
                        "service_ids": selected,
                        "lease_rounds": requested["lease_rounds"],
                        "points_per_round": requested["points_per_round"],
                        "score_weight": requested["score_weight"],
                    },
                    event_id=stable_id(
                        "audit", "koth-config", match_id, enabled, selected,
                        requested["lease_rounds"], requested["points_per_round"],
                        requested["score_weight"], reason, now,
                    ),
                ),
                conn,
            )
        return self.state(match_id, operator=True)

    def sync_hills(
        self,
        match_id: str,
        conn: Any,
        *,
        config: dict[str, Any] | None = None,
    ) -> int:
        match = self.repo.get_match(match_id, conn)
        if not match or match["mode"] not in KOTH_SUPPORTED_MODES:
            return 0
        match_config = config or json_load(match["config"])
        policy = self.normalized_config(match_config.get("koth", {}))
        now = self.db.server_time(conn)
        conn.execute(
            "UPDATE koth_hills SET enabled=0,updated_at=? WHERE match_id=?",
            (now, match_id),
        )
        if not policy["enabled"]:
            return 0
        selected = set(policy["service_ids"])
        available_services = self.repo.list_services(match_id, conn)
        known_service_ids = {service["id"] for service in available_services}
        if selected - known_service_ids:
            raise ValueError("KOTH service must belong to the match")
        services = [
            service for service in available_services
            if not selected or service["id"] in selected
        ]
        count = 0
        for team in self.repo.list_teams(match_id, conn):
            for service in services:
                hill_id = stable_id(
                    "koth-hill", match_id, team["id"], service["id"]
                )
                conn.execute(
                    """INSERT INTO koth_hills(
                       id,match_id,victim_team_id,service_id,enabled,lease_rounds,
                       points_per_round,activated_at,created_at,updated_at)
                       VALUES(?,?,?,?,1,?,?,?,?,?)
                       ON CONFLICT(match_id,victim_team_id,service_id) DO UPDATE SET
                         enabled=1,lease_rounds=excluded.lease_rounds,
                         points_per_round=excluded.points_per_round,
                         activated_at=excluded.activated_at,
                         updated_at=excluded.updated_at""",
                    (
                        hill_id, match_id, team["id"], service["id"],
                        policy["lease_rounds"], policy["points_per_round"],
                        now, now, now,
                    ),
                )
                count += 1
        return count

    def acquire_for_flag(
        self,
        conn: Any,
        *,
        match: dict[str, Any],
        current_round: dict[str, Any],
        attacker_team_id: str,
        victim_team_id: str,
        service_id: str,
        flag_id: str,
        submission_id: str,
        actor: str,
        acquired_at: float,
    ) -> dict[str, Any] | None:
        policy = self.normalized_config(json_load(match["config"]).get("koth", {}))
        if not policy["enabled"] or "koth" not in set(
            json_load(match["config"]).get("score_categories", [])
        ):
            return None
        hill_query = (
            "SELECT * FROM koth_hills WHERE match_id=? AND victim_team_id=? "
            "AND service_id=? AND enabled=1"
        )
        if self.db.backend_name == "postgresql":
            # Serialize ownership classification and sequence allocation per
            # hill while allowing unrelated hills to progress independently.
            hill_query += " FOR UPDATE"
        hill = conn.execute(
            hill_query,
            (match["id"], victim_team_id, service_id),
        ).fetchone()
        if not hill:
            return None
        round_sequence = int(current_round["sequence"])
        previous = conn.execute(
            """SELECT * FROM koth_leases WHERE hill_id=? AND starts_sequence<=?
               AND acquired_at>=?
               ORDER BY sequence DESC LIMIT 1""",
            (hill["id"], round_sequence, hill["activated_at"]),
        ).fetchone()
        previous_active = bool(
            previous and int(previous["expires_after_sequence"]) >= round_sequence
        )
        result = (
            "renewed"
            if previous_active and previous["owner_team_id"] == attacker_team_id
            else "captured"
            if previous_active
            else "acquired"
        )
        expires = round_sequence + int(hill["lease_rounds"]) - 1
        event_id = stable_id(
            "koth-lease", match["id"], attacker_team_id, flag_id
        )
        inserted = conn.execute(
            """INSERT INTO koth_leases(
               event_id,hill_id,owner_team_id,source_flag_id,acquired_round_id,
               starts_sequence,expires_after_sequence,acquired_at)
               VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(event_id) DO NOTHING""",
            (
                event_id, hill["id"], attacker_team_id, flag_id,
                current_round["id"], round_sequence, expires, acquired_at,
            ),
        )
        if inserted.rowcount != 1:
            return None
        self.evidence.record(
            AuditContext(
                actor=actor,
                event_type="koth_ownership",
                result=result,
                team_id=attacker_team_id,
                match_id=match["id"],
                round_id=current_round["id"],
                service_id=service_id,
                metadata={
                    "hill_id": hill["id"],
                    "victim_team_id": victim_team_id,
                    "previous_owner_team_id": (
                        previous["owner_team_id"] if previous_active else None
                    ),
                    "expires_after_round": expires,
                    "submission_id": submission_id,
                },
                event_id=stable_id("audit", "koth-ownership", event_id),
            ),
            conn,
        )
        return {
            "hill_id": hill["id"],
            "owner_team_id": attacker_team_id,
            "result": result,
            "expires_after_round": expires,
        }

    def scoring_targets(
        self, conn: Any, match_id: str, round_row: dict[str, Any]
    ) -> dict[tuple[str, str], dict[str, Any]]:
        sequence = int(round_row["sequence"])
        hills = conn.execute(
            """SELECT h.* FROM koth_hills h
               WHERE h.match_id=? AND h.enabled=1 ORDER BY h.id""",
            (match_id,),
        ).fetchall()
        aggregates: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {"target": 0, "hills": []}
        )
        for hill in hills:
            lease = conn.execute(
                """SELECT * FROM koth_leases WHERE hill_id=?
                   AND starts_sequence<=? AND acquired_at>=?
                   ORDER BY sequence DESC LIMIT 1""",
                (hill["id"], sequence, hill["activated_at"]),
            ).fetchone()
            if not lease or int(lease["expires_after_sequence"]) < sequence:
                continue
            checks = conn.execute(
                """SELECT check_type,status FROM service_checks
                   WHERE round_id=? AND team_id=? AND service_id=?""",
                (
                    round_row["id"], hill["victim_team_id"],
                    hill["service_id"],
                ),
            ).fetchall()
            successful_types = {
                row["check_type"] for row in checks if row["status"] == "ok"
            }
            functional = {
                "put_flag", "get_flag", "benign_workflow"
            }.issubset(successful_types)
            if not functional:
                continue
            key = (lease["owner_team_id"], hill["service_id"])
            aggregates[key]["target"] += int(hill["points_per_round"])
            aggregates[key]["hills"].append({
                "hill_id": hill["id"],
                "victim_team_id": hill["victim_team_id"],
                "lease_sequence": int(lease["sequence"]),
                "expires_after_round": int(lease["expires_after_sequence"]),
            })
        return dict(aggregates)

    def state(
        self,
        match_id: str,
        *,
        operator: bool = False,
    ) -> dict[str, Any]:
        conn = self.db.connect()
        try:
            match = self.repo.get_match(match_id, conn)
            if not match:
                raise KeyError(match_id)
            config = json_load(match["config"])
            policy = self.normalized_config(config.get("koth", {}))
            current = self.repo.current_round(match_id, conn)
            sequence = int(current["sequence"]) if current else 0
            visible_sequence = sequence
            stealth = config.get("stealth", {})
            if (
                not operator and isinstance(stealth, dict)
                and stealth.get("enabled") is True
            ):
                delay = stealth.get("alert_delay_rounds", 2)
                if isinstance(delay, int) and not isinstance(delay, bool):
                    visible_sequence = max(0, sequence - delay)
            rows = conn.execute(
                """SELECT h.*,victim.name AS victim_team,
                          victim.slug AS victim_team_slug,s.name AS service,
                          s.slug AS service_slug
                   FROM koth_hills h
                   JOIN teams victim ON victim.id=h.victim_team_id
                   JOIN game_services s ON s.id=h.service_id
                   WHERE h.match_id=? AND h.enabled=1
                   ORDER BY victim.slug,s.slug""",
                (match_id,),
            ).fetchall()
            hills = []
            for row in rows:
                lease = conn.execute(
                    """SELECT l.*,owner.name AS owner_team,
                              owner.slug AS owner_team_slug
                       FROM koth_leases l
                       JOIN teams owner ON owner.id=l.owner_team_id
                       WHERE l.hill_id=? AND l.starts_sequence<=?
                       AND l.acquired_at>=?
                       ORDER BY l.sequence DESC LIMIT 1""",
                    (row["id"], visible_sequence, row["activated_at"]),
                ).fetchone()
                active = bool(
                    lease and int(lease["expires_after_sequence"]) >= visible_sequence
                )
                item = {
                    "id": row["id"],
                    "victim_team_id": row["victim_team_id"],
                    "victim_team": row["victim_team"],
                    "victim_team_slug": row["victim_team_slug"],
                    "service_id": row["service_id"],
                    "service": row["service"],
                    "service_slug": row["service_slug"],
                    "status": "owned" if active else "unclaimed",
                    "owner_team_id": lease["owner_team_id"] if active else None,
                    "owner_team": lease["owner_team"] if active else None,
                    "owner_team_slug": lease["owner_team_slug"] if active else None,
                    "expires_after_round": (
                        int(lease["expires_after_sequence"]) if active else None
                    ),
                    "remaining_rounds": (
                        int(lease["expires_after_sequence"]) - visible_sequence + 1
                        if active else 0
                    ),
                    "points_per_round": int(row["points_per_round"]),
                }
                if operator and lease:
                    item.update({
                        "lease_sequence": int(lease["sequence"]),
                        "acquired_round": int(lease["starts_sequence"]),
                        "acquired_at": float(lease["acquired_at"]),
                    })
                hills.append(item)
        finally:
            conn.close()
        return {
            "enabled": policy["enabled"],
            "round": sequence,
            "as_of_round": visible_sequence,
            "lease_rounds": policy["lease_rounds"],
            "points_per_round": policy["points_per_round"],
            "score_weight": policy["score_weight"],
            "hills": hills,
            "disclosure": (
                "delayed-ownership-only-no-flag-or-endpoint"
                if visible_sequence != sequence
                else "ownership-only-no-flag-or-endpoint"
            ),
        }
