from __future__ import annotations

import re
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from .db import Database
from .evidence import AuditContext, EvidenceRecorder
from .utils import canonical_json, json_load, stable_id

if TYPE_CHECKING:
    from .repositories import AttackDefenseRepository


STEALTH_SUPPORTED_MODES = {"attack_defense", "hybrid_live_fire"}
STEALTH_SCORE_TYPES = {"stealth_attack", "stealth_detection"}


class StealthService:
    """Delayed disclosure and detection-aware scoring for symmetric modes.

    Accepted flag semantics remain authoritative and unchanged. This service
    creates an internal incident from an accepted submission, accepts a
    defender's pre-disclosure evidence hash, and projects only delayed,
    attacker-redacted alerts to participants and observers.
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
            raise ValueError("stealth.enabled must be a boolean")
        delay = raw.get("alert_delay_rounds", 2)
        window = raw.get("detection_window_rounds", 2)
        attack_points = raw.get("attacker_undetected_points", 2)
        detection_points = raw.get("defender_detection_points", 2)
        attack_weight = raw.get("attack_score_weight", 1.0)
        detection_weight = raw.get("detection_score_weight", 1.0)
        activated_at = raw.get("activated_at", 0.0)
        integers = {
            "alert_delay_rounds": delay,
            "detection_window_rounds": window,
            "attacker_undetected_points": attack_points,
            "defender_detection_points": detection_points,
        }
        if any(isinstance(item, bool) or not isinstance(item, int) for item in integers.values()):
            raise ValueError("stealth round and point values must be integers")
        if not 1 <= delay <= 20:
            raise ValueError("stealth.alert_delay_rounds must be between 1 and 20")
        if not 1 <= window <= delay:
            raise ValueError(
                "stealth.detection_window_rounds must be between 1 and alert delay"
            )
        if not 0 <= attack_points <= 100_000 or not 0 <= detection_points <= 100_000:
            raise ValueError("stealth point value is outside policy")
        if any(
            isinstance(item, bool) or not isinstance(item, (int, float))
            or not 0 <= float(item) <= 100
            for item in (attack_weight, detection_weight)
        ):
            raise ValueError("stealth score weight is outside policy")
        if isinstance(activated_at, bool) or not isinstance(activated_at, (int, float)):
            raise ValueError("stealth.activated_at must be numeric")
        return {
            "enabled": enabled,
            "alert_delay_rounds": delay,
            "detection_window_rounds": window,
            "attacker_undetected_points": attack_points,
            "defender_detection_points": detection_points,
            "attack_score_weight": float(attack_weight),
            "detection_score_weight": float(detection_weight),
            "activated_at": max(0.0, float(activated_at)),
        }

    def configure(
        self,
        match_id: str,
        *,
        enabled: bool,
        alert_delay_rounds: int,
        detection_window_rounds: int,
        attacker_undetected_points: int,
        defender_detection_points: int,
        attack_score_weight: float,
        detection_score_weight: float,
        actor: str,
        reason: str,
    ) -> dict[str, Any]:
        if not reason or not reason.strip():
            raise ValueError("Stealth configuration reason is required")
        requested = self.normalized_config({
            "enabled": enabled,
            "alert_delay_rounds": alert_delay_rounds,
            "detection_window_rounds": detection_window_rounds,
            "attacker_undetected_points": attacker_undetected_points,
            "defender_detection_points": defender_detection_points,
            "attack_score_weight": attack_score_weight,
            "detection_score_weight": detection_score_weight,
        })
        with self.db.transaction(immediate=True) as conn:
            match = self.repo.get_match(match_id, conn)
            if not match:
                raise KeyError(match_id)
            if match["mode"] not in STEALTH_SUPPORTED_MODES:
                raise ValueError(
                    "Stealth Mode is only available in symmetric live-fire modes"
                )
            if match["status"] not in {"draft", "paused"}:
                raise ValueError(
                    "Stealth configuration requires a draft or paused match"
                )
            now = self.db.server_time(conn)
            requested["activated_at"] = now
            config = json_load(match["config"])
            categories = list(config.get("score_categories") or [])
            weights = dict(config.get("score_weights") or {})
            if enabled:
                for category in ("stealth_attack", "stealth_detection"):
                    if category not in categories:
                        categories.append(category)
                weights.update({
                    "stealth_attack": requested["attack_score_weight"],
                    "stealth_detection": requested["detection_score_weight"],
                })
            else:
                categories = [
                    item for item in categories if item not in STEALTH_SCORE_TYPES
                ]
                weights.pop("stealth_attack", None)
                weights.pop("stealth_detection", None)
            config.update({
                "score_categories": categories,
                "score_weights": weights,
                "stealth": requested,
            })
            conn.execute(
                "UPDATE matches SET config=?,updated_at=? WHERE id=?",
                (canonical_json(config), now, match_id),
            )
            self.evidence.record(
                AuditContext(
                    actor=actor,
                    event_type="stealth_configuration",
                    result="enabled" if enabled else "disabled",
                    match_id=match_id,
                    metadata={
                        "reason": reason,
                        "alert_delay_rounds": requested["alert_delay_rounds"],
                        "detection_window_rounds": requested["detection_window_rounds"],
                        "attacker_undetected_points": requested[
                            "attacker_undetected_points"
                        ],
                        "defender_detection_points": requested[
                            "defender_detection_points"
                        ],
                    },
                    event_id=stable_id(
                        "audit", "stealth-config", match_id, enabled, now, reason
                    ),
                ),
                conn,
            )
        return self.state(match_id, operator=True)

    def create_incident(
        self,
        conn: Any,
        *,
        match: dict[str, Any],
        current_round: dict[str, Any],
        attacker_team_id: str,
        victim_team_id: str,
        service_id: str,
        submission_id: str,
        occurred_at: float,
        actor: str,
    ) -> dict[str, Any] | None:
        policy = self.normalized_config(
            json_load(match["config"]).get("stealth", {})
        )
        categories = set(json_load(match["config"]).get("score_categories", []))
        if not policy["enabled"] or not STEALTH_SCORE_TYPES.issubset(categories):
            return None
        sequence = int(current_round["sequence"])
        incident_id = stable_id("stealth-incident", match["id"], submission_id)
        event_id = stable_id("stealth-incident-event", submission_id)
        inserted = conn.execute(
            """INSERT INTO stealth_incidents(
               id,event_id,match_id,round_id,occurred_sequence,attacker_team_id,
               victim_team_id,service_id,submission_id,status,
               detection_deadline_sequence,disclose_after_sequence,
               attacker_points,defender_points,occurred_at)
               VALUES(?,?,?,?,?,?,?,?,?,'open',?,?,?,?,?)
               ON CONFLICT(event_id) DO NOTHING""",
            (
                incident_id, event_id, match["id"], current_round["id"], sequence,
                attacker_team_id, victim_team_id, service_id, submission_id,
                sequence + policy["detection_window_rounds"] - 1,
                sequence + policy["alert_delay_rounds"],
                policy["attacker_undetected_points"],
                policy["defender_detection_points"], occurred_at,
            ),
        )
        if inserted.rowcount != 1:
            return None
        self.evidence.record(
            AuditContext(
                actor=actor,
                event_type="stealth_incident",
                result="withheld",
                team_id=victim_team_id,
                match_id=match["id"],
                round_id=current_round["id"],
                service_id=service_id,
                metadata={
                    "incident_id": incident_id,
                    "attacker_team_id": attacker_team_id,
                    "detection_deadline_round": (
                        sequence + policy["detection_window_rounds"] - 1
                    ),
                    "disclose_after_round": sequence + policy["alert_delay_rounds"],
                },
                event_id=stable_id("audit", "stealth-incident", incident_id),
            ),
            conn,
        )
        return {"incident_id": incident_id, "status": "withheld"}

    def report_detection(
        self,
        match_id: str,
        team_id: str,
        service_id: str,
        indicator_hash: str,
        evidence_summary: str,
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        if not re.fullmatch(r"[0-9a-f]{64}", indicator_hash):
            raise ValueError("indicator_hash must be a lowercase SHA-256 value")
        if not 3 <= len(evidence_summary) <= 280:
            raise ValueError("evidence summary length is outside policy")
        if not idempotency_key or len(idempotency_key) > 128:
            raise ValueError("valid idempotency key is required")
        report_event_id = stable_id(
            "stealth-report", match_id, team_id, idempotency_key
        )
        with self.db.transaction(immediate=True) as conn:
            existing = conn.execute(
                "SELECT id FROM stealth_detection_reports WHERE event_id=?",
                (report_event_id,),
            ).fetchone()
            if existing:
                return {
                    "recorded": True,
                    "status": "pending_verification",
                    "report_id": existing["id"],
                }
            match = self.repo.get_match(match_id, conn)
            current = self.repo.current_round(match_id, conn)
            team = self.repo.get_team(team_id, conn)
            service = self.repo.get_service(service_id, conn)
            if not match or not current:
                raise ValueError("match has no active round")
            policy = self.normalized_config(
                json_load(match["config"]).get("stealth", {})
            )
            if (
                not policy["enabled"] or match["status"] != "running"
                or current["status"] != "active"
            ):
                raise ValueError("Stealth detection reporting is not active")
            if not team or team["match_id"] != match_id or not team["enabled"]:
                raise ValueError("team does not belong to match")
            if not service or service["match_id"] != match_id or not service["enabled"]:
                raise ValueError("service does not belong to match")
            sequence = int(current["sequence"])
            query = (
                "SELECT * FROM stealth_incidents WHERE match_id=? "
                "AND victim_team_id=? AND service_id=? AND status='open' "
                "AND occurred_at>=? AND detection_deadline_sequence>=? "
                "ORDER BY occurred_sequence,id LIMIT 1"
            )
            if self.db.backend_name == "postgresql":
                query += " FOR UPDATE SKIP LOCKED"
            incident = conn.execute(
                query,
                (match_id, team_id, service_id, policy["activated_at"], sequence),
            ).fetchone()
            report_id = stable_id("stealth-report-id", report_event_id)
            internal_result = "matched" if incident else "no_match"
            now = self.db.server_time(conn)
            conn.execute(
                """INSERT INTO stealth_detection_reports(
                   id,event_id,match_id,round_id,team_id,service_id,
                   indicator_hash,evidence_summary,internal_result,
                   matched_incident_id,submitted_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    report_id, report_event_id, match_id, current["id"], team_id,
                    service_id, indicator_hash, evidence_summary, internal_result,
                    incident["id"] if incident else None, now,
                ),
            )
            if incident:
                conn.execute(
                    """UPDATE stealth_incidents SET status='detected',detected_at=?,
                       detection_report_id=? WHERE id=? AND status='open'""",
                    (now, report_id, incident["id"]),
                )
            self.evidence.record(
                AuditContext(
                    actor=actor,
                    event_type="stealth_detection_report",
                    result="recorded",
                    team_id=team_id,
                    match_id=match_id,
                    round_id=current["id"],
                    service_id=service_id,
                    metadata={
                        "report_id": report_id,
                        "internal_result": internal_result,
                        "matched_incident_id": incident["id"] if incident else None,
                        "indicator_hash": indicator_hash,
                    },
                    event_id=stable_id("audit", "stealth-report", report_event_id),
                ),
                conn,
            )
        return {
            "recorded": True,
            "status": "pending_verification",
            "report_id": report_id,
        }

    def scoring_targets(
        self, conn: Any, match_id: str, round_row: dict[str, Any]
    ) -> dict[tuple[str, str, str], dict[str, Any]]:
        match = self.repo.get_match(match_id, conn)
        policy = self.normalized_config(
            json_load(match["config"]).get("stealth", {})
        )
        sequence = int(round_row["sequence"])
        rows = conn.execute(
            """SELECT * FROM stealth_incidents WHERE match_id=?
               AND detection_deadline_sequence=? AND occurred_at>=?
               ORDER BY id""",
            (match_id, sequence, policy["activated_at"]),
        ).fetchall()
        targets: dict[tuple[str, str, str], dict[str, Any]] = defaultdict(
            lambda: {"target": 0, "incidents": []}
        )
        for row in rows:
            detected = row["detected_at"] is not None
            team_id = row["victim_team_id"] if detected else row["attacker_team_id"]
            score_type = "stealth_detection" if detected else "stealth_attack"
            points = int(row["defender_points"] if detected else row["attacker_points"])
            key = (team_id, row["service_id"], score_type)
            targets[key]["target"] += points
            targets[key]["incidents"].append({
                "incident_id": row["id"],
                "occurred_round": int(row["occurred_sequence"]),
                "outcome": "detected" if detected else "undetected",
            })
        return dict(targets)

    def mark_scored(self, conn: Any, match_id: str, sequence: int) -> None:
        now = self.db.server_time(conn)
        conn.execute(
            """UPDATE stealth_incidents SET status=CASE
                 WHEN detected_at IS NULL THEN 'finalized_undetected'
                 ELSE 'finalized_detected' END,finalized_at=?
               WHERE match_id=? AND detection_deadline_sequence=?
               AND status IN ('open','detected')""",
            (now, match_id, sequence),
        )

    def state(
        self,
        match_id: str,
        *,
        operator: bool = False,
        team_id: str | None = None,
        observer: bool = False,
    ) -> dict[str, Any]:
        conn = self.db.connect()
        try:
            match = self.repo.get_match(match_id, conn)
            if not match:
                raise KeyError(match_id)
            policy = self.normalized_config(
                json_load(match["config"]).get("stealth", {})
            )
            current = self.repo.current_round(match_id, conn)
            sequence = int(current["sequence"]) if current else 0
            if operator:
                incidents = [dict(row) for row in conn.execute(
                    """SELECT i.*,s.name AS service,s.slug AS service_slug,
                              a.name AS attacker_team,v.name AS victim_team
                       FROM stealth_incidents i
                       JOIN game_services s ON s.id=i.service_id
                       JOIN teams a ON a.id=i.attacker_team_id
                       JOIN teams v ON v.id=i.victim_team_id
                       WHERE i.match_id=? AND i.occurred_at>=?
                       ORDER BY i.occurred_at DESC LIMIT 250""",
                    (match_id, policy["activated_at"]),
                )]
                reports = [dict(row) for row in conn.execute(
                    """SELECT id,round_id,team_id,service_id,indicator_hash,
                              evidence_summary,internal_result,matched_incident_id,
                              submitted_at FROM stealth_detection_reports
                       WHERE match_id=? ORDER BY submitted_at DESC LIMIT 250""",
                    (match_id,),
                )]
                disclosure = "operator-realtime"
            elif observer:
                rows = conn.execute(
                    """SELECT s.id AS service_id,s.name AS service,
                              COUNT(*) AS total,
                              SUM(CASE WHEN i.detected_at IS NOT NULL THEN 1 ELSE 0 END)
                                AS detected
                       FROM stealth_incidents i
                       JOIN game_services s ON s.id=i.service_id
                       WHERE i.match_id=? AND i.disclose_after_sequence<=?
                         AND i.occurred_at>=?
                       GROUP BY s.id,s.name ORDER BY s.name""",
                    (match_id, sequence, policy["activated_at"]),
                ).fetchall()
                incidents = [
                    {
                        "service_id": row["service_id"],
                        "service": row["service"],
                        "total": int(row["total"]),
                        "detected": int(row["detected"] or 0),
                        "undetected": int(row["total"]) - int(row["detected"] or 0),
                    }
                    for row in rows
                ]
                reports = []
                disclosure = "delayed-aggregate-no-team-attribution"
            else:
                if not team_id:
                    raise ValueError("team membership is required")
                rows = conn.execute(
                    """SELECT i.id,i.occurred_sequence,i.status,
                              i.disclose_after_sequence,i.detected_at,
                              s.id AS service_id,s.name AS service,s.slug AS service_slug
                       FROM stealth_incidents i
                       JOIN game_services s ON s.id=i.service_id
                       WHERE i.match_id=? AND i.victim_team_id=?
                         AND i.disclose_after_sequence<=? AND i.occurred_at>=?
                       ORDER BY i.occurred_sequence DESC,i.id LIMIT 100""",
                    (match_id, team_id, sequence, policy["activated_at"]),
                ).fetchall()
                incidents = [
                    {
                        "id": row["id"],
                        "occurred_round": int(row["occurred_sequence"]),
                        "service_id": row["service_id"],
                        "service": row["service"],
                        "service_slug": row["service_slug"],
                        "status": (
                            "detected" if row["detected_at"] is not None
                            else "undetected"
                        ),
                        "disclosed": True,
                    }
                    for row in rows
                ]
                report_rows = conn.execute(
                    """SELECT id,round_id,service_id,submitted_at
                       FROM stealth_detection_reports
                       WHERE match_id=? AND team_id=?
                       ORDER BY submitted_at DESC LIMIT 100""",
                    (match_id, team_id),
                ).fetchall()
                reports = [
                    {
                        "id": row["id"], "round_id": row["round_id"],
                        "service_id": row["service_id"],
                        "submitted_at": float(row["submitted_at"]),
                        "status": "pending_verification",
                    }
                    for row in report_rows
                ]
                disclosure = "own-delayed-attacker-redacted"
        finally:
            conn.close()
        return {
            "enabled": policy["enabled"],
            "round": sequence,
            "alert_delay_rounds": policy["alert_delay_rounds"],
            "detection_window_rounds": policy["detection_window_rounds"],
            "attacker_undetected_points": policy["attacker_undetected_points"],
            "defender_detection_points": policy["defender_detection_points"],
            "incidents": incidents,
            "reports": reports,
            "disclosure": disclosure,
        }
