from __future__ import annotations

import base64
import hashlib
import hmac
import re
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .config import AttackDefenseSettings
from .db import Database
from .evidence import AuditContext, EvidenceRecorder
from .models import FlagStatus
from .repositories import AttackDefenseRepository
from .utils import json_load, stable_id

if TYPE_CHECKING:
    from .koth import KothService
    from .stealth import StealthService

FLAG_RE = re.compile(r"^FLAG\{[A-Za-z0-9_-]{32}\}$")


@dataclass(frozen=True)
class IssuedFlag:
    id: str
    token: str
    token_hash: str
    valid_from: float
    valid_until: float


@dataclass(frozen=True)
class FlagValidationResult:
    accepted: bool
    status: str
    reason: str
    score_delta: int = 0
    flag_id: str | None = None
    victim_team_id: str | None = None
    service_id: str | None = None


class FlagService:
    def __init__(
        self,
        db: Database,
        repo: AttackDefenseRepository,
        settings: AttackDefenseSettings,
        evidence: EvidenceRecorder,
        koth: "KothService | None" = None,
        stealth: "StealthService | None" = None,
    ):
        self.db = db
        self.repo = repo
        self.settings = settings
        self.evidence = evidence
        self.koth = koth
        self.stealth = stealth

    def _token(self, match_id: str, round_id: str, team_id: str, service_id: str) -> str:
        msg = f"v1:{match_id}:{round_id}:{team_id}:{service_id}".encode()
        opaque = hmac.new(self.settings.flag_secret.encode(), msg, hashlib.sha256).digest()[:24]
        return "FLAG{" + base64.urlsafe_b64encode(opaque).decode().rstrip("=") + "}"

    def token_hash(self, token: str) -> str:
        return hmac.new(
            self.settings.flag_hash_secret.encode(), token.encode(), hashlib.sha256
        ).hexdigest()

    def issue_flag(
        self, match_id: str, round_id: str, team_id: str, service_id: str
    ) -> IssuedFlag:
        token = self._token(match_id, round_id, team_id, service_id)
        lookup = self.token_hash(token)
        flag_id = stable_id("flag", match_id, round_id, team_id, service_id)
        with self.db.transaction(immediate=True) as conn:
            match = self.repo.get_match(match_id, conn)
            round_row = self.repo.get_round(round_id, conn)
            if not match or not round_row or round_row["match_id"] != match_id:
                raise ValueError("unknown match or round")
            team = self.repo.get_team(team_id, conn)
            service = self.repo.get_service(service_id, conn)
            if (
                not team or team["match_id"] != match_id or not team["enabled"]
                or not service or service["match_id"] != match_id
                or not service["enabled"]
            ):
                raise ValueError("team and service must be enabled members of the match")
            now = self.db.server_time(conn)
            valid_until = now + (
                match["round_duration_seconds"] * match["active_flag_window"]
            )
            conn.execute(
                """INSERT OR IGNORE INTO flags(
                   id,match_id,round_id,team_id,service_id,token_hash,secret_reference,
                   status,valid_from,valid_until,created_at)
                   VALUES(?,?,?,?,?,?,'hmac:v1',?,?,?,?)""",
                (
                    flag_id, match_id, round_id, team_id, service_id, lookup,
                    FlagStatus.issued, now, valid_until, now,
                ),
            )
            row = conn.execute("SELECT * FROM flags WHERE id=?", (flag_id,)).fetchone()
            self.evidence.record(
                AuditContext(
                    actor="game_engine", event_type="flag_issuance", result="issued",
                    correlation_id=round_row["correlation_id"], team_id=team_id,
                    match_id=match_id, round_id=round_id, service_id=service_id,
                    metadata={"flag_id": flag_id, "token_hash": lookup},
                    event_id=stable_id("audit", "flag-issued", flag_id),
                ),
                conn,
            )
        return IssuedFlag(
            id=flag_id, token=token, token_hash=lookup,
            valid_from=float(row["valid_from"]), valid_until=float(row["valid_until"]),
        )

    def reconstruct(self, flag_row: dict) -> str:
        return self._token(
            flag_row["match_id"], flag_row["round_id"],
            flag_row["team_id"], flag_row["service_id"],
        )

    def mark_injected(self, flag_id: str, success: bool, correlation_id: str = "") -> None:
        with self.db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM flags WHERE id=?", (flag_id,)).fetchone()
            if not row:
                raise KeyError(flag_id)
            now = self.db.server_time(conn)
            status = FlagStatus.injected if success else FlagStatus.injection_failed
            conn.execute(
                "UPDATE flags SET status=?,injected_at=? WHERE id=?",
                (status, now if success else None, flag_id),
            )
            self.evidence.record(
                AuditContext(
                    actor="flag_injector", event_type="flag_injection",
                    result="success" if success else "failed",
                    correlation_id=correlation_id, team_id=row["team_id"],
                    match_id=row["match_id"], round_id=row["round_id"],
                    service_id=row["service_id"], metadata={"flag_id": flag_id},
                    event_id=stable_id("audit", "flag-injection", flag_id, success),
                ),
                conn,
            )

    def validate_submission(
        self,
        match_id: str,
        attacker_team_id: str,
        token: str,
        actor: str,
    ) -> FlagValidationResult:
        normalized = (token or "").strip()
        submitted_hash = self.token_hash(normalized)
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            match = self.repo.get_match(match_id, conn)
            current = self.repo.current_round(match_id, conn)
            reason = "invalid_or_inactive"
            row = None
            if (
                match and match["status"] == "running"
                and current and current["status"] == "active"
                and FLAG_RE.fullmatch(normalized)
            ):
                row = conn.execute(
                    """SELECT f.*,r.sequence AS flag_round_sequence,
                              s.enabled AS service_enabled
                       FROM flags f
                       JOIN rounds r ON r.id=f.round_id
                       JOIN game_services s ON s.id=f.service_id
                       WHERE f.match_id=? AND f.token_hash=?""",
                    (match_id, submitted_hash),
                ).fetchone()
            accepted = False
            if row:
                expected = self.reconstruct(dict(row))
                signature_ok = hmac.compare_digest(expected.encode(), normalized.encode())
                current_seq = int(current["sequence"])
                active = (
                    int(row["flag_round_sequence"]) <= current_seq
                    < int(row["flag_round_sequence"]) + int(match["active_flag_window"])
                )
                if not signature_ok:
                    reason = "bad_signature"
                elif row["team_id"] == attacker_team_id:
                    reason = "self_flag"
                elif row["status"] not in (FlagStatus.injected, FlagStatus.compromised):
                    reason = "not_injected"
                elif not bool(row["service_enabled"]):
                    reason = "service_disabled"
                elif (
                    not active
                    or float(row["valid_from"]) > now
                    or float(row["valid_until"]) < now
                ):
                    reason = "expired_or_future"
                else:
                    duplicate = conn.execute(
                        "SELECT 1 FROM flag_submissions WHERE attacker_team_id=? AND flag_id=?",
                        (attacker_team_id, row["id"]),
                    ).fetchone()
                    if duplicate:
                        reason = "duplicate"
                    else:
                        accepted = True
                        reason = "accepted"

            submission_id = str(uuid.uuid4())
            round_id = current["id"] if current else None
            inserted = conn.execute(
                """INSERT INTO flag_submissions(
                   id,match_id,round_id,attacker_team_id,victim_team_id,service_id,
                   flag_id,submitted_token_hash,result,reject_reason,submitted_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(attacker_team_id,flag_id) DO NOTHING""",
                (
                    submission_id, match_id, round_id, attacker_team_id,
                    row["team_id"] if row else None, row["service_id"] if row else None,
                    row["id"] if row else None, submitted_hash,
                    "accepted" if accepted else "rejected", None if accepted else reason, now,
                ),
            )
            if inserted.rowcount != 1:
                accepted = False
                reason = "duplicate"

            score_delta = 0
            if accepted and row:
                conn.execute(
                    "UPDATE flags SET status=?,retrieved_at=COALESCE(retrieved_at,?) WHERE id=?",
                    (FlagStatus.compromised, now, row["id"]),
                )
                event_id = stable_id("attack-score", attacker_team_id, row["id"])
                score_categories = set(json_load(match["config"]).get(
                    "score_categories", []
                ))
                if "attack" in score_categories and self.repo.insert_ledger(
                    conn,
                    event_id=event_id,
                    match_id=match_id,
                    round_id=row["round_id"],
                    team_id=attacker_team_id,
                    service_id=row["service_id"],
                    score_type="attack",
                    delta=self.settings.attack_score_per_flag,
                    reason="first valid opponent flag submission",
                    evidence={"flag_id": row["id"], "submission_id": submission_id},
                    metadata={"victim_redacted": True},
                ):
                    score_delta = self.settings.attack_score_per_flag
                if self.koth is not None:
                    self.koth.acquire_for_flag(
                        conn,
                        match=dict(match),
                        current_round=dict(current),
                        attacker_team_id=attacker_team_id,
                        victim_team_id=row["team_id"],
                        service_id=row["service_id"],
                        flag_id=row["id"],
                        submission_id=submission_id,
                        actor=actor,
                        acquired_at=now,
                    )
                if self.stealth is not None:
                    self.stealth.create_incident(
                        conn,
                        match=dict(match),
                        current_round=dict(current),
                        attacker_team_id=attacker_team_id,
                        victim_team_id=row["team_id"],
                        service_id=row["service_id"],
                        submission_id=submission_id,
                        occurred_at=now,
                        actor=actor,
                    )
            self.evidence.record(
                AuditContext(
                    actor=actor, event_type="flag_submission",
                    result="accepted" if accepted else "rejected",
                    team_id=attacker_team_id, match_id=match_id, round_id=round_id,
                    service_id=row["service_id"] if row else None,
                    metadata={
                        "submission_id": submission_id,
                        "flag_id": row["id"] if row else None,
                        "internal_reason": reason,
                        "submitted_token_hash": submitted_hash,
                    },
                    event_id=stable_id("audit", "submission", submission_id),
                ),
                conn,
            )
        return FlagValidationResult(
            accepted=accepted,
            status="accepted" if accepted else "rejected",
            reason=reason,
            score_delta=score_delta,
            flag_id=row["id"] if row else None,
            victim_team_id=row["team_id"] if row else None,
            service_id=row["service_id"] if row else None,
        )

    def expire_flags(self, match_id: str, current_round: int) -> int:
        with self.db.transaction(immediate=True) as conn:
            match = self.repo.get_match(match_id, conn)
            if not match:
                return 0
            cur = conn.execute(
                """UPDATE flags SET status='expired'
                   WHERE match_id=? AND status IN ('injected','compromised','issued')
                   AND round_id IN (
                     SELECT id FROM rounds WHERE match_id=?
                     AND sequence + ? <= ?
                   )""",
                (match_id, match_id, match["active_flag_window"], current_round),
            )
            return cur.rowcount
