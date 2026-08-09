from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from .db import Database
from .utils import canonical_json, evidence_hash, stable_id

SENSITIVE_KEYS = {
    "flag", "token", "secret", "password", "authorization", "management_token",
    "encrypted_token",
}


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(k): ("[redacted]" if str(k).lower() in SENSITIVE_KEYS else sanitize(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [sanitize(v) for v in value]
    return value


@dataclass(frozen=True)
class AuditContext:
    actor: str
    event_type: str
    result: str
    correlation_id: str = ""
    team_id: str | None = None
    match_id: str | None = None
    round_id: str | None = None
    service_id: str | None = None
    metadata: dict[str, Any] | None = None
    event_id: str | None = None


class EvidenceRecorder:
    def __init__(self, db: Database):
        self.db = db

    def record(self, ctx: AuditContext, conn: sqlite3.Connection | None = None) -> str:
        clean = sanitize(ctx.metadata or {})
        digest = evidence_hash(clean)
        event_id = ctx.event_id or stable_id(
            "audit", ctx.event_type, ctx.result, ctx.correlation_id, ctx.actor,
            ctx.team_id, ctx.match_id, ctx.round_id, ctx.service_id, digest,
        )

        def _insert(c: sqlite3.Connection) -> None:
            now = self.db.server_time(c)
            c.execute(
                """INSERT OR IGNORE INTO audit_events(
                   event_id,correlation_id,actor,team_id,match_id,round_id,service_id,
                   event_type,result,evidence_hash,metadata,timestamp)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event_id, ctx.correlation_id, ctx.actor, ctx.team_id, ctx.match_id,
                    ctx.round_id, ctx.service_id, ctx.event_type, ctx.result, digest,
                    canonical_json(clean), now,
                ),
            )
            c.execute(
                """INSERT OR IGNORE INTO audit_event_stream(event_id)
                   VALUES(?)""",
                (event_id,),
            )

        if conn is not None:
            _insert(conn)
        else:
            with self.db.transaction(immediate=True) as local:
                _insert(local)
        return event_id
