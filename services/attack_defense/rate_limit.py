from __future__ import annotations

from dataclasses import dataclass

from .db import Database


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    count: int
    limit: int
    retry_after_seconds: int


class DistributedRateLimiter:
    """Fixed-window limiter using the authoritative game database clock.

    With PostgreSQL, the UPSERT row lock makes the counter shared and atomic
    across every API replica. SQLite retains the same behavior for local mode.
    """

    def __init__(self, db: Database):
        self.db = db

    def consume(
        self, subject: str, action: str, window_seconds: int, limit: int,
    ) -> RateLimitDecision:
        if window_seconds < 1 or limit < 1:
            raise ValueError("rate limit policy must be positive")
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            bucket = int(now // window_seconds)
            row = conn.execute(
                """INSERT INTO rate_limits(subject_key,action,window_start,count)
                   VALUES(?,?,?,1) ON CONFLICT(subject_key,action,window_start)
                   DO UPDATE SET count=rate_limits.count+1
                   RETURNING count""",
                (subject, action, bucket),
            ).fetchone()
            count = int(row[0])
            conn.execute(
                """DELETE FROM rate_limits
                   WHERE subject_key=? AND action=? AND window_start<?""",
                (subject, action, bucket - 2),
            )
        # Preserve the public API contract and avoid exposing the server's
        # exact position within the shared window.
        return RateLimitDecision(count <= limit, count, limit, window_seconds)
