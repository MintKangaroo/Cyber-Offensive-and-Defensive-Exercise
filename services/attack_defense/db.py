from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class Database:
    """SQLite connection and migration boundary for the MVP.

    `BEGIN IMMEDIATE` serializes score/flag mutations across local workers.  The
    uniqueness constraints remain the final idempotency boundary.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def migrate(self) -> list[str]:
        conn = self.connect()
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations("
            "version TEXT PRIMARY KEY, applied_at REAL NOT NULL)"
        )
        applied = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
        migration_dir = Path(__file__).parent / "migrations"
        installed: list[str] = []
        for migration in sorted(migration_dir.glob("*.sql")):
            version = migration.stem
            if version in applied:
                continue
            script = migration.read_text(encoding="utf-8")
            conn.executescript(script)
            conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) "
                "VALUES(?, (julianday('now') - 2440587.5) * 86400.0)",
                (version,),
            )
            installed.append(version)
        conn.close()
        return installed

    @staticmethod
    def server_time(conn: sqlite3.Connection) -> float:
        row = conn.execute(
            "SELECT (julianday('now') - 2440587.5) * 86400.0"
        ).fetchone()
        return float(row[0])
