from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_INSERT_OR_IGNORE_RE = re.compile(
    r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+", re.IGNORECASE
)
_REAL_RE = re.compile(r"\bREAL\b", re.IGNORECASE)
_BLOB_RE = re.compile(r"\bBLOB\b", re.IGNORECASE)
_MIGRATION_LOCK_KEY = 0x434F4445584144  # stable, repository-specific 56-bit key


class CompatRow:
    """Row supporting both SQLite-style name and ordinal access."""

    def __init__(self, names: Sequence[str], values: Sequence[Any]):
        self._names = tuple(names)
        self._values = tuple(values)
        self._positions = {name: index for index, name in enumerate(self._names)}

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._values[key]
        return self._values[self._positions[key]]

    def __iter__(self) -> Iterator[Any]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._names)

    def keys(self) -> tuple[str, ...]:
        return self._names


def _compat_row_factory(cursor: Any):
    names = tuple(column.name for column in (cursor.description or ()))

    def make_row(values: Sequence[Any]) -> CompatRow:
        return CompatRow(names, values)

    return make_row


def _postgres_sql(sql: str) -> str:
    """Translate the deliberately small SQLite-compatible SQL subset."""
    translated = sql.replace("?", "%s")
    if _INSERT_OR_IGNORE_RE.match(translated):
        translated = _INSERT_OR_IGNORE_RE.sub("INSERT INTO ", translated, count=1)
        translated = translated.rstrip().removesuffix(";").rstrip()
        translated += " ON CONFLICT DO NOTHING"
    return translated


def _postgres_migration_sql(sql: str) -> str:
    translated = _REAL_RE.sub("DOUBLE PRECISION", sql)
    translated = _BLOB_RE.sub("BYTEA", translated)
    translated = translated.replace(
        "INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY"
    )
    return _postgres_sql(translated)


def _migration_statements(script: str) -> Iterator[str]:
    # Migration files contain plain DDL/DML only: no functions or semicolons in
    # string literals. Keeping this constrained avoids executing arbitrary SQL
    # through a generic parser.
    for statement in script.split(";"):
        value = statement.strip()
        if value and not value.upper().startswith("PRAGMA "):
            yield value


class _PostgresConnection:
    def __init__(self, raw: Any):
        self.raw = raw

    def execute(self, sql: str, parameters: Sequence[Any] | None = None):
        return self.raw.execute(
            _postgres_sql(sql), tuple(parameters or ()), prepare=False
        )

    def close(self) -> None:
        self.raw.close()


class Database:
    """Attack/Defense persistence with SQLite development and PostgreSQL HA.

    SQLite remains the zero-dependency local/demo backend. PostgreSQL is a
    shared-state backend for replicated API/game-engine workers and supplies
    session advisory locks plus the authoritative server clock.
    """

    def __init__(
        self,
        path: Path,
        database_url: str = "",
        *,
        connect_timeout_seconds: int = 5,
        statement_timeout_ms: int = 10_000,
        application_name: str = "cyber-range-attack-defense",
    ):
        self.path = Path(path)
        self.database_url = database_url
        self.connect_timeout_seconds = connect_timeout_seconds
        self.statement_timeout_ms = statement_timeout_ms
        self.application_name = application_name
        self.backend_name = "postgresql" if database_url else "sqlite"
        if self.backend_name == "sqlite":
            self.path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def integrity_error(self) -> type[Exception]:
        if self.backend_name == "sqlite":
            return sqlite3.IntegrityError
        import psycopg

        return psycopg.IntegrityError

    def _postgres_connect(self, *, autocommit: bool):
        import psycopg

        options = (
            f"-c statement_timeout={self.statement_timeout_ms} "
            f"-c idle_in_transaction_session_timeout={self.statement_timeout_ms * 2}"
        )
        return psycopg.connect(
            self.database_url,
            autocommit=autocommit,
            connect_timeout=self.connect_timeout_seconds,
            application_name=self.application_name,
            options=options,
            row_factory=_compat_row_factory,
        )

    def connect(self):
        if self.backend_name == "postgresql":
            return _PostgresConnection(self._postgres_connect(autocommit=True))
        conn = sqlite3.connect(
            self.path, timeout=10, isolation_level=None, check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[Any]:
        if self.backend_name == "postgresql":
            raw = self._postgres_connect(autocommit=True)
            try:
                with raw.transaction():
                    yield _PostgresConnection(raw)
            finally:
                raw.close()
            return
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
        if self.backend_name == "postgresql":
            return self._migrate_postgresql()
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

    def _migrate_postgresql(self) -> list[str]:
        raw = self._postgres_connect(autocommit=True)
        installed: list[str] = []
        acquired = False
        try:
            raw.execute("SELECT pg_advisory_lock(%s)", (_MIGRATION_LOCK_KEY,))
            acquired = True
            with raw.transaction():
                conn = _PostgresConnection(raw)
                raw.execute(
                    "CREATE TABLE IF NOT EXISTS schema_migrations("
                    "version TEXT PRIMARY KEY, applied_at DOUBLE PRECISION NOT NULL)"
                )
                applied = {
                    row[0] for row in raw.execute(
                        "SELECT version FROM schema_migrations"
                    )
                }
                migration_dir = Path(__file__).parent / "migrations"
                for migration in sorted(migration_dir.glob("*.sql")):
                    version = migration.stem
                    if version in applied:
                        continue
                    for statement in _migration_statements(
                        migration.read_text(encoding="utf-8")
                    ):
                        raw.execute(_postgres_migration_sql(statement), prepare=False)
                    now = self.server_time(conn)
                    raw.execute(
                        "INSERT INTO schema_migrations(version,applied_at) VALUES(%s,%s)",
                        (version, now),
                    )
                    installed.append(version)
        finally:
            try:
                if acquired:
                    raw.execute(
                        "SELECT pg_advisory_unlock(%s)", (_MIGRATION_LOCK_KEY,)
                    )
            finally:
                raw.close()
        return installed

    def server_time(self, conn: Any) -> float:
        if self.backend_name == "postgresql":
            row = conn.execute(
                "SELECT EXTRACT(EPOCH FROM clock_timestamp())"
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT (julianday('now') - 2440587.5) * 86400.0"
            ).fetchone()
        return float(row[0])

    @staticmethod
    def _advisory_key(match_id: str) -> int:
        unsigned = int.from_bytes(
            hashlib.sha256(f"attack-defense:{match_id}".encode()).digest()[:8],
            "big", signed=False,
        )
        return unsigned if unsigned < 2**63 else unsigned - 2**64

    @contextmanager
    def match_lock(
        self, match_id: str, owner_id: str, lease_seconds: int,
    ) -> Iterator[bool]:
        if self.backend_name == "postgresql":
            raw = self._postgres_connect(autocommit=True)
            key = self._advisory_key(match_id)
            acquired = False
            try:
                acquired = bool(
                    raw.execute(
                        "SELECT pg_try_advisory_lock(%s)", (key,)
                    ).fetchone()[0]
                )
                yield acquired
            finally:
                if acquired:
                    raw.execute("SELECT pg_advisory_unlock(%s)", (key,))
                raw.close()
            return

        with self.transaction(immediate=True) as conn:
            now = self.server_time(conn)
            row = conn.execute(
                "SELECT owner_id,lease_until FROM engine_locks WHERE lock_key=?",
                (match_id,),
            ).fetchone()
            acquired = not (
                row and row["lease_until"] > now and row["owner_id"] != owner_id
            )
            if acquired:
                conn.execute(
                    """INSERT INTO engine_locks(lock_key,owner_id,lease_until,updated_at)
                       VALUES(?,?,?,?)
                       ON CONFLICT(lock_key) DO UPDATE SET owner_id=excluded.owner_id,
                         lease_until=excluded.lease_until,updated_at=excluded.updated_at""",
                    (match_id, owner_id, now + lease_seconds, now),
                )
        try:
            yield acquired
        finally:
            if acquired:
                with self.transaction(immediate=True) as conn:
                    conn.execute(
                        """UPDATE engine_locks SET lease_until=0
                           WHERE lock_key=? AND owner_id=?""",
                        (match_id, owner_id),
                    )
