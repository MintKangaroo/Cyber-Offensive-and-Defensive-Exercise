from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Iterable
from typing import Any

from .db import Database
from .koth import KothService
from .mode_strategies import strategy_for, supported_score_categories
from .models import ROUND_TRANSITIONS, assert_transition
from .stealth import STEALTH_SCORE_TYPES, StealthService
from .utils import canonical_json, evidence_hash, json_load, stable_id


class AttackDefenseRepository:
    def __init__(self, db: Database):
        self.db = db

    @staticmethod
    def normalize_match_config(
        mode: str, config: dict[str, Any]
    ) -> dict[str, Any]:
        strategy = strategy_for(mode)
        koth_config = KothService.normalized_config(config.get("koth", {}))
        stealth_config = StealthService.normalized_config(config.get("stealth", {}))
        # Match creation is the initial policy epoch. Operator reconfiguration
        # replaces this with authoritative database time.
        stealth_config["activated_at"] = 0.0
        requested_categories = config.get("score_categories", list(strategy.score_categories))
        if koth_config["enabled"] and "koth" not in requested_categories:
            requested_categories = [*requested_categories, "koth"]
        if stealth_config["enabled"]:
            requested_categories = [
                *requested_categories,
                *(
                    category for category in sorted(STEALTH_SCORE_TYPES)
                    if category not in requested_categories
                ),
            ]
        if (
            not isinstance(requested_categories, list)
            or not set(requested_categories).issubset(supported_score_categories(mode))
        ):
            raise ValueError("score_categories must be supported by the selected match mode")
        selected = set(requested_categories)
        requested_weights = config.get(
            "score_weights", {category: 1.0 for category in requested_categories}
        )
        if (
            not isinstance(requested_weights, dict)
            or any(
                category not in selected
                or not isinstance(weight, (int, float))
                or float(weight) < 0
                for category, weight in requested_weights.items()
            )
        ):
            raise ValueError("score_weights must be non-negative and mode-supported")
        merged_config = {
            **config,
            "score_categories": requested_categories,
            "koth": koth_config,
            "stealth": stealth_config,
            "score_weights": {
                **{category: 1.0 for category in requested_categories},
                **requested_weights,
                **(
                    {"koth": koth_config["score_weight"]}
                    if koth_config["enabled"] else {}
                ),
                **(
                    {
                        "stealth_attack": stealth_config["attack_score_weight"],
                        "stealth_detection": stealth_config[
                            "detection_score_weight"
                        ],
                    }
                    if stealth_config["enabled"] else {}
                ),
            },
        }
        return merged_config

    def create_match(
        self,
        name: str,
        round_duration_seconds: int,
        active_flag_window: int,
        config: dict[str, Any],
        match_id: str | None = None,
        mode: str = "attack_defense",
    ) -> dict:
        mid = match_id or str(uuid.uuid4())
        merged_config = self.normalize_match_config(mode, config)
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            conn.execute(
                """INSERT INTO matches(
                   id,name,mode,status,round_duration_seconds,active_flag_window,
                   config,created_at,updated_at) VALUES(?,?,?,'draft',?,?,?,?,?)""",
                (mid, name, mode, round_duration_seconds, active_flag_window,
                 canonical_json(merged_config), now, now),
            )
        return self.get_match(mid)

    def get_match(self, match_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
        owned = conn is None
        conn = conn or self.db.connect()
        row = conn.execute("SELECT * FROM matches WHERE id=?", (match_id,)).fetchone()
        if owned:
            conn.close()
        return self._row(row)

    def list_matches(self, statuses: Iterable[str] | None = None) -> list[dict]:
        conn = self.db.connect()
        query = "SELECT * FROM matches WHERE mode IN ('attack_defense','hybrid_live_fire')"
        params: list[Any] = []
        if statuses:
            status_list = list(statuses)
            query += f" AND status IN ({','.join('?' for _ in status_list)})"
            params.extend(status_list)
        rows = [self._row(r) for r in conn.execute(query, params)]
        conn.close()
        return rows

    def add_team(self, match_id: str, slug: str, name: str, team_id: str | None = None) -> dict:
        tid = team_id or str(uuid.uuid4())
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            conn.execute(
                "INSERT INTO teams(id,match_id,slug,name,created_at) VALUES(?,?,?,?,?)",
                (tid, match_id, slug, name, now),
            )
        return self.get_team(tid)

    def get_team(self, team_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
        owned = conn is None
        conn = conn or self.db.connect()
        row = conn.execute("SELECT * FROM teams WHERE id=?", (team_id,)).fetchone()
        if owned:
            conn.close()
        return self._row(row)

    def list_teams(self, match_id: str, conn: sqlite3.Connection | None = None) -> list[dict]:
        owned = conn is None
        conn = conn or self.db.connect()
        rows = [self._row(r) for r in conn.execute(
            "SELECT * FROM teams WHERE match_id=? AND enabled=1 ORDER BY slug", (match_id,)
        )]
        if owned:
            conn.close()
        return rows

    def add_service(
        self,
        match_id: str,
        slug: str,
        name: str,
        base_image: str,
        internal_port: int,
        checker_type: str,
        config: dict[str, Any],
        base_image_digest: str | None = None,
        service_id: str | None = None,
    ) -> dict:
        sid = service_id or str(uuid.uuid4())
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            conn.execute(
                """INSERT INTO game_services(
                   id,match_id,slug,name,base_image,base_image_digest,internal_port,
                   checker_type,config,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    sid, match_id, slug, name, base_image, base_image_digest,
                    internal_port, checker_type, canonical_json(config), now,
                ),
            )
        return self.get_service(sid)

    def get_service(self, service_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
        owned = conn is None
        conn = conn or self.db.connect()
        row = conn.execute("SELECT * FROM game_services WHERE id=?", (service_id,)).fetchone()
        if owned:
            conn.close()
        return self._row(row)

    def list_services(self, match_id: str, conn: sqlite3.Connection | None = None) -> list[dict]:
        owned = conn is None
        conn = conn or self.db.connect()
        rows = [self._row(r) for r in conn.execute(
            "SELECT * FROM game_services WHERE match_id=? AND enabled=1 ORDER BY slug", (match_id,)
        )]
        if owned:
            conn.close()
        return rows

    def ensure_instances(self, match_id: str) -> list[dict]:
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            for team in self.list_teams(match_id, conn):
                for service in self.list_services(match_id, conn):
                    config = json_load(service["config"])
                    endpoint = str(config.get("endpoint_template", "")).format(
                        team_slug=team["slug"], service_slug=service["slug"]
                    )
                    management = str(config.get("management_endpoint_template", "")).format(
                        team_slug=team["slug"], service_slug=service["slug"]
                    )
                    runtime_id = str(
                        (config.get("runtime_id_by_team") or {}).get(team["slug"])
                        or config.get("runtime_id_template", "{team_slug}-{service_slug}")
                    ).format(team_slug=team["slug"], service_slug=service["slug"])
                    endpoint = str(
                        (config.get("endpoint_by_team") or {}).get(team["slug"]) or endpoint
                    )
                    management = str(
                        (config.get("management_endpoint_by_team") or {}).get(team["slug"])
                        or management
                    )
                    iid = stable_id("instance", match_id, team["id"], service["id"])
                    conn.execute(
                        """INSERT OR IGNORE INTO team_service_instances(
                           id,match_id,team_id,service_id,runtime_id,image_digest,status,
                           endpoint,management_endpoint,updated_at)
                           VALUES(?,?,?,?,?,?,?,NULLIF(?,''),NULLIF(?,''),?)""",
                        (
                            iid, match_id, team["id"], service["id"],
                            runtime_id,
                            service["base_image_digest"] or service["base_image"],
                            "declared", endpoint, management, now,
                        ),
                    )
        return self.list_instances(match_id)

    def list_instances(
        self, match_id: str, team_id: str | None = None, conn: sqlite3.Connection | None = None
    ) -> list[dict]:
        owned = conn is None
        conn = conn or self.db.connect()
        query = (
            "SELECT i.*,t.slug AS team_slug,s.slug AS service_slug,s.checker_type,"
            "s.config AS service_config,s.base_image,s.base_image_digest,"
            "s.internal_port FROM team_service_instances i "
            "JOIN teams t ON t.id=i.team_id JOIN game_services s ON s.id=i.service_id "
            "WHERE i.match_id=?"
        )
        params: list[Any] = [match_id]
        if team_id:
            query += " AND i.team_id=?"
            params.append(team_id)
        query += " ORDER BY t.slug,s.slug"
        rows = [self._row(r) for r in conn.execute(query, params)]
        if owned:
            conn.close()
        return rows

    def get_instance(
        self, match_id: str, team_id: str, service_id: str,
        conn: sqlite3.Connection | None = None,
    ) -> dict | None:
        owned = conn is None
        conn = conn or self.db.connect()
        row = conn.execute(
            """SELECT i.*,t.slug AS team_slug,s.slug AS service_slug,s.checker_type,
                      s.config AS service_config,s.base_image,s.base_image_digest,
                      s.internal_port
               FROM team_service_instances i
               JOIN teams t ON t.id=i.team_id JOIN game_services s ON s.id=i.service_id
               WHERE i.match_id=? AND i.team_id=? AND i.service_id=?""",
            (match_id, team_id, service_id),
        ).fetchone()
        if owned:
            conn.close()
        return self._row(row)

    def create_round(self, match_id: str) -> dict:
        with self.db.transaction(immediate=True) as conn:
            existing = conn.execute(
                """SELECT * FROM rounds WHERE match_id=? AND status NOT IN
                   ('finalized','failed') ORDER BY sequence DESC LIMIT 1""",
                (match_id,),
            ).fetchone()
            if existing:
                return self._row(existing)
            seq = conn.execute(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM rounds WHERE match_id=?", (match_id,)
            ).fetchone()[0]
            rid = stable_id("round", match_id, seq)
            correlation = stable_id("round-correlation", match_id, seq)
            now = self.db.server_time(conn)
            conn.execute(
                """INSERT OR IGNORE INTO rounds(
                   id,match_id,sequence,status,correlation_id,created_at)
                   VALUES(?,?,?,'pending',?,?)""",
                (rid, match_id, seq, correlation, now),
            )
            conn.execute(
                "UPDATE matches SET current_round_id=?,updated_at=? WHERE id=?",
                (rid, now, match_id),
            )
            row = conn.execute("SELECT * FROM rounds WHERE id=?", (rid,)).fetchone()
        return self._row(row)

    def get_round(self, round_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
        owned = conn is None
        conn = conn or self.db.connect()
        row = conn.execute("SELECT * FROM rounds WHERE id=?", (round_id,)).fetchone()
        if owned:
            conn.close()
        return self._row(row)

    def current_round(self, match_id: str, conn: sqlite3.Connection | None = None) -> dict | None:
        owned = conn is None
        conn = conn or self.db.connect()
        row = conn.execute(
            "SELECT r.* FROM matches m LEFT JOIN rounds r ON r.id=m.current_round_id WHERE m.id=?",
            (match_id,),
        ).fetchone()
        if owned:
            conn.close()
        return self._row(row) if row and row["id"] else None

    def transition_round(
        self, round_id: str, target: str, fields: dict[str, Any] | None = None
    ) -> dict:
        fields = fields or {}
        allowed_fields = {
            "starts_at", "ends_at", "finalized_at", "last_check_at", "failure_reason"
        }
        if set(fields) - allowed_fields:
            raise ValueError("unsupported round transition fields")
        with self.db.transaction(immediate=True) as conn:
            row = conn.execute("SELECT * FROM rounds WHERE id=?", (round_id,)).fetchone()
            if not row:
                raise KeyError(round_id)
            if row["status"] != target:
                assert_transition(row["status"], target, ROUND_TRANSITIONS)
                sets = ["status=?"] + [f"{k}=?" for k in fields]
                values = [target, *fields.values(), round_id, row["status"]]
                cur = conn.execute(
                    f"UPDATE rounds SET {','.join(sets)} WHERE id=? AND status=?", values
                )
                if cur.rowcount != 1:
                    raise RuntimeError("round changed concurrently")
            row = conn.execute("SELECT * FROM rounds WHERE id=?", (round_id,)).fetchone()
        return self._row(row)

    def extend_round_end(self, round_id: str, add_seconds: float, now: float) -> dict | None:
        """감사 4.7: 다운타임 보정 — active 라운드의 ends_at을 add_seconds만큼 뒤로 밀고
        last_check_at을 now로 갱신한다(상태는 그대로). 크래시/재기동으로 tick이 멈춘 공백을
        라운드 잔여시간에 되돌려준다."""
        with self.db.transaction(immediate=True) as conn:
            cur = conn.execute(
                "UPDATE rounds SET ends_at=ends_at+?, last_check_at=? "
                "WHERE id=? AND status='active' AND ends_at IS NOT NULL",
                (add_seconds, now, round_id),
            )
            if cur.rowcount != 1:
                return None
            row = conn.execute("SELECT * FROM rounds WHERE id=?", (round_id,)).fetchone()
        return self._row(row)

    def insert_ledger(
        self,
        conn: sqlite3.Connection,
        *,
        event_id: str,
        match_id: str,
        round_id: str | None,
        team_id: str,
        service_id: str | None,
        score_type: str,
        delta: int,
        reason: str,
        evidence: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        now = self.db.server_time(conn)
        cur = conn.execute(
            """INSERT OR IGNORE INTO score_ledger(
               id,event_id,match_id,round_id,team_id,service_id,score_type,delta,
               reason,evidence_hash,metadata,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                stable_id("ledger", event_id), event_id, match_id, round_id, team_id,
                service_id, score_type, delta, reason, evidence_hash(evidence),
                canonical_json(metadata or {}), now,
            ),
        )
        return cur.rowcount == 1

    @staticmethod
    def _row(row: sqlite3.Row | None) -> dict | None:
        return dict(row) if row is not None else None
