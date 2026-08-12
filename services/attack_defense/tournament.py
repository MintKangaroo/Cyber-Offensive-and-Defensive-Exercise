from __future__ import annotations

import math
import uuid
from typing import TYPE_CHECKING, Any

from .db import Database
from .evidence import AuditContext, EvidenceRecorder
from .utils import canonical_json, json_load, stable_id

if TYPE_CHECKING:
    from .repositories import AttackDefenseRepository
    from .scoring import ScoringService


BRACKET_SIZES = {2, 4, 8, 16}
TOURNAMENT_MATCH_MODES = {"attack_defense", "hybrid_live_fire"}


def seed_order(size: int) -> list[int]:
    """Return deterministic standard single-elimination seed slots."""
    if size not in BRACKET_SIZES:
        raise ValueError("bracket_size must be one of 2, 4, 8, or 16")
    order = [1, 2]
    while len(order) < size:
        complement = len(order) * 2 + 1
        order = [value for seed in order for value in (seed, complement - seed)]
    return order


def stage_name(sequence: int, total_stages: int) -> str:
    remaining = total_stages - sequence + 1
    return {
        1: "Final",
        2: "Semifinal",
        3: "Quarterfinal",
    }.get(remaining, f"Round of {2 ** remaining}")


class TournamentService:
    """Deterministic tournament bracket over isolated existing Matches.

    Tournament state never replaces Match state. Each fixture materializes a
    normal symmetric Match with fresh team/service IDs and an append-only map
    back to the stable tournament entries.
    """

    def __init__(
        self,
        db: Database,
        repo: AttackDefenseRepository,
        scoring: ScoringService,
        evidence: EvidenceRecorder,
    ):
        self.db = db
        self.repo = repo
        self.scoring = scoring
        self.evidence = evidence

    def create(
        self,
        *,
        name: str,
        bracket_size: int,
        match_mode: str,
        round_duration_seconds: int,
        active_flag_window: int,
        match_config: dict[str, Any],
        actor: str,
        tournament_id: str | None = None,
    ) -> dict[str, Any]:
        if bracket_size not in BRACKET_SIZES:
            raise ValueError("bracket_size must be one of 2, 4, 8, or 16")
        if match_mode not in TOURNAMENT_MATCH_MODES:
            raise ValueError("tournament Match mode must be symmetric")
        if not isinstance(match_config, dict):
            raise TypeError("match_config must be an object")
        normalized_match_config = self.repo.normalize_match_config(
            match_mode, match_config
        )
        tid = tournament_id or str(uuid.uuid4())
        with self.db.transaction(immediate=True) as conn:
            now = self.db.server_time(conn)
            conn.execute(
                """INSERT INTO tournaments(
                   id,name,format,status,match_mode,bracket_size,
                   round_duration_seconds,active_flag_window,config,
                   created_at,updated_at)
                   VALUES(?,?,'single_elimination','draft',?,?,?,?,?,?,?)""",
                (
                    tid, name, match_mode, bracket_size,
                    round_duration_seconds, active_flag_window,
                    canonical_json({"match_config": normalized_match_config}), now, now,
                ),
            )
            self.evidence.record(
                AuditContext(
                    actor=actor,
                    event_type="tournament_created",
                    result="success",
                    metadata={
                        "tournament_id": tid,
                        "format": "single_elimination",
                        "bracket_size": bracket_size,
                        "match_mode": match_mode,
                    },
                    event_id=stable_id("audit", "tournament-create", tid),
                ),
                conn,
            )
        return self.state(tid, operator=True)

    def add_entry(
        self,
        tournament_id: str,
        *,
        slug: str,
        name: str,
        identity_subject: str,
        seed: int | None,
        actor: str,
        entry_id: str | None = None,
    ) -> dict[str, Any]:
        eid = entry_id or stable_id("tournament-entry", tournament_id, slug)
        with self.db.transaction(immediate=True) as conn:
            tournament = self._get_tournament(conn, tournament_id)
            if tournament["status"] != "draft":
                raise ValueError("teams can be registered only in draft")
            if seed is not None and not 1 <= seed <= int(tournament["bracket_size"]):
                raise ValueError("seed is outside bracket")
            count = int(conn.execute(
                "SELECT COUNT(*) FROM tournament_entries WHERE tournament_id=?",
                (tournament_id,),
            ).fetchone()[0])
            if count >= int(tournament["bracket_size"]):
                raise ValueError("tournament bracket is full")
            now = self.db.server_time(conn)
            conn.execute(
                """INSERT INTO tournament_entries(
                   id,tournament_id,slug,name,identity_subject,seed,
                   created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)""",
                (eid, tournament_id, slug, name, identity_subject, seed, now, now),
            )
            self.evidence.record(
                AuditContext(
                    actor=actor,
                    event_type="tournament_team_registered",
                    result="success",
                    metadata={
                        "tournament_id": tournament_id,
                        "entry_id": eid,
                        "slug": slug,
                        "seed": seed,
                    },
                    event_id=stable_id("audit", "tournament-entry", eid),
                ),
                conn,
            )
        return self.entry(eid, operator=True)

    def add_service(
        self,
        tournament_id: str,
        *,
        slug: str,
        name: str,
        base_image: str,
        internal_port: int,
        checker_type: str,
        config: dict[str, Any],
        actor: str,
        base_image_digest: str | None = None,
        service_id: str | None = None,
    ) -> dict[str, Any]:
        sid = service_id or stable_id("tournament-service", tournament_id, slug)
        with self.db.transaction(immediate=True) as conn:
            tournament = self._get_tournament(conn, tournament_id)
            if tournament["status"] != "draft":
                raise ValueError("services can be registered only in draft")
            now = self.db.server_time(conn)
            conn.execute(
                """INSERT INTO tournament_services(
                   id,tournament_id,slug,name,base_image,base_image_digest,
                   internal_port,checker_type,config,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    sid, tournament_id, slug, name, base_image,
                    base_image_digest, internal_port, checker_type,
                    canonical_json(config), now,
                ),
            )
            self.evidence.record(
                AuditContext(
                    actor=actor,
                    event_type="tournament_service_registered",
                    result="success",
                    metadata={
                        "tournament_id": tournament_id,
                        "service_id": sid,
                        "slug": slug,
                    },
                    event_id=stable_id("audit", "tournament-service", sid),
                ),
                conn,
            )
        return {
            "id": sid, "tournament_id": tournament_id, "slug": slug,
            "name": name,
        }

    def seed(self, tournament_id: str, actor: str, reason: str) -> dict[str, Any]:
        if not reason.strip():
            raise ValueError("seeding reason is required")
        with self.db.transaction(immediate=True) as conn:
            tournament = self._get_tournament(conn, tournament_id)
            if tournament["status"] != "draft":
                raise ValueError("only draft tournaments can be seeded")
            size = int(tournament["bracket_size"])
            entries = [dict(row) for row in conn.execute(
                """SELECT * FROM tournament_entries WHERE tournament_id=?
                   ORDER BY CASE WHEN seed IS NULL THEN 1 ELSE 0 END,
                            seed,created_at,slug""",
                (tournament_id,),
            )]
            if len(entries) != size:
                raise ValueError("bracket requires exactly the configured team count")
            services = conn.execute(
                "SELECT COUNT(*) FROM tournament_services WHERE tournament_id=?",
                (tournament_id,),
            ).fetchone()[0]
            if not services:
                raise ValueError("tournament requires at least one service")
            used = {int(item["seed"]) for item in entries if item["seed"] is not None}
            available = iter(seed for seed in range(1, size + 1) if seed not in used)
            for entry in entries:
                if entry["seed"] is None:
                    entry["seed"] = next(available)
                    conn.execute(
                        "UPDATE tournament_entries SET seed=? WHERE id=?",
                        (entry["seed"], entry["id"]),
                    )
            by_seed = {int(item["seed"]): item for item in entries}
            total_stages = int(math.log2(size))
            now = self.db.server_time(conn)
            for sequence in range(1, total_stages + 1):
                stage_id = stable_id("tournament-stage", tournament_id, sequence)
                conn.execute(
                    """INSERT INTO tournament_stages(
                       id,tournament_id,sequence,name,status,created_at)
                       VALUES(?,?,?,?,?,?)""",
                    (
                        stage_id, tournament_id, sequence,
                        stage_name(sequence, total_stages),
                        "scheduled" if sequence == 1 else "pending", now,
                    ),
                )
                fixture_count = size // (2 ** sequence)
                for position in range(1, fixture_count + 1):
                    fixture_id = stable_id(
                        "tournament-fixture", tournament_id, sequence, position
                    )
                    team_a = team_b = None
                    if sequence == 1:
                        slots = seed_order(size)[(position - 1) * 2:position * 2]
                        team_a = by_seed[slots[0]]["id"]
                        team_b = by_seed[slots[1]]["id"]
                    conn.execute(
                        """INSERT INTO tournament_fixtures(
                           id,tournament_id,stage_id,stage_sequence,
                           bracket_position,status,team_a_entry_id,team_b_entry_id,
                           created_at,updated_at)
                           VALUES(?,?,?,?,?,'pending',?,?,?,?)""",
                        (
                            fixture_id, tournament_id, stage_id, sequence,
                            position, team_a, team_b, now, now,
                        ),
                    )
            conn.execute(
                """UPDATE tournaments SET status='seeded',current_stage=1,
                   updated_at=? WHERE id=?""",
                (now, tournament_id),
            )
            self.evidence.record(
                AuditContext(
                    actor=actor,
                    event_type="tournament_seeded",
                    result="success",
                    metadata={
                        "tournament_id": tournament_id,
                        "reason": reason,
                        "bracket_size": size,
                    },
                    event_id=stable_id("audit", "tournament-seed", tournament_id),
                ),
                conn,
            )
        self.reconcile(tournament_id, actor)
        return self.state(tournament_id, operator=True)

    def start(self, tournament_id: str, actor: str, reason: str) -> dict[str, Any]:
        if not reason.strip():
            raise ValueError("start reason is required")
        already_running = False
        with self.db.transaction(immediate=True) as conn:
            tournament = self._get_tournament(conn, tournament_id)
            if tournament["status"] == "running":
                already_running = True
            elif tournament["status"] != "seeded":
                raise ValueError("only seeded tournaments can start")
            if not already_running:
                now = self.db.server_time(conn)
                conn.execute(
                    """UPDATE tournaments SET status='running',starts_at=?,updated_at=?
                       WHERE id=?""",
                    (now, now, tournament_id),
                )
                self.evidence.record(
                    AuditContext(
                        actor=actor,
                        event_type="tournament_started",
                        result="success",
                        metadata={"tournament_id": tournament_id, "reason": reason},
                        event_id=stable_id(
                            "audit", "tournament-start", tournament_id
                        ),
                    ),
                    conn,
                )
        return self.state(tournament_id, operator=True)

    def reconcile(self, tournament_id: str, actor: str) -> dict[str, Any]:
        conn = self.db.connect()
        try:
            self._get_tournament(conn, tournament_id)
            fixture_ids = [row[0] for row in conn.execute(
                """SELECT id FROM tournament_fixtures WHERE tournament_id=?
                   AND team_a_entry_id IS NOT NULL AND team_b_entry_id IS NOT NULL
                   AND status='pending' ORDER BY stage_sequence,bracket_position""",
                (tournament_id,),
            )]
        finally:
            conn.close()
        materialized = 0
        for fixture_id in fixture_ids:
            if self._materialize_fixture(fixture_id, actor):
                materialized += 1
        return {"tournament_id": tournament_id, "materialized": materialized}

    def _materialize_fixture(self, fixture_id: str, actor: str) -> bool:
        conn = self.db.connect()
        try:
            fixture = self._fixture(conn, fixture_id)
            if not fixture or not fixture["team_a_entry_id"] or not fixture["team_b_entry_id"]:
                return False
            tournament = self._get_tournament(conn, fixture["tournament_id"])
            entries = {
                row["id"]: dict(row) for row in conn.execute(
                    "SELECT * FROM tournament_entries WHERE tournament_id=?",
                    (fixture["tournament_id"],),
                )
            }
            services = [dict(row) for row in conn.execute(
                "SELECT * FROM tournament_services WHERE tournament_id=? ORDER BY slug",
                (fixture["tournament_id"],),
            )]
        finally:
            conn.close()
        match_id = stable_id("tournament-match", fixture_id)
        if not self.repo.get_match(match_id):
            config = json_load(tournament["config"]).get("match_config", {})
            config = {
                **(config if isinstance(config, dict) else {}),
                "tournament_id": tournament["id"],
                "tournament_fixture_id": fixture_id,
            }
            try:
                self.repo.create_match(
                    f"{tournament['name']} · {stage_name(int(fixture['stage_sequence']), int(math.log2(int(tournament['bracket_size']))))} {fixture['bracket_position']}",
                    int(tournament["round_duration_seconds"]),
                    int(tournament["active_flag_window"]),
                    config,
                    match_id,
                    tournament["match_mode"],
                )
            except self.db.integrity_error:
                if not self.repo.get_match(match_id):
                    raise
        for entry_id in (fixture["team_a_entry_id"], fixture["team_b_entry_id"]):
            entry = entries[entry_id]
            match_team_id = stable_id("tournament-match-team", fixture_id, entry_id)
            if not self.repo.get_team(match_team_id):
                try:
                    self.repo.add_team(
                        match_id, entry["slug"], entry["name"], match_team_id
                    )
                except self.db.integrity_error:
                    if not self.repo.get_team(match_team_id):
                        raise
        for service in services:
            game_service_id = stable_id(
                "tournament-game-service", fixture_id, service["id"]
            )
            if not self.repo.get_service(game_service_id):
                try:
                    self.repo.add_service(
                        match_id,
                        service["slug"],
                        service["name"],
                        service["base_image"],
                        int(service["internal_port"]),
                        service["checker_type"],
                        json_load(service["config"]),
                        service["base_image_digest"],
                        game_service_id,
                    )
                except self.db.integrity_error:
                    if not self.repo.get_service(game_service_id):
                        raise
        self.repo.ensure_instances(match_id)
        with self.db.transaction(immediate=True) as conn:
            current = self._fixture(conn, fixture_id)
            if current["match_id"]:
                return False
            now = self.db.server_time(conn)
            conn.execute(
                """UPDATE tournament_fixtures SET match_id=?,status='scheduled',
                   scheduled_at=?,updated_at=? WHERE id=? AND match_id IS NULL""",
                (match_id, now, now, fixture_id),
            )
            conn.execute(
                """UPDATE tournament_stages SET status='scheduled'
                   WHERE id=? AND status='pending'""",
                (current["stage_id"],),
            )
            for entry_id in (fixture["team_a_entry_id"], fixture["team_b_entry_id"]):
                conn.execute(
                    """INSERT INTO tournament_match_teams(
                       fixture_id,entry_id,match_team_id,created_at)
                       VALUES(?,?,?,?) ON CONFLICT(fixture_id,entry_id) DO NOTHING""",
                    (
                        fixture_id, entry_id,
                        stable_id("tournament-match-team", fixture_id, entry_id), now,
                    ),
                )
            self.evidence.record(
                AuditContext(
                    actor=actor,
                    event_type="tournament_fixture_scheduled",
                    result="success",
                    match_id=match_id,
                    metadata={
                        "tournament_id": tournament["id"],
                        "fixture_id": fixture_id,
                    },
                    event_id=stable_id("audit", "fixture-scheduled", fixture_id),
                ),
                conn,
            )
        return True

    def mark_fixture_running(
        self, fixture_id: str, actor: str, reason: str
    ) -> dict[str, Any]:
        if not reason.strip():
            raise ValueError("fixture start reason is required")
        already_running = False
        with self.db.transaction(immediate=True) as conn:
            fixture = self._fixture(conn, fixture_id)
            if fixture and fixture["status"] == "running":
                already_running = True
            elif not fixture or fixture["status"] != "scheduled":
                raise ValueError("only scheduled fixtures can start")
            if not already_running:
                tournament = self._get_tournament(conn, fixture["tournament_id"])
                if tournament["status"] != "running":
                    raise ValueError("tournament is not running")
                match = self.repo.get_match(fixture["match_id"], conn)
                if not match or match["status"] != "running":
                    raise ValueError("fixture Match did not start")
                now = self.db.server_time(conn)
                conn.execute(
                    """UPDATE tournament_fixtures SET status='running',started_at=?,
                       updated_at=? WHERE id=?""",
                    (now, now, fixture_id),
                )
                conn.execute(
                    "UPDATE tournament_stages SET status='active' WHERE id=?",
                    (fixture["stage_id"],),
                )
                self.evidence.record(
                    AuditContext(
                        actor=actor,
                        event_type="tournament_fixture_started",
                        result="success",
                        match_id=fixture["match_id"],
                        metadata={
                            "tournament_id": fixture["tournament_id"],
                            "fixture_id": fixture_id,
                            "reason": reason,
                        },
                        event_id=stable_id(
                            "audit", "fixture-start", fixture_id
                        ),
                    ),
                    conn,
                )
        return self.fixture(fixture_id, operator=True)

    def finalize_fixture(
        self,
        fixture_id: str,
        actor: str,
        reason: str,
        winner_entry_id: str | None = None,
    ) -> dict[str, Any]:
        if not reason.strip():
            raise ValueError("fixture finalization reason is required")
        conn = self.db.connect()
        try:
            fixture = self._fixture(conn, fixture_id)
            if not fixture:
                raise ValueError("fixture is not finalizable")
            if fixture["status"] == "finalized":
                return self.fixture(fixture_id, operator=True)
            if fixture["status"] not in {"running", "scheduled"}:
                raise ValueError("fixture is not finalizable")
            match = self.repo.get_match(fixture["match_id"], conn)
            if not match or match["status"] != "ended":
                raise ValueError("fixture Match must be ended first")
            mappings = [dict(row) for row in conn.execute(
                "SELECT * FROM tournament_match_teams WHERE fixture_id=?",
                (fixture_id,),
            )]
        finally:
            conn.close()
        board = self.scoring.scoreboard(fixture["match_id"], public=False)
        by_match_team = {row["team_id"]: row for row in board}
        entry_scores = {
            item["entry_id"]: by_match_team[item["match_team_id"]]
            for item in mappings
        }
        participants = {fixture["team_a_entry_id"], fixture["team_b_entry_id"]}
        if winner_entry_id is not None and winner_entry_id not in participants:
            raise ValueError("winner must be a fixture participant")
        ordered = sorted(
            entry_scores.items(),
            key=lambda item: (
                -float(item[1]["total"]),
                -int(item[1]["attack"]),
                -int(item[1]["availability"]),
                item[0],
            ),
        )
        first, second = ordered[0], ordered[1]
        tie_key = lambda row: (
            float(row["total"]), int(row["attack"]), int(row["availability"])
        )
        tied = tie_key(first[1]) == tie_key(second[1])
        if winner_entry_id is None:
            if tied:
                raise ValueError("tied fixture requires an explicit winner")
            winner_entry_id = first[0]
        elif not tied and winner_entry_id != first[0]:
            raise ValueError("explicit winner cannot override the scoreboard")
        loser_entry_id = next(item for item in participants if item != winner_entry_id)
        public_result = {
            entry_id: {
                "total": row["total"],
                "attack": row["attack"],
                "defense": row["defense"],
                "flag_defense": row["flag_defense"],
                "availability": row["availability"],
            }
            for entry_id, row in entry_scores.items()
        }
        tournament_completed = False
        with self.db.transaction(immediate=True) as conn:
            latest = self._fixture(conn, fixture_id)
            if latest["status"] == "finalized":
                # A concurrent finalizer won after the read above. Avoid opening
                # a second SQLite connection while this write transaction is
                # active; the committed state is returned below.
                tournament_completed = True
            else:
                now = self.db.server_time(conn)
                conn.execute(
                    """UPDATE tournament_fixtures SET status='finalized',
                       winner_entry_id=?,loser_entry_id=?,result=?,completed_at=?,
                       updated_at=? WHERE id=?""",
                    (
                        winner_entry_id, loser_entry_id,
                        canonical_json({"scores": public_result, "reason": reason}),
                        now, now, fixture_id,
                    ),
                )
                conn.execute(
                    """UPDATE tournament_entries SET status='eliminated',updated_at=?
                       WHERE id=?""",
                    (now, loser_entry_id),
                )
                remaining = conn.execute(
                    """SELECT COUNT(*) FROM tournament_fixtures
                       WHERE stage_id=? AND status!='finalized'""",
                    (latest["stage_id"],),
                ).fetchone()[0]
                if int(remaining) == 0:
                    conn.execute(
                        """UPDATE tournament_stages SET status='finalized',completed_at=?
                           WHERE id=?""",
                        (now, latest["stage_id"]),
                    )
                tournament = self._get_tournament(conn, latest["tournament_id"])
                final_stage = int(math.log2(int(tournament["bracket_size"])))
                if int(latest["stage_sequence"]) == final_stage:
                    tournament_completed = True
                    conn.execute(
                        """UPDATE tournament_entries SET status='champion',updated_at=?
                           WHERE id=?""",
                        (now, winner_entry_id),
                    )
                    conn.execute(
                        """UPDATE tournaments SET status='completed',
                           winner_entry_id=?,completed_at=?,updated_at=? WHERE id=?""",
                        (winner_entry_id, now, now, tournament["id"]),
                    )
                else:
                    next_sequence = int(latest["stage_sequence"]) + 1
                    next_position = (int(latest["bracket_position"]) + 1) // 2
                    slot = (
                        "team_a_entry_id"
                        if int(latest["bracket_position"]) % 2 == 1
                        else "team_b_entry_id"
                    )
                    conn.execute(
                        f"""UPDATE tournament_fixtures SET {slot}=?,updated_at=?
                            WHERE tournament_id=? AND stage_sequence=?
                            AND bracket_position=? AND {slot} IS NULL""",
                        (
                            winner_entry_id, now, tournament["id"],
                            next_sequence, next_position,
                        ),
                    )
                    conn.execute(
                        """UPDATE tournaments SET current_stage=CASE
                             WHEN current_stage<? THEN ? ELSE current_stage END,
                           updated_at=? WHERE id=?""",
                        (next_sequence, next_sequence, now, tournament["id"]),
                    )
                self.evidence.record(
                    AuditContext(
                        actor=actor,
                        event_type="tournament_fixture_finalized",
                        result="success",
                        match_id=latest["match_id"],
                        metadata={
                            "tournament_id": latest["tournament_id"],
                            "fixture_id": fixture_id,
                            "winner_entry_id": winner_entry_id,
                            "loser_entry_id": loser_entry_id,
                            "reason": reason,
                        },
                        event_id=stable_id("audit", "fixture-finalize", fixture_id),
                    ),
                    conn,
                )
        if not tournament_completed:
            self.reconcile(fixture["tournament_id"], actor)
        return self.fixture(fixture_id, operator=True)

    def resolve_entry(
        self,
        tournament_id: str,
        *,
        actor: str,
        tournament_claim: str,
        match_id: str,
        team_id: str,
    ) -> dict[str, Any] | None:
        conn = self.db.connect()
        try:
            if tournament_claim == tournament_id:
                row = conn.execute(
                    """SELECT * FROM tournament_entries
                       WHERE tournament_id=? AND identity_subject=?""",
                    (tournament_id, actor),
                ).fetchone()
                if row:
                    return dict(row)
            row = conn.execute(
                """SELECT e.* FROM tournament_entries e
                   JOIN tournament_match_teams mt ON mt.entry_id=e.id
                   JOIN tournament_fixtures f ON f.id=mt.fixture_id
                   WHERE e.tournament_id=? AND f.match_id=? AND mt.match_team_id=?""",
                (tournament_id, match_id, team_id),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def participant_state(
        self, tournament_id: str, entry_id: str
    ) -> dict[str, Any]:
        state = self.state(tournament_id, operator=False)
        conn = self.db.connect()
        try:
            rows = [dict(row) for row in conn.execute(
                """SELECT f.id AS fixture_id,f.match_id,f.status,
                          mt.match_team_id,f.stage_sequence,f.bracket_position
                   FROM tournament_match_teams mt
                   JOIN tournament_fixtures f ON f.id=mt.fixture_id
                   WHERE mt.entry_id=? ORDER BY f.stage_sequence DESC""",
                (entry_id,),
            )]
        finally:
            conn.close()
        state["identity"] = {
            "entry_id": entry_id,
            "fixtures": rows,
            "credential_scope": "fresh-match-token-required-per-fixture",
        }
        return state

    def entry(self, entry_id: str, *, operator: bool) -> dict[str, Any]:
        conn = self.db.connect()
        try:
            row = conn.execute(
                "SELECT * FROM tournament_entries WHERE id=?", (entry_id,)
            ).fetchone()
            if not row:
                raise KeyError(entry_id)
            item = dict(row)
            if not operator:
                item.pop("identity_subject", None)
            return item
        finally:
            conn.close()

    def fixture(self, fixture_id: str, *, operator: bool) -> dict[str, Any]:
        conn = self.db.connect()
        try:
            row = self._fixture(conn, fixture_id)
            if not row:
                raise KeyError(fixture_id)
            item = dict(row)
            item["result"] = json_load(item["result"])
            if operator:
                item["match_teams"] = [dict(value) for value in conn.execute(
                    "SELECT * FROM tournament_match_teams WHERE fixture_id=?",
                    (fixture_id,),
                )]
            return item
        finally:
            conn.close()

    def state(self, tournament_id: str, *, operator: bool) -> dict[str, Any]:
        conn = self.db.connect()
        try:
            tournament = dict(self._get_tournament(conn, tournament_id))
            tournament["config"] = (
                json_load(tournament["config"]) if operator else {}
            )
            entries = [dict(row) for row in conn.execute(
                """SELECT * FROM tournament_entries WHERE tournament_id=?
                   ORDER BY seed,slug""",
                (tournament_id,),
            )]
            if not operator:
                for entry in entries:
                    entry.pop("identity_subject", None)
            fixtures = [dict(row) for row in conn.execute(
                """SELECT f.*,a.name AS team_a,b.name AS team_b,w.name AS winner
                   FROM tournament_fixtures f
                   LEFT JOIN tournament_entries a ON a.id=f.team_a_entry_id
                   LEFT JOIN tournament_entries b ON b.id=f.team_b_entry_id
                   LEFT JOIN tournament_entries w ON w.id=f.winner_entry_id
                   WHERE f.tournament_id=?
                   ORDER BY f.stage_sequence,f.bracket_position""",
                (tournament_id,),
            )]
            for fixture in fixtures:
                fixture["result"] = json_load(fixture["result"])
                if not operator:
                    fixture.pop("loser_entry_id", None)
                    fixture.pop("match_id", None)
                    if isinstance(fixture["result"], dict):
                        fixture["result"].pop("reason", None)
            stages = [dict(row) for row in conn.execute(
                """SELECT * FROM tournament_stages WHERE tournament_id=?
                   ORDER BY sequence""",
                (tournament_id,),
            )]
            services = [
                {
                    "id": row["id"], "slug": row["slug"], "name": row["name"]
                }
                for row in conn.execute(
                    """SELECT id,slug,name FROM tournament_services
                       WHERE tournament_id=? ORDER BY slug""",
                    (tournament_id,),
                )
            ]
        finally:
            conn.close()
        return {
            **tournament,
            "entries": entries,
            "stages": stages,
            "fixtures": fixtures,
            "services": services,
            "disclosure": (
                "operator-bracket-and-identity-map"
                if operator else "public-bracket-no-credential-or-runtime-data"
            ),
        }

    @staticmethod
    def _fixture(conn: Any, fixture_id: str):
        return conn.execute(
            "SELECT * FROM tournament_fixtures WHERE id=?", (fixture_id,)
        ).fetchone()

    @staticmethod
    def _get_tournament(conn: Any, tournament_id: str):
        row = conn.execute(
            "SELECT * FROM tournaments WHERE id=?", (tournament_id,)
        ).fetchone()
        if not row:
            raise KeyError(tournament_id)
        return row
