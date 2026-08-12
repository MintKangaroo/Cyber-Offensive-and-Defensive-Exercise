from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Response,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse

from shared.rbac import Identity, authenticate, require_role

from .checker import HttpFlagInjector, HttpWorkflowChecker
from .config import AttackDefenseSettings
from .db import Database
from .evidence import AuditContext, EvidenceRecorder
from .flag_service import FlagService
from .game_engine import GameEngine
from .koth import KothService
from .metrics import render_metrics
from .patch_pipeline import HttpRegistryInspector, PatchPipeline, RegistryInspector
from .pcap_privacy import (
    CaptureIntegrityError,
    CaptureNotReleased,
    CaptureService,
    PcapPrivacyError,
)
from .rate_limit import DistributedRateLimiter
from .repositories import AttackDefenseRepository
from .schemas import (
    AdjustmentRequest,
    AnnouncementRequest,
    ExtendRoundRequest,
    FlagSubmitRequest,
    KothConfigureRequest,
    MatchCreateRequest,
    PatchSubmitRequest,
    ReasonRequest,
    RuntimeCompleteRequest,
    RuntimeInstanceResultRequest,
    ScoreEventRequest,
    ServiceCreateRequest,
    ServiceEnableRequest,
    StealthConfigureRequest,
    StealthDetectionReportRequest,
    TeamCreateRequest,
    TournamentCreateRequest,
    TournamentEntryCreateRequest,
    TournamentFixtureFinalizeRequest,
    TournamentServiceCreateRequest,
)
from .scoring import ScoringService
from .service_fabric import DeclaredComposeRuntime, ServiceRuntime
from .stealth import StealthService
from .tournament import TournamentService
from .utils import json_load, stable_id


logger = logging.getLogger("attack_defense.api")


@dataclass
class Components:
    settings: AttackDefenseSettings
    db: Database
    repo: AttackDefenseRepository
    evidence: EvidenceRecorder
    koth: KothService
    stealth: StealthService
    tournaments: TournamentService
    flags: FlagService
    scoring: ScoringService
    checker: HttpWorkflowChecker
    runtime: ServiceRuntime
    patches: PatchPipeline
    captures: CaptureService
    rate_limiter: DistributedRateLimiter
    engine: GameEngine


def build_components(
    settings: AttackDefenseSettings | None = None,
    *,
    runtime: ServiceRuntime | None = None,
    inspector: RegistryInspector | None = None,
) -> Components:
    settings = settings or AttackDefenseSettings.from_env()
    settings.validate()
    db = Database(
        settings.database_path,
        settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
        statement_timeout_ms=settings.database_statement_timeout_ms,
        application_name=settings.database_application_name,
    )
    db.migrate()
    repo = AttackDefenseRepository(db)
    evidence = EvidenceRecorder(db)
    koth = KothService(db, repo, evidence)
    stealth = StealthService(db, repo, evidence)
    flags = FlagService(db, repo, settings, evidence, koth, stealth)
    scoring = ScoringService(db, repo, settings, evidence, koth, stealth)
    tournaments = TournamentService(db, repo, scoring, evidence)
    injector = HttpFlagInjector(settings)
    checker = HttpWorkflowChecker(settings, injector)
    runtime = runtime or DeclaredComposeRuntime()
    patches = PatchPipeline(
        db, repo, settings, evidence,
        inspector or HttpRegistryInspector(settings.patch_validation_timeout_seconds),
        checker,
    )
    captures = CaptureService(db, repo, flags, settings, evidence)
    rate_limiter = DistributedRateLimiter(db)
    engine = GameEngine(
        db, repo, flags, scoring, checker, runtime, evidence, settings,
        koth=koth,
    )
    return Components(
        settings, db, repo, evidence, koth, stealth, tournaments, flags, scoring, checker, runtime, patches,
        captures, rate_limiter, engine,
    )


def _public_service_summary(c: Components, match_id: str) -> dict:
    if not c.repo.get_match(match_id):
        raise KeyError(match_id)
    conn = c.db.connect()
    try:
        rows = [
            dict(row) for row in conn.execute(
                """SELECT s.id AS service_id,s.slug AS service,s.name,
                          COUNT(i.id) AS total,
                          SUM(CASE WHEN i.status='healthy' THEN 1 ELSE 0 END) AS healthy,
                          MAX(COALESCE(i.updated_at,0)) AS updated_at
                   FROM game_services s
                   LEFT JOIN team_service_instances i ON i.service_id=s.id
                   WHERE s.match_id=? AND s.enabled=1
                   GROUP BY s.id,s.slug,s.name ORDER BY s.slug""",
                (match_id,),
            )
        ]
    finally:
        conn.close()
    return {
        "services": [
            {
                **row,
                "degraded": int(row["total"]) - int(row["healthy"] or 0),
                "status": (
                    "healthy"
                    if int(row["total"]) > 0
                    and int(row["healthy"] or 0) == int(row["total"])
                    else "degraded"
                ),
            }
            for row in rows
        ],
        "disclosure": "aggregate-only",
    }


def _public_scoreboard(c: Components, match_id: str) -> dict:
    rows = c.scoring.scoreboard(match_id, public=True)
    current = c.repo.current_round(match_id)
    match = c.repo.get_match(match_id)
    match_config = json_load(match["config"]) if match else {}
    delay = int(match_config.get(
        "scoreboard_delay_rounds", c.settings.scoreboard_delay_rounds
    ))
    stealth = c.stealth.normalized_config(match_config.get("stealth", {}))
    if stealth["enabled"]:
        delay = max(delay, int(stealth["alert_delay_rounds"]))
    return {
        "view": "public", "delay_rounds": delay,
        "last_public_round": max(
            0, int(current["sequence"] if current else 0) - delay
        ),
        "provisional": bool(current and current["status"] != "finalized"),
        "scoreboard": rows,
    }


def create_app(components: Components | None = None) -> FastAPI:
    c = components or build_components()
    worker_thread: threading.Thread | None = None

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        nonlocal worker_thread
        # Recover ready tournament fixtures before ticking persisted running
        # Matches. Both paths use stable IDs and database locks, so a replica
        # restart cannot create a duplicate bracket Match.
        if c.settings.enabled:
            conn = c.db.connect()
            try:
                tournament_ids = [row[0] for row in conn.execute(
                    """SELECT id FROM tournaments
                       WHERE status IN ('seeded','running') ORDER BY created_at"""
                )]
            finally:
                conn.close()
            for tournament_id in tournament_ids:
                try:
                    with c.db.match_lock(
                        f"tournament:{tournament_id}",
                        c.engine.owner_id,
                        c.settings.engine_lock_seconds,
                    ) as acquired:
                        if acquired:
                            c.tournaments.reconcile(
                                tournament_id, "startup-recovery"
                            )
                except Exception as exc:
                    logger.exception(
                        "tournament recovery failed",
                        extra={"tournament_id": tournament_id},
                    )
                    c.evidence.record(AuditContext(
                        actor="startup-recovery",
                        event_type="tournament_recovery",
                        result="failed",
                        metadata={
                            "tournament_id": tournament_id,
                            "error_class": type(exc).__name__,
                        },
                        event_id=stable_id(
                            "audit", "tournament-recovery", tournament_id,
                            type(exc).__name__, int(time.time()),
                        ),
                    ))
        # Persisted running Matches resume through the idempotent tick engine.
        if c.settings.auto_engine and c.settings.enabled:
            worker_thread = threading.Thread(
                target=c.engine.run_forever, name="ad-game-engine", daemon=True
            )
            worker_thread.start()
        yield
        c.engine.stop()
        if worker_thread:
            worker_thread.join(timeout=2)

    app = FastAPI(title="Attack/Defense Live Fire API", version="0.1.0", lifespan=lifespan)
    app.state.components = c
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=(
            r"https?://(localhost|127\.0\.0\.1|(\d{1,3}\.){3}\d{1,3}|"
            r"[\w-]+\.ts\.net)(:\d+)?"
        ),
        allow_credentials=True, allow_methods=["GET", "POST"],
        allow_headers=[
            "Authorization", "Content-Type", "Last-Event-ID", "Idempotency-Key",
            "X-Operation-Reason", "X-Round-Id", "X-Service-Id",
        ],
        expose_headers=[
            "Content-Disposition", "Retry-After", "X-Capture-SHA256",
            "X-Capture-Watermark",
        ],
    )

    @app.middleware("http")
    async def payload_limit(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH"}:
            try:
                length = int(request.headers.get("content-length", "0"))
            except ValueError:
                length = 0
            is_capture_ingest = (
                request.method == "POST"
                and "/api/attack-defense/operator/matches/" in request.url.path
                and request.url.path.endswith("/captures")
            )
            maximum = (
                c.settings.pcap_max_upload_mb * 1024 * 1024
                if is_capture_ingest else 16_384
            )
            if length > maximum:
                return Response(status_code=413, content="payload too large")
        return await call_next(request)

    def operator(authorization: str = Header(default="")) -> Identity:
        return require_role(authorization, {"instructor", "operator"})

    def competitor(authorization: str = Header(default="")) -> Identity:
        ident = require_role(authorization, {"competitor", "red", "blue"})
        if ident.dev_mode and not c.settings.allow_insecure_dev_auth:
            raise HTTPException(401, "competitor authentication must be configured")
        if not ident.team_id and not ident.tournament_id:
            raise HTTPException(403, "team or tournament membership claim required")
        return ident

    def membership(match_id: str, ident: Identity) -> dict:
        if ident.match_id and ident.match_id != match_id:
            raise HTTPException(403, "match membership required")
        team = c.repo.get_team(ident.team_id)
        if not team or team["match_id"] != match_id or not team["enabled"]:
            raise HTTPException(403, "match membership required")
        return team

    def rate_limit(subject: str, action: str, seconds: int, maximum: int) -> None:
        decision = c.rate_limiter.consume(subject, action, seconds, maximum)
        if not decision.allowed:
            raise HTTPException(
                429, "rate limit exceeded",
                headers={"Retry-After": str(decision.retry_after_seconds)},
            )

    def server_now() -> float:
        conn = c.db.connect()
        try:
            return c.db.server_time(conn)
        finally:
            conn.close()

    @app.get("/health")
    def health():
        conn = c.db.connect()
        matches = conn.execute("SELECT COUNT(*) FROM matches").fetchone()[0]
        running = conn.execute("SELECT COUNT(*) FROM matches WHERE status='running'").fetchone()[0]
        conn.close()
        return {
            "service": "attack_defense", "enabled": c.settings.enabled,
            "matches": matches, "running_matches": running,
            "database_backend": c.db.backend_name,
        }

    @app.get("/ready")
    def readiness():
        try:
            database_time = server_now()
            skew = abs(time.time() - database_time)
        except Exception:
            return Response(
                status_code=503, media_type="application/json",
                content='{"ready":false,"reason":"database_unavailable"}',
            )
        ready = skew <= c.settings.max_database_clock_skew_seconds
        body = {
            "ready": ready, "database_backend": c.db.backend_name,
            "clock_skew_seconds": round(skew, 3),
        }
        if not ready:
            body["reason"] = "clock_skew_exceeded"
        return Response(
            status_code=200 if ready else 503,
            media_type="application/json", content=json.dumps(body),
        )

    @app.get("/metrics", response_class=PlainTextResponse)
    def metrics():
        return render_metrics(c.db)

    # ---- Operator match configuration and control -------------------------
    @app.post("/api/attack-defense/matches", status_code=201)
    def create_match(req: MatchCreateRequest, ident: Identity = Depends(operator)):
        try:
            return c.repo.create_match(
                req.name,
                req.round_duration_seconds or c.settings.round_duration_seconds,
                req.active_flag_window or c.settings.active_flag_window_rounds,
                {**req.config, "created_by": ident.actor},
                req.id,
                req.mode,
            )
        except Exception as exc:
            if type(exc).__name__ == "IntegrityError":
                raise HTTPException(409, "match already exists")
            if isinstance(exc, ValueError):
                raise HTTPException(400, str(exc))
            raise

    @app.get("/api/attack-defense/operator/matches")
    def operator_matches(_: Identity = Depends(operator)):
        return {"matches": c.repo.list_matches()}

    # ---- LiveCTF tournament orchestration --------------------------------
    @app.post("/api/attack-defense/operator/tournaments", status_code=201)
    def create_tournament(
        req: TournamentCreateRequest, ident: Identity = Depends(operator)
    ):
        try:
            return c.tournaments.create(
                name=req.name,
                bracket_size=req.bracket_size,
                match_mode=req.match_mode,
                round_duration_seconds=(
                    req.round_duration_seconds
                    or c.settings.round_duration_seconds
                ),
                active_flag_window=(
                    req.active_flag_window
                    or c.settings.active_flag_window_rounds
                ),
                match_config=req.match_config,
                actor=ident.actor,
                tournament_id=req.id,
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        except c.db.integrity_error:
            raise HTTPException(409, "tournament already exists")

    @app.get("/api/attack-defense/operator/tournaments")
    def list_tournaments(_: Identity = Depends(operator)):
        conn = c.db.connect()
        try:
            rows = [dict(row) for row in conn.execute(
                """SELECT id,name,format,status,match_mode,bracket_size,
                          current_stage,winner_entry_id,starts_at,completed_at,
                          created_at,updated_at
                   FROM tournaments ORDER BY created_at DESC"""
            )]
        finally:
            conn.close()
        return {"tournaments": rows}

    @app.get("/api/attack-defense/operator/tournaments/{tournament_id}")
    def operator_tournament(
        tournament_id: str, _: Identity = Depends(operator)
    ):
        try:
            return c.tournaments.state(tournament_id, operator=True)
        except KeyError:
            raise HTTPException(404, "tournament not found")

    @app.post(
        "/api/attack-defense/operator/tournaments/{tournament_id}/entries",
        status_code=201,
    )
    def register_tournament_entry(
        tournament_id: str,
        req: TournamentEntryCreateRequest,
        ident: Identity = Depends(operator),
    ):
        try:
            return c.tournaments.add_entry(
                tournament_id,
                slug=req.slug,
                name=req.name,
                identity_subject=req.identity_subject,
                seed=req.seed,
                actor=ident.actor,
                entry_id=req.id,
            )
        except KeyError:
            raise HTTPException(404, "tournament not found")
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        except c.db.integrity_error:
            raise HTTPException(409, "tournament entry already exists")

    @app.post(
        "/api/attack-defense/operator/tournaments/{tournament_id}/services",
        status_code=201,
    )
    def register_tournament_service(
        tournament_id: str,
        req: TournamentServiceCreateRequest,
        ident: Identity = Depends(operator),
    ):
        try:
            return c.tournaments.add_service(
                tournament_id,
                slug=req.slug,
                name=req.name,
                base_image=req.base_image,
                base_image_digest=req.base_image_digest,
                internal_port=req.internal_port,
                checker_type=req.checker_type,
                config=req.config,
                actor=ident.actor,
                service_id=req.id,
            )
        except KeyError:
            raise HTTPException(404, "tournament not found")
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        except c.db.integrity_error:
            raise HTTPException(409, "tournament service already exists")

    @app.post("/api/attack-defense/operator/tournaments/{tournament_id}/seed")
    def seed_tournament(
        tournament_id: str,
        req: ReasonRequest,
        ident: Identity = Depends(operator),
    ):
        try:
            with c.engine.exclusive_match(f"tournament:{tournament_id}"):
                return c.tournaments.seed(tournament_id, ident.actor, req.reason)
        except KeyError:
            raise HTTPException(404, "tournament not found")
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/attack-defense/operator/tournaments/{tournament_id}/start")
    def start_tournament(
        tournament_id: str,
        req: ReasonRequest,
        ident: Identity = Depends(operator),
    ):
        try:
            with c.engine.exclusive_match(f"tournament:{tournament_id}"):
                return c.tournaments.start(tournament_id, ident.actor, req.reason)
        except KeyError:
            raise HTTPException(404, "tournament not found")
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/attack-defense/operator/tournaments/{tournament_id}/reconcile")
    def reconcile_tournament(
        tournament_id: str,
        req: ReasonRequest,
        ident: Identity = Depends(operator),
    ):
        try:
            with c.engine.exclusive_match(f"tournament:{tournament_id}"):
                result = c.tournaments.reconcile(tournament_id, ident.actor)
                result["reason"] = req.reason
                return result
        except KeyError:
            raise HTTPException(404, "tournament not found")
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post(
        "/api/attack-defense/operator/tournaments/{tournament_id}"
        "/fixtures/{fixture_id}/start"
    )
    def start_tournament_fixture(
        tournament_id: str,
        fixture_id: str,
        req: ReasonRequest,
        ident: Identity = Depends(operator),
    ):
        try:
            with c.engine.exclusive_match(f"tournament:{tournament_id}"):
                fixture = c.tournaments.fixture(fixture_id, operator=True)
                if fixture["tournament_id"] != tournament_id:
                    raise KeyError(fixture_id)
                if fixture["status"] == "running":
                    return fixture
                match = c.repo.get_match(fixture["match_id"])
                if not match:
                    raise ValueError("fixture has no materialized Match")
                if match["status"] == "draft":
                    c.engine.start_match(match["id"], ident.actor)
                elif match["status"] != "running":
                    raise ValueError("fixture Match cannot start from current state")
                return c.tournaments.mark_fixture_running(
                    fixture_id, ident.actor, req.reason
                )
        except KeyError:
            raise HTTPException(404, "tournament fixture not found")
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post(
        "/api/attack-defense/operator/tournaments/{tournament_id}"
        "/fixtures/{fixture_id}/finalize"
    )
    def finalize_tournament_fixture(
        tournament_id: str,
        fixture_id: str,
        req: TournamentFixtureFinalizeRequest,
        ident: Identity = Depends(operator),
    ):
        try:
            with c.engine.exclusive_match(f"tournament:{tournament_id}"):
                fixture = c.tournaments.fixture(fixture_id, operator=True)
                if fixture["tournament_id"] != tournament_id:
                    raise KeyError(fixture_id)
                if fixture["status"] == "finalized":
                    return fixture
                if fixture["status"] != "running":
                    raise ValueError("only running fixtures can be finalized")
                match = c.repo.get_match(fixture["match_id"])
                if match and match["status"] in {"running", "paused"}:
                    c.engine.end_match(match["id"], ident.actor, req.reason)
                return c.tournaments.finalize_fixture(
                    fixture_id,
                    ident.actor,
                    req.reason,
                    req.winner_entry_id,
                )
        except KeyError:
            raise HTTPException(404, "tournament fixture not found")
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.get("/api/attack-defense/operator/ha/status")
    def ha_status(_: Identity = Depends(operator)):
        conn = c.db.connect()
        try:
            database_time = c.db.server_time(conn)
            migrations = [row[0] for row in conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            )]
            running = int(conn.execute(
                "SELECT COUNT(*) FROM matches WHERE status='running'"
            ).fetchone()[0])
        finally:
            conn.close()
        return {
            "database_backend": c.db.backend_name,
            "ha_capable": c.db.backend_name == "postgresql",
            "database_time": database_time,
            "clock_skew_seconds": round(abs(time.time() - database_time), 3),
            "running_matches": running, "migrations": migrations,
            "engine_owner": c.engine.owner_id,
        }

    @app.post("/api/attack-defense/matches/{match_id}/teams", status_code=201)
    def create_team(match_id: str, req: TeamCreateRequest, _: Identity = Depends(operator)):
        if not c.repo.get_match(match_id):
            raise HTTPException(404, "match not found")
        try:
            return c.repo.add_team(match_id, req.slug, req.name, req.id)
        except Exception as exc:
            if type(exc).__name__ == "IntegrityError":
                raise HTTPException(409, "team already exists")
            raise

    @app.post("/api/attack-defense/matches/{match_id}/services", status_code=201)
    def create_service(
        match_id: str, req: ServiceCreateRequest, _: Identity = Depends(operator)
    ):
        if not c.repo.get_match(match_id):
            raise HTTPException(404, "match not found")
        try:
            return c.repo.add_service(
                match_id, req.slug, req.name, req.base_image, req.internal_port,
                req.checker_type, req.config, req.base_image_digest, req.id,
            )
        except Exception as exc:
            if type(exc).__name__ == "IntegrityError":
                raise HTTPException(409, "service already exists")
            raise

    @app.post("/api/attack-defense/matches/{match_id}/start")
    def start_match(
        match_id: str, req: ReasonRequest, ident: Identity = Depends(operator)
    ):
        try:
            return c.engine.start_match(match_id, ident.actor)
        except KeyError:
            raise HTTPException(404, "match not found")
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/attack-defense/matches/{match_id}/pause")
    def pause_match(
        match_id: str, req: ReasonRequest, ident: Identity = Depends(operator)
    ):
        try:
            return c.engine.pause_match(match_id, ident.actor, req.reason)
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/attack-defense/matches/{match_id}/resume")
    def resume_match(
        match_id: str, req: ReasonRequest, ident: Identity = Depends(operator)
    ):
        try:
            return c.engine.resume_match(match_id, ident.actor, req.reason)
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/attack-defense/matches/{match_id}/end")
    def end_match(
        match_id: str, req: ReasonRequest, ident: Identity = Depends(operator)
    ):
        return c.engine.end_match(match_id, ident.actor, req.reason)

    @app.post("/api/attack-defense/matches/{match_id}/rounds/current/finalize")
    def finalize_round(match_id: str, ident: Identity = Depends(operator)):
        try:
            return c.engine.force_finalize(match_id, ident.actor)
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/attack-defense/matches/{match_id}/rounds/current/extend")
    def extend_round(
        match_id: str, req: ExtendRoundRequest, ident: Identity = Depends(operator)
    ):
        try:
            with c.engine.exclusive_match(match_id):
                current = c.repo.current_round(match_id)
                if not current or current["status"] != "active":
                    raise ValueError("active round required")
                with c.db.transaction(immediate=True) as conn:
                    conn.execute(
                        "UPDATE rounds SET ends_at=ends_at+? WHERE id=?",
                        (req.seconds, current["id"]),
                    )
                    conn.execute(
                        """UPDATE flags SET valid_until=valid_until+? WHERE match_id=?
                           AND status IN ('issued','injected','compromised')""",
                        (req.seconds, match_id),
                    )
                    c.evidence.record(
                        AuditContext(
                            actor=ident.actor, event_type="round_extended",
                            result="success",
                            correlation_id=current["correlation_id"],
                            match_id=match_id, round_id=current["id"],
                            metadata={
                                "seconds": req.seconds, "reason": req.reason,
                            },
                            event_id=stable_id(
                                "audit", "round-extend", current["id"],
                                req.seconds, req.reason,
                            ),
                        ),
                        conn,
                    )
                return c.repo.get_round(current["id"])
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/attack-defense/matches/{match_id}/rounds/current/tick")
    def tick_round(match_id: str, _: Identity = Depends(operator)):
        return c.engine.tick_match(match_id)

    @app.get("/api/attack-defense/matches/{match_id}/rounds/current")
    def current_round(match_id: str, _: Identity = Depends(operator)):
        row = c.repo.current_round(match_id)
        if not row:
            raise HTTPException(404, "round not found")
        return row

    @app.post("/api/attack-defense/matches/{match_id}/rounds/{round_id}/recalculate")
    def recalculate_round(
        match_id: str, round_id: str, ident: Identity = Depends(operator)
    ):
        row = c.repo.get_round(round_id)
        if not row or row["match_id"] != match_id:
            raise HTTPException(404, "round not found")
        try:
            with c.engine.exclusive_match(match_id):
                return c.scoring.calculate_round(round_id, ident.actor)
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/attack-defense/matches/{match_id}/score/recalculate")
    def recalculate_match(match_id: str, ident: Identity = Depends(operator)):
        try:
            with c.engine.exclusive_match(match_id):
                return c.scoring.recalculate_match(match_id, ident.actor)
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/attack-defense/matches/{match_id}/score/adjust")
    def adjust_score(
        match_id: str, req: AdjustmentRequest, ident: Identity = Depends(operator)
    ):
        team = c.repo.get_team(req.team_id)
        if not team or team["match_id"] != match_id:
            raise HTTPException(404, "team not found")
        return c.scoring.adjustment(
            match_id, req.team_id, req.delta, req.reason, ident.actor,
            req.service_id, req.round_id,
        )

    @app.get("/api/attack-defense/operator/matches/{match_id}/checks")
    def checker_results(
        match_id: str, limit: int = 500, _: Identity = Depends(operator)
    ):
        conn = c.db.connect()
        rows = [dict(r) for r in conn.execute(
            """SELECT * FROM service_checks WHERE match_id=?
               ORDER BY checked_at DESC LIMIT ?""", (match_id, min(max(limit, 1), 2000))
        )]
        conn.close()
        for row in rows:
            row["evidence"] = json_load(row["evidence"])
        return {"checks": rows}

    @app.get("/api/attack-defense/operator/matches/{match_id}/flags")
    def flag_operations(match_id: str, _: Identity = Depends(operator)):
        conn = c.db.connect()
        rows = [dict(r) for r in conn.execute(
            """SELECT id,match_id,round_id,team_id,service_id,status,valid_from,
               valid_until,injected_at,retrieved_at,created_at FROM flags
               WHERE match_id=? ORDER BY created_at DESC""", (match_id,)
        )]
        conn.close()
        return {"flags": rows}

    @app.get("/api/attack-defense/operator/matches/{match_id}/services")
    def operator_services(match_id: str, _: Identity = Depends(operator)):
        return {"services": c.repo.list_instances(match_id)}

    @app.post(
        "/api/attack-defense/operator/matches/{match_id}/teams/{team_id}"
        "/services/{service_id}/restart",
        status_code=202,
    )
    def restart_service(
        match_id: str, team_id: str, service_id: str, req: ReasonRequest,
        ident: Identity = Depends(operator),
    ):
        try:
            return c.patches.queue_instance_operation(
                match_id, team_id, service_id, "restart", ident.actor
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post(
        "/api/attack-defense/operator/matches/{match_id}/teams/{team_id}"
        "/services/{service_id}/rollback",
        status_code=202,
    )
    def rollback_service(
        match_id: str, team_id: str, service_id: str, req: ReasonRequest,
        ident: Identity = Depends(operator),
    ):
        try:
            return c.patches.queue_instance_operation(
                match_id, team_id, service_id, "rollback_instance", ident.actor
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post(
        "/api/attack-defense/operator/matches/{match_id}/services/{service_id}/enabled"
    )
    def enable_service(
        match_id: str, service_id: str, req: ServiceEnableRequest,
        ident: Identity = Depends(operator),
    ):
        service = c.repo.get_service(service_id)
        if not service or service["match_id"] != match_id:
            raise HTTPException(404, "service not found")
        with c.db.transaction(immediate=True) as conn:
            conn.execute(
                "UPDATE game_services SET enabled=? WHERE id=?",
                (1 if req.enabled else 0, service_id),
            )
            from .evidence import AuditContext
            c.evidence.record(
                AuditContext(
                    actor=ident.actor, event_type="service_enabled_changed",
                    result="enabled" if req.enabled else "disabled", match_id=match_id,
                    service_id=service_id, metadata={"reason": req.reason},
                    event_id=stable_id(
                        "audit", "service-enabled", service_id, req.enabled, req.reason
                    ),
                ),
                conn,
            )
        return {"service_id": service_id, "enabled": req.enabled}

    @app.post("/api/attack-defense/operator/matches/{match_id}/announcements")
    def announcement(
        match_id: str, req: AnnouncementRequest, ident: Identity = Depends(operator)
    ):
        from .evidence import AuditContext
        event_id = c.evidence.record(AuditContext(
            actor=ident.actor, event_type="operator_announcement", result="published",
            match_id=match_id,
            metadata={"message": req.message, "severity": req.severity, "reason": req.reason},
            event_id=stable_id(
                "audit", "announcement", match_id, req.message, req.severity
            ),
        ))
        return {"event_id": event_id, "published": True}

    @app.post(
        "/api/attack-defense/operator/matches/{match_id}/koth/configure"
    )
    def configure_koth(
        match_id: str,
        req: KothConfigureRequest,
        ident: Identity = Depends(operator),
    ):
        try:
            with c.engine.exclusive_match(match_id):
                return c.koth.configure(
                    match_id,
                    enabled=req.enabled,
                    service_ids=req.service_ids,
                    lease_rounds=(
                        req.lease_rounds
                        if req.lease_rounds is not None
                        else c.settings.koth_default_lease_rounds
                    ),
                    points_per_round=(
                        req.points_per_round
                        if req.points_per_round is not None
                        else c.settings.koth_default_points_per_round
                    ),
                    score_weight=req.score_weight,
                    actor=ident.actor,
                    reason=req.reason,
                )
        except KeyError:
            raise HTTPException(404, "match not found")
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.get("/api/attack-defense/operator/matches/{match_id}/koth")
    def operator_koth_state(
        match_id: str, _: Identity = Depends(operator)
    ):
        try:
            return c.koth.state(match_id, operator=True)
        except KeyError:
            raise HTTPException(404, "match not found")

    @app.post(
        "/api/attack-defense/operator/matches/{match_id}/stealth/configure"
    )
    def configure_stealth(
        match_id: str,
        req: StealthConfigureRequest,
        ident: Identity = Depends(operator),
    ):
        try:
            with c.engine.exclusive_match(match_id):
                delay = (
                    req.alert_delay_rounds
                    if req.alert_delay_rounds is not None
                    else c.settings.stealth_alert_delay_rounds
                )
                window = (
                    req.detection_window_rounds
                    if req.detection_window_rounds is not None
                    else c.settings.stealth_detection_window_rounds
                )
                return c.stealth.configure(
                    match_id,
                    enabled=req.enabled,
                    alert_delay_rounds=delay,
                    detection_window_rounds=window,
                    attacker_undetected_points=(
                        req.attacker_undetected_points
                        if req.attacker_undetected_points is not None
                        else c.settings.stealth_attacker_undetected_points
                    ),
                    defender_detection_points=(
                        req.defender_detection_points
                        if req.defender_detection_points is not None
                        else c.settings.stealth_defender_detection_points
                    ),
                    attack_score_weight=req.attack_score_weight,
                    detection_score_weight=req.detection_score_weight,
                    actor=ident.actor,
                    reason=req.reason,
                )
        except KeyError:
            raise HTTPException(404, "match not found")
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.get("/api/attack-defense/operator/matches/{match_id}/stealth")
    def operator_stealth_state(
        match_id: str, _: Identity = Depends(operator)
    ):
        try:
            return c.stealth.state(match_id, operator=True)
        except KeyError:
            raise HTTPException(404, "match not found")

    @app.post("/api/attack-defense/internal/matches/{match_id}/score-events")
    def ingest_hybrid_score_event(
        match_id: str, req: ScoreEventRequest, ident: Identity = Depends(operator)
    ):
        match = c.repo.get_match(match_id)
        team = c.repo.get_team(req.team_id)
        if not match or not team or team["match_id"] != match_id:
            raise HTTPException(404, "match or team not found")
        config = json_load(match["config"])
        if req.score_type not in set(config.get("score_categories") or []):
            raise HTTPException(409, "score category is disabled for this match")
        if match["mode"] == "attack_defense" and req.score_type in {
            "detection", "containment", "recovery", "incident_response", "mission_inject",
        }:
            raise HTTPException(409, "exercise score category is not valid in attack_defense mode")
        with c.db.transaction(immediate=True) as conn:
            inserted = c.repo.insert_ledger(
                conn, event_id=req.event_id, match_id=match_id,
                round_id=req.round_id, team_id=req.team_id, service_id=req.service_id,
                score_type=req.score_type, delta=req.delta, reason=req.reason,
                evidence=req.evidence, metadata=req.metadata,
            )
            from .evidence import AuditContext
            c.evidence.record(
                AuditContext(
                    actor=ident.actor, event_type="hybrid_score_event",
                    result="recorded" if inserted else "duplicate",
                    team_id=req.team_id, match_id=match_id, round_id=req.round_id,
                    service_id=req.service_id,
                    metadata={"source_event_id": req.event_id, "score_type": req.score_type},
                    event_id=stable_id("audit", "hybrid-score", req.event_id),
                ),
                conn,
            )
        return {"recorded": inserted, "event_id": req.event_id}

    @app.get("/api/attack-defense/operator/matches/{match_id}/patches")
    def operator_patches(match_id: str, _: Identity = Depends(operator)):
        conn = c.db.connect()
        rows = [dict(r) for r in conn.execute(
            """SELECT * FROM patch_submissions WHERE match_id=?
               ORDER BY submitted_at DESC""", (match_id,)
        )]
        conn.close()
        return {"patches": rows}

    @app.get("/api/attack-defense/operator/matches/{match_id}/audit")
    def audit_events(
        match_id: str, limit: int = 500, _: Identity = Depends(operator)
    ):
        conn = c.db.connect()
        rows = [dict(r) for r in conn.execute(
            """SELECT * FROM audit_events WHERE match_id=?
               ORDER BY timestamp DESC LIMIT ?""", (match_id, min(max(limit, 1), 2000))
        )]
        conn.close()
        for row in rows:
            row["metadata"] = json_load(row["metadata"])
        return {"events": rows}

    # ---- Sanitized PCAP evidence -----------------------------------------
    @app.post(
        "/api/attack-defense/operator/matches/{match_id}/captures",
        status_code=201,
    )
    async def ingest_capture(
        request: Request,
        match_id: str,
        operation_reason: str = Header(
            min_length=3, max_length=500, alias="X-Operation-Reason"
        ),
        round_id: str | None = Header(
            default=None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$",
            alias="X-Round-Id",
        ),
        service_id: str | None = Header(
            default=None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$",
            alias="X-Service-Id",
        ),
        ident: Identity = Depends(operator),
    ):
        media_type = request.headers.get("content-type", "").split(";", 1)[0].strip()
        if media_type not in {
            "application/vnd.tcpdump.pcap", "application/octet-stream",
        }:
            raise HTTPException(415, "classic pcap content type required")
        maximum = c.settings.pcap_max_upload_mb * 1024 * 1024
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > maximum:
                raise HTTPException(413, "capture exceeds upload policy")
        if not body:
            raise HTTPException(400, "capture body is empty")
        try:
            return await asyncio.to_thread(
                c.captures.ingest,
                match_id, bytes(body), ident.actor, operation_reason,
                round_id=round_id, service_id=service_id,
            )
        except KeyError:
            raise HTTPException(404, "match not found")
        except PcapPrivacyError as exc:
            from .evidence import AuditContext
            c.evidence.record(AuditContext(
                actor=ident.actor, event_type="capture_ingest", result="rejected",
                match_id=match_id, round_id=round_id, service_id=service_id,
                metadata={
                    "reason": operation_reason,
                    "error_class": type(exc).__name__,
                },
                event_id=stable_id(
                    "audit", "capture-rejected", match_id, ident.actor,
                    time.time_ns(),
                ),
            ))
            raise HTTPException(400, "capture failed privacy validation")

    @app.get("/api/attack-defense/operator/matches/{match_id}/captures")
    def operator_captures(match_id: str, _: Identity = Depends(operator)):
        if not c.repo.get_match(match_id):
            raise HTTPException(404, "match not found")
        return {"captures": c.captures.list(match_id, operator=True)}

    # ---- Participant/public views -----------------------------------------
    @app.get("/api/attack-defense/public/tournaments/{tournament_id}")
    def public_tournament(tournament_id: str):
        try:
            return c.tournaments.state(tournament_id, operator=False)
        except KeyError:
            raise HTTPException(404, "tournament not found")

    @app.get("/api/attack-defense/tournaments/{tournament_id}")
    def participant_tournament(
        tournament_id: str, ident: Identity = Depends(competitor)
    ):
        entry = c.tournaments.resolve_entry(
            tournament_id,
            actor=ident.actor,
            tournament_claim=ident.tournament_id,
            match_id=ident.match_id,
            team_id=ident.team_id,
        )
        if not entry:
            raise HTTPException(403, "tournament membership required")
        try:
            return c.tournaments.participant_state(tournament_id, entry["id"])
        except KeyError:
            raise HTTPException(404, "tournament not found")

    @app.get("/api/attack-defense/public/matches/{match_id}/state")
    def public_match_state(match_id: str):
        match = c.repo.get_match(match_id)
        if not match:
            raise HTTPException(404, "match not found")
        round_row = c.repo.current_round(match_id)
        config = json_load(match["config"])
        return {
            "id": match["id"], "name": match["name"], "mode": match["mode"],
            "status": match["status"], "starts_at": match["starts_at"],
            "round": round_row["sequence"] if round_row else 0,
            "round_status": round_row["status"] if round_row else None,
            "round_ends_at": round_row["ends_at"] if round_row else None,
            "server_time": server_now(),
            "tournament_id": config.get("tournament_id"),
            "tournament_fixture_id": config.get("tournament_fixture_id"),
        }

    @app.get("/api/attack-defense/matches/{match_id}/state")
    def match_state(match_id: str, ident: Identity = Depends(competitor)):
        team = membership(match_id, ident)
        match = c.repo.get_match(match_id)
        if not match:
            raise HTTPException(404, "match not found")
        round_row = c.repo.current_round(match_id)
        config = json_load(match["config"])
        return {
            "id": match["id"], "name": match["name"], "mode": match["mode"],
            "status": match["status"], "starts_at": match["starts_at"],
            "round": round_row["sequence"] if round_row else 0,
            "round_status": round_row["status"] if round_row else None,
            "round_ends_at": round_row["ends_at"] if round_row else None,
            "server_time": server_now(),
            "team": {"id": team["id"], "name": team["name"]},
            "tournament_id": config.get("tournament_id"),
            "tournament_fixture_id": config.get("tournament_fixture_id"),
        }

    @app.get("/api/attack-defense/matches/{match_id}/services/me")
    def own_services(match_id: str, ident: Identity = Depends(competitor)):
        membership(match_id, ident)
        rows = c.repo.list_instances(match_id, ident.team_id)
        return {"services": [_participant_instance(r) for r in rows]}

    @app.get("/api/attack-defense/matches/{match_id}/attack-surface")
    def attack_surface(match_id: str, ident: Identity = Depends(competitor)):
        membership(match_id, ident)
        teams = [
            {"id": t["id"], "name": t["name"], "slug": t["slug"]}
            for t in c.repo.list_teams(match_id) if t["id"] != ident.team_id
        ]
        services = [
            {"id": s["id"], "name": s["name"], "slug": s["slug"]}
            for s in c.repo.list_services(match_id)
        ]
        return {"teams": teams, "services": services, "disclosure": "public-connectivity-only"}

    @app.get("/api/attack-defense/public/matches/{match_id}/service-summary")
    def public_service_summary(match_id: str):
        try:
            return _public_service_summary(c, match_id)
        except KeyError:
            raise HTTPException(404, "match not found")

    @app.get("/api/attack-defense/matches/{match_id}/services/{service_id}/docs")
    def service_docs(
        match_id: str, service_id: str, ident: Identity = Depends(competitor)
    ):
        membership(match_id, ident)
        service = c.repo.get_service(service_id)
        if not service or service["match_id"] != match_id:
            raise HTTPException(404, "service not found")
        return {
            "id": service["id"], "name": service["name"],
            "slug": service["slug"], "protocol": "ad-http-v1",
            "normal_workflow": (
                ["register", "login", "create_note", "read_note"]
                if service["checker_type"] == "vulnerable_notes"
                else ["register", "login", "upload_file", "download_file"]
            ),
            "patch_contract": "normal workflow and management flag put/get must remain functional",
        }

    @app.post("/api/attack-defense/matches/{match_id}/flags/submit")
    def submit_flag(
        match_id: str, req: FlagSubmitRequest, ident: Identity = Depends(competitor)
    ):
        membership(match_id, ident)
        rate_limit(
            ident.team_id, "flag_submit", 60,
            c.settings.max_flag_submissions_per_minute,
        )
        result = c.flags.validate_submission(match_id, ident.team_id, req.flag, ident.actor)
        if result.accepted:
            return {
                "accepted": True, "status": "accepted",
                "score_delta": result.score_delta,
            }
        return {
            "accepted": False, "status": "rejected",
            "reason": "invalid_or_inactive",
        }

    @app.post(
        "/api/attack-defense/matches/{match_id}/stealth/detections",
        status_code=202,
    )
    def submit_stealth_detection(
        match_id: str,
        req: StealthDetectionReportRequest,
        ident: Identity = Depends(competitor),
        idempotency_key: str = Header(default="", alias="Idempotency-Key"),
    ):
        membership(match_id, ident)
        if not idempotency_key or len(idempotency_key) > 128:
            raise HTTPException(400, "valid Idempotency-Key is required")
        rate_limit(
            ident.team_id,
            "stealth_detection_report",
            60,
            c.settings.max_stealth_reports_per_minute,
        )
        try:
            return c.stealth.report_detection(
                match_id,
                ident.team_id,
                req.service_id,
                req.indicator_hash,
                req.evidence_summary,
                idempotency_key,
                ident.actor,
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.get("/api/attack-defense/matches/{match_id}/stealth")
    def own_stealth_state(
        match_id: str, ident: Identity = Depends(competitor)
    ):
        membership(match_id, ident)
        try:
            return c.stealth.state(match_id, team_id=ident.team_id)
        except KeyError:
            raise HTTPException(404, "match not found")

    @app.post(
        "/api/attack-defense/matches/{match_id}/services/{service_id}/patches",
        status_code=202,
    )
    def submit_patch(
        match_id: str, service_id: str, req: PatchSubmitRequest,
        background_tasks: BackgroundTasks,
        ident: Identity = Depends(competitor),
    ):
        membership(match_id, ident)
        rate_limit(
            ident.team_id, "patch_submit", 3600,
            c.settings.max_patch_submissions_per_hour,
        )
        try:
            patch = c.patches.submit(
                match_id, ident.team_id, service_id, req.image_reference, ident.actor
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc))
        # Manifest inspection is network-bound, so the 202 response is returned
        # first. The durable sandbox/deploy stages are emitted as runtime_jobs
        # and executed only by the trusted host runner.
        background_tasks.add_task(
            c.patches.inspect_and_queue, patch["id"], "patch_pipeline"
        )
        return _participant_patch(patch)

    @app.get("/api/attack-defense/matches/{match_id}/patches")
    def own_patches(match_id: str, ident: Identity = Depends(competitor)):
        membership(match_id, ident)
        conn = c.db.connect()
        rows = [dict(r) for r in conn.execute(
            """SELECT * FROM patch_submissions WHERE match_id=? AND team_id=?
               ORDER BY submitted_at DESC""", (match_id, ident.team_id)
        )]
        conn.close()
        return {"patches": [_participant_patch(r) for r in rows]}

    @app.get("/api/attack-defense/matches/{match_id}/patches/{patch_id}")
    def own_patch(
        match_id: str, patch_id: str, ident: Identity = Depends(competitor)
    ):
        membership(match_id, ident)
        patch = c.patches.get(patch_id)
        if not patch or patch["match_id"] != match_id or patch["team_id"] != ident.team_id:
            raise HTTPException(404, "patch not found")
        return _participant_patch(patch)

    @app.get("/api/attack-defense/matches/{match_id}/availability/me")
    def own_availability(match_id: str, ident: Identity = Depends(competitor)):
        membership(match_id, ident)
        current = c.repo.current_round(match_id)
        conn = c.db.connect()
        rows = [dict(r) for r in conn.execute(
            """SELECT service_id,
               SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) successful,
               SUM(CASE WHEN status!='checker_system_error' THEN 1 ELSE 0 END) eligible,
               MAX(checked_at) last_checked_at
               FROM service_checks WHERE match_id=? AND team_id=? AND round_id=?
               GROUP BY service_id""",
            (match_id, ident.team_id, current["id"] if current else ""),
        )]
        conn.close()
        return {"round": current["sequence"] if current else 0, "services": rows}

    @app.get("/api/attack-defense/matches/{match_id}/captures")
    def available_captures(match_id: str, ident: Identity = Depends(competitor)):
        membership(match_id, ident)
        return {
            "captures": c.captures.list(match_id, operator=False),
            "disclosure": "sanitized-delayed-team-watermarked",
        }

    @app.get(
        "/api/attack-defense/matches/{match_id}/captures/{capture_id}/download"
    )
    def download_capture(
        match_id: str, capture_id: str,
        ident: Identity = Depends(competitor),
    ):
        membership(match_id, ident)
        rate_limit(
            ident.team_id, "capture_download", 60,
            c.settings.pcap_max_downloads_per_minute,
        )
        try:
            artifact = c.captures.download(
                match_id, capture_id, ident.team_id, ident.actor
            )
        except KeyError:
            raise HTTPException(404, "capture not found")
        except CaptureNotReleased as exc:
            raise HTTPException(
                425, "capture is not available yet",
                headers={"Retry-After": str(exc.retry_after)},
            )
        except CaptureIntegrityError:
            from .evidence import AuditContext
            c.evidence.record(AuditContext(
                actor=ident.actor, event_type="capture_download", result="failed",
                team_id=ident.team_id, match_id=match_id,
                metadata={"capture_id": capture_id, "error": "integrity_failure"},
                event_id=stable_id(
                    "audit", "capture-integrity", capture_id,
                    ident.team_id, time.time_ns(),
                ),
            ))
            raise HTTPException(503, "capture is temporarily unavailable")
        return Response(
            content=artifact.data,
            media_type="application/vnd.tcpdump.pcap",
            headers={
                "Content-Disposition": f'attachment; filename="{artifact.filename}"',
                "Cache-Control": "private, no-store",
                "X-Content-Type-Options": "nosniff",
                "X-Capture-Watermark": artifact.watermark,
                "X-Capture-SHA256": artifact.sha256,
            },
        )

    @app.get("/api/attack-defense/matches/{match_id}/scoreboard")
    def public_scoreboard(match_id: str):
        try:
            return _public_scoreboard(c, match_id)
        except KeyError:
            raise HTTPException(404, "match not found")

    @app.get("/api/attack-defense/public/matches/{match_id}/broadcast")
    def public_broadcast_snapshot(match_id: str, response: Response):
        """Return one explicitly public, broadcast-safe graphics snapshot."""
        match = c.repo.get_match(match_id)
        if not match:
            raise HTTPException(404, "match not found")
        try:
            scoreboard = _public_scoreboard(c, match_id)
            services = _public_service_summary(c, match_id)
        except KeyError:
            raise HTTPException(404, "match not found")
        current = c.repo.current_round(match_id)
        match_config = json_load(match["config"])
        tournament_id = match_config.get("tournament_id")
        tournament = None
        if tournament_id:
            try:
                tournament = c.tournaments.state(tournament_id, operator=False)
            except KeyError:
                tournament = None
        generated_at = server_now()
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Robots-Tag"] = "noindex, nofollow"
        return {
            "schema_version": "broadcast-overlay.v1",
            "generated_at": generated_at,
            "refresh_after_seconds": 5,
            "match": {
                "id": match["id"], "name": match["name"],
                "mode": match["mode"], "status": match["status"],
                "starts_at": match["starts_at"],
                "round": current["sequence"] if current else 0,
                "round_status": current["status"] if current else None,
                "round_ends_at": current["ends_at"] if current else None,
                "server_time": generated_at,
                "tournament_id": tournament_id,
            },
            "scoreboard": scoreboard,
            "services": services["services"],
            "tournament": tournament,
            "disclosure": {
                "audience": "public-broadcast",
                "scoreboard": "delayed-public-projection",
                "scoreboard_delay_rounds": scoreboard["delay_rounds"],
                "last_public_round": scoreboard["last_public_round"],
                "services": services["disclosure"],
                "events_included": False,
                "sensitive_fields_included": False,
            },
        }

    @app.get("/api/attack-defense/matches/{match_id}/koth")
    def public_koth_state(match_id: str):
        try:
            return c.koth.state(match_id, operator=False)
        except KeyError:
            raise HTTPException(404, "match not found")

    @app.get("/api/attack-defense/public/matches/{match_id}/stealth/summary")
    def public_stealth_summary(match_id: str):
        try:
            return c.stealth.state(match_id, observer=True)
        except KeyError:
            raise HTTPException(404, "match not found")

    @app.get("/api/attack-defense/operator/matches/{match_id}/scoreboard")
    def realtime_scoreboard(match_id: str, _: Identity = Depends(operator)):
        try:
            return {"view": "operator", "scoreboard": c.scoring.scoreboard(match_id, public=False)}
        except KeyError:
            raise HTTPException(404, "match not found")

    # ---- Patch/runtime worker boundary ------------------------------------
    @app.post("/api/attack-defense/operator/patches/{patch_id}/validate")
    def validate_patch(patch_id: str, ident: Identity = Depends(operator)):
        try:
            return c.patches.inspect_and_queue(patch_id, ident.actor)
        except KeyError:
            raise HTTPException(404, "patch not found")
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/attack-defense/operator/runtime/jobs/claim")
    def claim_runtime_job(
        runner_id: str = Header(alias="X-Runner-Id"),
        _: Identity = Depends(operator),
    ):
        job = c.patches.claim_job(runner_id[:80])
        return {"job": job}

    @app.post("/api/attack-defense/operator/runtime/jobs/{job_id}/complete")
    def complete_runtime_job(
        job_id: str, req: RuntimeCompleteRequest, ident: Identity = Depends(operator)
    ):
        try:
            return c.patches.complete_job(
                job_id, req.success, req.result, ident.actor, req.claim_token
            )
        except ValueError as exc:
            raise HTTPException(409, str(exc))

    @app.post(
        "/api/attack-defense/operator/matches/{match_id}/instances/{instance_id}"
        "/runtime-result"
    )
    def record_runtime_result(
        match_id: str, instance_id: str, req: RuntimeInstanceResultRequest,
        ident: Identity = Depends(operator),
    ):
        instance = next(
            (
                row for row in c.repo.list_instances(match_id)
                if row["id"] == instance_id
            ),
            None,
        )
        if not instance:
            raise HTTPException(404, "service instance not found")
        if c.settings.game_runtime == "kubernetes":
            endpoints = [value for value in (
                req.endpoint, req.management_endpoint
            ) if value]
            if req.success and len(endpoints) != 2:
                raise HTTPException(
                    400, "successful Kubernetes result requires both endpoints"
                )
            if any(not urlsplit(value).hostname.endswith(".svc") for value in endpoints):
                raise HTTPException(400, "Kubernetes endpoints must use cluster DNS")
        with c.db.transaction(immediate=True) as conn:
            now = c.db.server_time(conn)
            conn.execute(
                """UPDATE team_service_instances
                   SET runtime_id=?,status=?,
                       endpoint=CASE WHEN ? THEN COALESCE(?,endpoint) ELSE endpoint END,
                       management_endpoint=CASE WHEN ? THEN COALESCE(?,management_endpoint)
                         ELSE management_endpoint END,
                       image_digest=CASE WHEN ? THEN COALESCE(?,image_digest)
                         ELSE image_digest END,
                       deployed_at=CASE WHEN ? THEN COALESCE(deployed_at,?) ELSE deployed_at END,
                       updated_at=? WHERE id=? AND match_id=?""",
                (
                    req.runtime_id, "healthy" if req.success else "degraded",
                    req.success, req.endpoint, req.success,
                    req.management_endpoint, req.success, req.image_digest,
                    req.success, now, now, instance_id, match_id,
                ),
            )
            c.evidence.record(AuditContext(
                actor=ident.actor, event_type="runtime_reconcile",
                result="success" if req.success else "failed",
                team_id=instance["team_id"], match_id=match_id,
                service_id=instance["service_id"],
                metadata={
                    "instance_id": instance_id, "reason": req.reason,
                    "error_code": req.error_code,
                },
                event_id=stable_id(
                    "audit", "runtime-reconcile", instance_id,
                    time.time_ns(), req.success,
                ),
            ), conn)
        return {
            "recorded": True, "instance_id": instance_id,
            "status": "healthy" if req.success else "degraded",
        }

    # ---- Sanitized real-time feed -----------------------------------------
    @app.get("/api/attack-defense/matches/{match_id}/events/stream")
    async def event_stream(
        request: Request, match_id: str,
        authorization: str = Header(default=""),
        last_event_id: str = Header(default="0", alias="Last-Event-ID"),
    ):
        ident: Identity | None = None
        if authorization:
            try:
                ident = authenticate(authorization)
            except HTTPException:
                raise
        try:
            cursor = max(0, int(last_event_id or "0"))
        except ValueError:
            cursor = 0

        async def frames():
            nonlocal cursor
            yield "retry: 2000\n\n"
            while not await request.is_disconnected():
                conn = c.db.connect()
                rows = conn.execute(
                    """SELECT s.sequence AS stream_sequence,a.*,
                              m.config AS match_config
                       FROM audit_event_stream s
                       JOIN audit_events a ON a.event_id=s.event_id
                       JOIN matches m ON m.id=a.match_id
                       WHERE a.match_id=? AND s.sequence>?
                       ORDER BY s.sequence LIMIT 100""", (match_id, cursor)
                ).fetchall()
                conn.close()
                if not rows:
                    yield ": keepalive\n\n"
                    await asyncio.sleep(2)
                    continue
                for row in rows:
                    cursor = int(row["stream_sequence"])
                    event = _public_event(dict(row), ident)
                    if event is None:
                        continue
                    yield (
                        f"id: {cursor}\nevent: {event['category']}\n"
                        f"data: {json.dumps(event, separators=(',', ':'))}\n\n"
                    )
                await asyncio.sleep(0)

        return StreamingResponse(
            frames(), media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return app


def _participant_instance(row: dict) -> dict:
    return {
        "id": row["id"], "service_id": row["service_id"],
        "service": row["service_slug"], "status": row["status"],
        "image_digest": row["image_digest"], "last_health_at": row["last_health_at"],
        "deployed_at": row["deployed_at"], "updated_at": row["updated_at"],
    }


def _participant_patch(row: dict) -> dict:
    validation = json_load(row.get("validation_result"))
    public_validation = {
        k: v for k, v in validation.items()
        if k in {"stage", "category", "violations", "put_flag", "checks", "completed"}
    }
    return {
        "id": row["id"], "match_id": row["match_id"],
        "service_id": row["service_id"], "image_reference": row["image_reference"],
        "image_digest": row["image_digest"], "status": row["status"],
        "validation_result": public_validation,
        "submitted_at": row["submitted_at"], "validated_at": row["validated_at"],
        "deployed_at": row["deployed_at"],
    }


PUBLIC_EVENT_TYPES = {
    "match_started", "match_paused", "match_resumed", "match_ended",
    "round_transition", "patch_submission", "patch_validation",
    "patch_deploy", "patch_rollback", "operator_adjustment",
    "operator_announcement", "round_extended",
    "koth_ownership", "koth_configuration", "stealth_configuration",
}


def _public_event(row: dict, ident: Identity | None) -> dict | None:
    operator_view = bool(ident and ident.role in {"instructor", "operator"})
    own_team = bool(ident and ident.team_id and ident.team_id == row.get("team_id"))
    match_config = json_load(row.get("match_config"))
    stealth = match_config.get("stealth", {})
    stealth_enabled = isinstance(stealth, dict) and stealth.get("enabled") is True
    if not operator_view and row["event_type"] == "stealth_incident":
        return None
    if not operator_view and stealth_enabled and row["event_type"] == "koth_ownership":
        # The delayed KOTH state endpoint is the authoritative release path.
        # Suppressing this immediate event avoids creating a victim/service
        # timing oracle and does not alter flag acceptance semantics.
        return None
    if not operator_view and row["event_type"] not in PUBLIC_EVENT_TYPES and not own_team:
        return None
    category = (
        "patch" if "patch" in row["event_type"] else
        "attack" if row["event_type"] == "koth_ownership" else
        "score" if "score" in row["event_type"] or "adjustment" in row["event_type"] else
        "service" if row["event_type"] in {"service_check", "flag_injection"} else
        "system"
    )
    event = {
        "event_id": row["event_id"], "category": category,
        "type": row["event_type"], "result": row["result"],
        "timestamp": row["timestamp"],
    }
    if operator_view:
        event.update({
            "team_id": row.get("team_id"), "round_id": row.get("round_id"),
            "service_id": row.get("service_id"), "metadata": json_load(row.get("metadata")),
        })
    elif row["event_type"] == "koth_ownership":
        metadata = json_load(row.get("metadata"))
        event.update({
            "team_id": row.get("team_id"),
            "service_id": row.get("service_id"),
            "metadata": {
                key: metadata.get(key) for key in (
                    "hill_id", "victim_team_id", "previous_owner_team_id",
                    "expires_after_round",
                )
            },
        })
    elif own_team:
        event["scope"] = "own_team"
    return event
