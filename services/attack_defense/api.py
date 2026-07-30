from __future__ import annotations

import asyncio
import json
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

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
from .evidence import EvidenceRecorder
from .flag_service import FlagService
from .game_engine import GameEngine
from .metrics import render_metrics
from .patch_pipeline import HttpRegistryInspector, PatchPipeline, RegistryInspector
from .repositories import AttackDefenseRepository
from .pcap_privacy import sanitize_capture
from .schemas import (
    AnnouncementRequest,
    AdjustmentRequest,
    CaptureSanitizeRequest,
    ExtendRoundRequest,
    FlagSubmitRequest,
    MatchCreateRequest,
    PatchSubmitRequest,
    ReasonRequest,
    RuntimeCompleteRequest,
    ScoreEventRequest,
    ServiceEnableRequest,
    ServiceCreateRequest,
    TeamCreateRequest,
)
from .scoring import ScoringService
from .service_fabric import DeclaredComposeRuntime, ServiceRuntime
from .utils import canonical_json, json_load, stable_id


@dataclass
class Components:
    settings: AttackDefenseSettings
    db: Database
    repo: AttackDefenseRepository
    evidence: EvidenceRecorder
    flags: FlagService
    scoring: ScoringService
    checker: HttpWorkflowChecker
    runtime: ServiceRuntime
    patches: PatchPipeline
    engine: GameEngine


def build_components(
    settings: AttackDefenseSettings | None = None,
    *,
    runtime: ServiceRuntime | None = None,
    inspector: RegistryInspector | None = None,
) -> Components:
    settings = settings or AttackDefenseSettings.from_env()
    settings.validate()
    db = Database(settings.database_path)
    db.migrate()
    repo = AttackDefenseRepository(db)
    evidence = EvidenceRecorder(db)
    flags = FlagService(db, repo, settings, evidence)
    scoring = ScoringService(db, repo, settings, evidence)
    injector = HttpFlagInjector(settings)
    checker = HttpWorkflowChecker(settings, injector)
    if runtime is None:
        if settings.game_runtime == "kubernetes":
            from .k8s_runtime import KubernetesRuntime
            runtime = KubernetesRuntime(settings.allowed_registry, dry_run=True)
        else:
            runtime = DeclaredComposeRuntime()
    patches = PatchPipeline(
        db, repo, settings, evidence,
        inspector or HttpRegistryInspector(settings.patch_validation_timeout_seconds),
        checker,
    )
    engine = GameEngine(
        db, repo, flags, scoring, checker, runtime, evidence, settings
    )
    return Components(
        settings, db, repo, evidence, flags, scoring, checker, runtime, patches, engine
    )


def create_app(components: Components | None = None) -> FastAPI:
    c = components or build_components()
    worker_thread: threading.Thread | None = None

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        nonlocal worker_thread
        # Recovering consists of ticking persisted running matches. Every stage
        # is idempotent, so no separate volatile recovery state is needed.
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
        allow_headers=["Authorization", "Content-Type", "Last-Event-ID", "Idempotency-Key"],
    )

    @app.middleware("http")
    async def payload_limit(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH"}:
            try:
                length = int(request.headers.get("content-length", "0"))
            except ValueError:
                length = 0
            if length > 16_384:
                return Response(status_code=413, content="payload too large")
        return await call_next(request)

    def operator(authorization: str = Header(default="")) -> Identity:
        return require_role(authorization, {"instructor", "operator"})

    def competitor(authorization: str = Header(default="")) -> Identity:
        ident = require_role(authorization, {"competitor", "red", "blue"})
        if ident.dev_mode and not c.settings.allow_insecure_dev_auth:
            raise HTTPException(401, "competitor authentication must be configured")
        if not ident.team_id:
            raise HTTPException(403, "team membership claim required")
        return ident

    def membership(match_id: str, ident: Identity) -> dict:
        if ident.match_id and ident.match_id != match_id:
            raise HTTPException(403, "match membership required")
        team = c.repo.get_team(ident.team_id)
        if not team or team["match_id"] != match_id or not team["enabled"]:
            raise HTTPException(403, "match membership required")
        return team

    def rate_limit(subject: str, action: str, seconds: int, maximum: int) -> None:
        with c.db.transaction(immediate=True) as conn:
            now = c.db.server_time(conn)
            bucket = int(now // seconds)
            conn.execute(
                """INSERT INTO rate_limits(subject_key,action,window_start,count)
                   VALUES(?,?,?,1) ON CONFLICT(subject_key,action,window_start)
                   DO UPDATE SET count=count+1""",
                (subject, action, bucket),
            )
            count = conn.execute(
                """SELECT count FROM rate_limits
                   WHERE subject_key=? AND action=? AND window_start=?""",
                (subject, action, bucket),
            ).fetchone()[0]
        if count > maximum:
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(seconds)})

    @app.get("/health")
    def health():
        conn = c.db.connect()
        matches = conn.execute("SELECT COUNT(*) FROM matches").fetchone()[0]
        running = conn.execute("SELECT COUNT(*) FROM matches WHERE status='running'").fetchone()[0]
        conn.close()
        return {
            "service": "attack_defense", "enabled": c.settings.enabled,
            "matches": matches, "running_matches": running,
        }

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

    @app.post("/api/attack-defense/captures/sanitize")
    def sanitize_pcap(req: CaptureSanitizeRequest, identity: Identity = Depends(operator)):
        """PCAP/캡처 프라이버시(roadmap #1): 플래그 스크럽·팀 익명화·지연 게이팅·워터마크 후
        수신 팀에 배포 가능한 정제본 반환. 지연 전이면 released=false 로 보류."""
        result = sanitize_capture(
            [f.model_dump() for f in req.flows],
            active_flags=set(req.active_flags),
            team_ips=req.team_ips,
            recipient_id=req.recipient_team_id,
            capture_ts=req.capture_ts,
            now=time.time(),
            delay_sec=c.settings.pcap_release_delay_seconds,
            salt=c.settings.pcap_anonymize_salt,
        )
        from .evidence import AuditContext
        c.evidence.record(AuditContext(
            actor=identity.actor, event_type="capture.sanitize",
            result="released" if result["released"] else "withheld",
            team_id=req.recipient_team_id,
            metadata={"flows": len(req.flows), "released": result["released"],
                      "reason": req.reason}))
        return result

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
        current = c.repo.current_round(match_id)
        if not current or current["status"] != "active":
            raise HTTPException(409, "active round required")
        with c.db.transaction(immediate=True) as conn:
            now = c.db.server_time(conn)
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
                __import__(
                    "services.attack_defense.evidence", fromlist=["AuditContext"]
                ).AuditContext(
                    actor=ident.actor, event_type="round_extended", result="success",
                    correlation_id=current["correlation_id"], match_id=match_id,
                    round_id=current["id"],
                    metadata={"seconds": req.seconds, "reason": req.reason},
                    event_id=stable_id("audit", "round-extend", current["id"], req.seconds, req.reason),
                ),
                conn,
            )
        return c.repo.get_round(current["id"])

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
        return c.scoring.calculate_round(round_id, ident.actor)

    @app.post("/api/attack-defense/matches/{match_id}/score/recalculate")
    def recalculate_match(match_id: str, ident: Identity = Depends(operator)):
        return c.scoring.recalculate_match(match_id, ident.actor)

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

    # ---- Participant/public views -----------------------------------------
    @app.get("/api/attack-defense/public/matches/{match_id}/state")
    def public_match_state(match_id: str):
        match = c.repo.get_match(match_id)
        if not match:
            raise HTTPException(404, "match not found")
        round_row = c.repo.current_round(match_id)
        return {
            "id": match["id"], "name": match["name"], "mode": match["mode"],
            "status": match["status"], "starts_at": match["starts_at"],
            "round": round_row["sequence"] if round_row else 0,
            "round_status": round_row["status"] if round_row else None,
            "round_ends_at": round_row["ends_at"] if round_row else None,
            "server_time": time.time(),
        }

    @app.get("/api/attack-defense/matches/{match_id}/state")
    def match_state(match_id: str, ident: Identity = Depends(competitor)):
        team = membership(match_id, ident)
        match = c.repo.get_match(match_id)
        if not match:
            raise HTTPException(404, "match not found")
        round_row = c.repo.current_round(match_id)
        return {
            "id": match["id"], "name": match["name"], "mode": match["mode"],
            "status": match["status"], "starts_at": match["starts_at"],
            "round": round_row["sequence"] if round_row else 0,
            "round_status": round_row["status"] if round_row else None,
            "round_ends_at": round_row["ends_at"] if round_row else None,
            "server_time": time.time(), "team": {"id": team["id"], "name": team["name"]},
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
        if not c.repo.get_match(match_id):
            raise HTTPException(404, "match not found")
        conn = c.db.connect()
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

    @app.get("/api/attack-defense/matches/{match_id}/scoreboard")
    def public_scoreboard(match_id: str):
        try:
            rows = c.scoring.scoreboard(match_id, public=True)
        except KeyError:
            raise HTTPException(404, "match not found")
        current = c.repo.current_round(match_id)
        match = c.repo.get_match(match_id)
        match_config = json_load(match["config"]) if match else {}
        delay = int(match_config.get(
            "scoreboard_delay_rounds", c.settings.scoreboard_delay_rounds
        ))
        return {
            "view": "public", "delay_rounds": delay,
            "last_public_round": max(
                0, int(current["sequence"] if current else 0)
                - delay
            ),
            "provisional": bool(current and current["status"] != "finalized"),
            "scoreboard": rows,
        }

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
            return c.patches.complete_job(job_id, req.success, req.result, ident.actor)
        except ValueError as exc:
            raise HTTPException(409, str(exc))

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
                    """SELECT rowid,* FROM audit_events WHERE match_id=? AND rowid>?
                       ORDER BY rowid LIMIT 100""", (match_id, cursor)
                ).fetchall()
                conn.close()
                if not rows:
                    yield ": keepalive\n\n"
                    await asyncio.sleep(2)
                    continue
                for row in rows:
                    cursor = int(row["rowid"])
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
}


def _public_event(row: dict, ident: Identity | None) -> dict | None:
    operator_view = bool(ident and ident.role in {"instructor", "operator"})
    own_team = bool(ident and ident.team_id and ident.team_id == row.get("team_id"))
    if not operator_view and row["event_type"] not in PUBLIC_EVENT_TYPES and not own_team:
        return None
    category = (
        "patch" if "patch" in row["event_type"] else
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
    elif own_team:
        event["scope"] = "own_team"
    return event
