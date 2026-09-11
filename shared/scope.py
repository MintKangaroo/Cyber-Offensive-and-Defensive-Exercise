"""Service-level range ownership. Strict mode is enabled by the production profile.

Unknown ownership is never assigned from the caller's request. Local legacy mode
remains available for isolated beginner exercises; it is not a multi-tenant mode.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import time
from contextvars import ContextVar
from http.cookies import SimpleCookie
from urllib.parse import parse_qs

import httpx
from fastapi import HTTPException
from starlette.responses import JSONResponse

from .rbac import Identity, require_role

_current: ContextVar[Identity | None] = ContextVar("range_identity", default=None)
PUBLIC_EVENTS = {
    "asset_compromised",
    "asset_recovered",
    "scenario_started",
    "scenario_ended",
    "stage_completed",
}


def enforced() -> bool:
    return os.environ.get("RANGE_SCOPE_ENFORCE", "").lower() in {
        "true",
        "1",
        "yes",
        "on",
    }


def identity() -> Identity | None:
    return _current.get() if enforced() else None


def is_team(ident: Identity | None = None) -> bool:
    who = ident if ident is not None else identity()
    return who is not None and who.role in {
        "red",
        "blue",
        "observer",
        "competitor",
        "operator",
    }


def scope_values(record: dict) -> tuple[str, str]:
    md = record.get("metadata") or record.get("matched_event") or {}
    if isinstance(md, str):
        try:
            md = json.loads(md)
        except (ValueError, TypeError):
            md = {}
    if not isinstance(md, dict):
        md = {}
    return str(record.get("team_id") or md.get("team_id") or ""), str(
        record.get("scenario_id")
        or md.get("scenario_id")
        or record.get("match_id")
        or md.get("match_id")
        or ""
    )


def owns(record: dict, ident: Identity | None = None) -> bool:
    who = ident if ident is not None else identity()
    if who is None or who.role == "instructor":
        return True
    team, scenario = scope_values(record)
    metadata = record.get("metadata") or {}
    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except ValueError:
            metadata = {}
    defender = record.get("defender_team_id") or (
        metadata.get("defender_team_id") if isinstance(metadata, dict) else None
    )
    membership = team == who.team_id or who.role == "blue" and defender == who.team_id
    return bool(
        who.team_id and who.match_id and membership and scenario == who.match_id
    )


def check(record: dict, ident: Identity | None = None):
    if not owns(record, ident):
        raise HTTPException(404, "Record not found in your exercise scope")


def pair(team: str | None = None, scenario: str | None = None) -> tuple[str, str]:
    who = identity()
    if who is None or who.role == "instructor":
        return team or "", scenario or ""
    if (
        team
        and team != who.team_id
        or scenario
        and scenario not in {"default", who.match_id}
    ):
        raise HTTPException(403, "Requested scope does not match your membership")
    return who.team_id, who.match_id


def check_agent_asset(asset: str):
    who = identity()
    if who and who.role == "range-agent" and who.actor != asset:
        raise HTTPException(404, "Asset not found in sensor scope")


def agent_identity(
    auth: str, service: str, path: str, method: str, query: bytes
) -> Identity | None:
    if not auth.startswith("RangeAgent "):
        return None
    asset, sep, token = auth.removeprefix("RangeAgent ").partition(":")
    master = os.environ.get("SERVICE_TOKEN", "")
    from .service_auth import range_agent_signature

    if (
        not sep
        or not master
        or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,120}", asset)
        or not hmac.compare_digest(token, range_agent_signature(master, asset))
    ):
        raise HTTPException(401, "Invalid sensor credential")
    allowed = False
    if service == "config" and method == "GET":
        allowed = (
            path == "/config/killswitch"
            or path in {"/config/patches", "/config/quarantine"}
            and parse_qs(query.decode()).get("asset") == [asset]
        )
    if service == "collector":
        allowed = method == "POST" and path == "/events"
    if service == "edr":
        allowed = (
            method == "POST"
            and (
                path == "/edr/ingest"
                or path.startswith("/edr/kill-commands/")
                and path.endswith("/ack")
            )
        ) or (method == "GET" and path == f"/edr/hosts/{asset}/kill-commands/pending")
    if not allowed:
        raise HTTPException(403, "Sensor route is not permitted")
    return Identity(actor=asset, role="range-agent")


def asset_owner(asset: str) -> dict:
    # An operator-provided inventory; telemetry/request text cannot grant access.
    try:
        inventory = json.loads(os.environ.get("RANGE_ASSET_SCOPES", "{}"))
    except ValueError:
        return {}
    value = inventory.get(asset, {}) if isinstance(inventory, dict) else {}
    return value if isinstance(value, dict) else {}


def event_projection(
    record: dict, ident: Identity | None = None, now: float | None = None
) -> dict | None:
    who = ident if ident is not None else identity()
    if who is None or who.role == "instructor":
        return record
    if who.role in {"red", "blue"}:
        return (
            record
            if owns(record, who) and (who.role != "red" or record.get("actor") == "red")
            else None
        )
    if who.role != "observer":
        return None
    import time

    cutoff = (time.time() if now is None else now) - max(
        30, int(os.environ.get("OBSERVER_DELAY_SEC", "30"))
    )
    ts = record.get("timestamp")
    if (
        not isinstance(ts, (int, float))
        or ts > cutoff
        or record.get("event_type") not in PUBLIC_EVENTS
    ):
        return None
    if who.match_id and record.get("scenario_id") != who.match_id:
        return None
    return {
        k: record[k]
        for k in (
            "event_id",
            "event_type",
            "timestamp",
            "scenario_id",
            "target_asset",
            "actor",
        )
        if k in record
    } | {"metadata": {}}


def topic_projection(topic: str, data: dict, who: Identity):
    if who.role == "instructor":
        return data
    if topic in {"events", "detections"}:
        return event_projection(data, who)
    if topic == "safety":
        return {
            k: data[k]
            for k in ("timestamp", "killswitch", "active", "action")
            if k in data
        }
    if who.role not in {"red", "blue"} or not owns(data, who):
        return None
    if topic == "scores":
        if who.role == "red" and data.get("actor") != "red":
            return None
        return {
            k: data[k]
            for k in (
                "timestamp",
                "scenario_id",
                "team_id",
                "actor",
                "points",
                "category",
                "event_id",
            )
            if k in data
        }
    if topic == "phase_clock":
        return {
            k: data[k]
            for k in (
                "timestamp",
                "scenario_id",
                "team_id",
                "phase",
                "elapsed_sec",
                "remaining_sec",
                "status",
            )
            if k in data
        }
    return None


async def verify_session(authorization: str) -> None:
    """Check revocation as well as signatures; an unavailable identity server is closed."""
    if authorization.removeprefix("Bearer ").count(".") != 2:
        return
    try:
        async with httpx.AsyncClient(timeout=3, follow_redirects=False) as client:
            response = await client.get(
                os.environ.get("AUTH_URL", "http://auth:8051").rstrip("/") + "/auth/me",
                headers={"Authorization": authorization},
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code >= 500:
            raise HTTPException(503, "Identity verification unavailable") from exc
        raise HTTPException(401, "Session expired or revoked") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(503, "Identity verification unavailable") from exc


async def receive_while_authorized(websocket) -> None:
    """Idle and active sockets both recheck JWT revocation/expiry every 15 seconds."""
    next_check = time.monotonic() + 15
    while True:
        if enforced() and time.monotonic() >= next_check:
            auth = websocket.scope.get("state", {}).get("range_authorization", "")
            try:
                await verify_session(auth)
            except HTTPException:
                await websocket.close(code=4401)
                return
            next_check = time.monotonic() + 15
        try:
            await asyncio.wait_for(
                websocket.receive_text(),
                timeout=max(0.1, next_check - time.monotonic()),
            )
        except asyncio.TimeoutError:
            next_check = min(next_check, time.monotonic())


# Grants use resolved FastAPI route templates, never a permissive URL prefix.
# A newly registered /alerts/export route must not inherit /alerts/{alert_id} access.
def _grants(roles, *routes):
    return {
        (spec.split(" ", 1)[0], spec.split(" ", 1)[1]): set(roles) for spec in routes
    }


_HUMAN_ROUTES = {
    "collector": _grants(
        {"red", "blue", "observer"},
        "GET /events",
        "GET /events/delayed",
        "GET /replay/events",
        "GET /replay/page",
        "GET /replay/checkpoint",
        "GET /stream",
        "GET /ws",
    ),
    "incident": _grants(
        {"blue"},
        "GET /incidents",
        "GET /incidents/sla",
        "GET /incidents/{iid}",
        "GET /incidents/{iid}/aar",
        "POST /incidents/from-alert",
        "POST /incidents/{iid}/transition",
        "POST /incidents/{iid}/note",
        "POST /incidents/{iid}/assign",
    ),
    "siem": _grants(
        {"blue"},
        "GET /search",
        "GET /alerts",
        "GET /alerts/{alert_id}",
        "POST /alerts/{alert_id}",
        "GET /stats",
        "GET /detection/attack-coverage",
        "GET /ws/logs",
        "GET /ws/alerts",
    ),
    "edr": _grants(
        {"blue"},
        "GET /edr/hosts",
        "GET /edr/alerts",
        "GET /edr/alerts/{alert_id}",
        "GET /edr/ws",
        "GET /edr/hosts/{asset}/processes",
        "GET /edr/hosts/{asset}/timeline",
        "GET /edr/hosts/{asset}/kill-commands",
        "POST /edr/hosts/{asset}/isolate",
        "POST /edr/hosts/{asset}/unisolate",
        "POST /edr/hosts/{asset}/process/{pid}/kill",
    ),
    "injects": _grants(
        {"red", "blue"}, "GET /injects/inbox", "POST /injects/{iid}/respond"
    ),
    "config": _grants(
        {"blue"},
        "GET /config/patches",
        "GET /config/quarantine",
        "GET /config/killswitch",
        "GET /config/history",
    ),
    "scoring": _grants({"red", "blue"}, "GET /scores", "GET /scores/history"),
    "portal": {
        **_grants(
            {"red", "blue"},
            "GET /portal/teams",
            "GET /portal/challenges",
            "GET /portal/challenges/{cid}",
            "GET /portal/challenges/{cid}/artifact",
            "GET /portal/competitions",
            "GET /portal/competitions/{sid}",
            "GET /portal/nice-coverage",
            "GET /portal/scoreboard",
            "GET /portal/training/me",
            "POST /portal/training/challenges/{cid}/start",
            "GET /portal/training/hints/policy",
            "GET /portal/training/challenges/{cid}/hints",
            "POST /portal/training/challenges/{cid}/hints/{index}/reveal",
            "GET /portal/training/blue/{cid}/rubric",
        ),
        **_grants({"red"}, "POST /portal/challenges/{cid}/submit"),
        **_grants(
            {"blue"},
            "GET /portal/blue/challenges",
            "GET /portal/blue/challenges/{cid}/dataset",
            "GET /portal/blue/scoreboard",
            "GET /portal/blue/patches",
            "POST /portal/blue/challenges/{cid}/submit",
            "POST /portal/blue/patch",
        ),
    },
    "noc": _grants({"blue"}, "GET /noc/status", "GET /noc/history", "GET /noc/ws"),
    "scenario": _grants(
        {"red", "blue"},
        "GET /scenario/{scenario_id}/progress",
        "POST /scenario/{scenario_id}/objective/submit",
    ),
}


def human_roles(service: str, path: str, method: str) -> set[str]:
    return {"instructor"} | _HUMAN_ROUTES.get(service, {}).get((method, path), set())


def route_template(routes, request_scope) -> str:
    """Resolve effective templates for both flattened and included FastAPI routers.

    FastAPI 0.141 retains included routers instead of copying their APIRoutes.
    Its effective contexts apply include prefixes and nested routing order. Match
    those contexts, never broaden authorization with string-prefix checks.
    """
    from starlette.routing import Match

    for route in routes:
        contexts = getattr(route, "effective_route_contexts", None)
        candidates = contexts() if callable(contexts) else (route,)
        for candidate in candidates:
            if candidate.matches(request_scope)[0] == Match.FULL:
                return getattr(candidate, "path", "") or getattr(
                    getattr(candidate, "starlette_route", None), "path", ""
                )
    return ""


class ScopeMiddleware:
    """Authenticate direct HTTP/WS access before service-specific SQL projections."""

    def __init__(self, app, service: str, routes=()):
        self.app = app
        self.service = service
        self.routes = routes

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] not in {"http", "websocket"}
            or not enforced()
            or scope.get("path") == "/health"
            or scope.get("method") == "OPTIONS"
        ):
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        cookie = SimpleCookie()
        try:
            cookie.load(headers.get("cookie", ""))
        except Exception:
            pass
        auth = headers.get("authorization", "") or (
            "Bearer " + cookie["cr_token"].value if "cr_token" in cookie else ""
        )
        path = scope.get("path", "")
        method = scope.get("method", "GET")
        service_token = os.environ.get("SERVICE_TOKEN", "")
        trusted = bool(
            service_token and hmac.compare_digest(auth, "Bearer " + service_token)
        )
        try:
            sensor = agent_identity(
                auth, self.service, path, method, scope.get("query_string", b"")
            )
            if sensor:
                who = sensor
            elif trusted and (
                method == "GET"
                or scope["type"] == "websocket"
                or path in {"/events", "/edr/ingest", "/score/ingest", "/replay/checkpoint"}
                or self.service == "edr"
                and path.startswith("/edr/kill-commands/")
                and path.endswith("/ack")
            ):
                who = Identity(actor="range-service", role="instructor")
            else:
                template = route_template(self.routes, scope)
                allowed = human_roles(self.service, template, method)
                who = require_role(auth, allowed, allow_dev=False)
                await verify_session(auth)
                if who.role in {"red", "blue"} and (
                    not who.team_id or not who.match_id
                ):
                    raise HTTPException(
                        403, "Team and exercise membership are required"
                    )
            scope = dict(scope)
            scope["headers"] = [
                (k, v)
                for k, v in scope.get("headers", [])
                if k.lower() != b"authorization"
            ] + [(b"authorization", auth.encode())]
            scope.setdefault("state", {})["range_identity"] = who
            scope["state"]["range_authorization"] = auth
            marker = _current.set(who)
            try:
                from .action_guard import dangerous, guarded

                if scope["type"] == "http" and dangerous(method, path):
                    await guarded(self.app, scope, receive, send, who)
                else:
                    await self.app(scope, receive, send)
            finally:
                _current.reset(marker)
        except HTTPException as exc:
            if scope["type"] == "websocket":
                await send(
                    {
                        "type": "websocket.close",
                        "code": 4403 if exc.status_code == 403 else 4401,
                    }
                )
            else:
                await JSONResponse({"detail": exc.detail}, status_code=exc.status_code)(
                    scope, receive, send
                )


def install(app, service: str):
    app.add_middleware(ScopeMiddleware, service=service, routes=app.router.routes)
