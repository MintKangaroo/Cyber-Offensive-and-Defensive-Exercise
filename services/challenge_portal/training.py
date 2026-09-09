"""Personal training evidence, separate from competition scores and solve ownership.

Only authenticated, membership-bound observations enter the personal profile.
Unattributed legacy attempts are retained in the original audit without guessing who
performed them. No submitted answer, flag hash or another learner's evidence leaves
this module.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Cookie, Header, HTTPException

from shared import scope
from shared.rbac import Identity, require_role

DOMAINS = (
    "Web",
    "Network",
    "Forensics",
    "Reverse Engineering",
    "Detection",
    "AI Security",
    "ICS/OT",
    "Incident Response",
)
CATEGORIES = {
    "web": "Web",
    "network": "Network",
    "forensics": "Forensics",
    "reversing": "Reverse Engineering",
    "reverse": "Reverse Engineering",
    "detection": "Detection",
    "ai": "AI Security",
    "ics": "ICS/OT",
    "incident_response": "Incident Response",
}


async def member(authorization: str, cookie: str | None = None) -> Identity:
    auth = authorization or (f"Bearer {cookie}" if cookie else "")
    ident = scope.identity() or require_role(auth, {"red", "blue"}, allow_dev=False)
    if (
        ident.role not in {"red", "blue"}
        or not ident.team_id
        or not ident.match_id
        or ident.dev_mode
    ):
        raise HTTPException(
            403, "Personal training requires an assigned Red or Blue membership"
        )
    if scope.identity() is None:
        await scope.verify_session(auth)
    return ident


def profile(conn, ident: Identity, catalog: dict) -> dict:
    # Red's existing audit team key includes its match; Blue's historical audit uses a plain team.
    audit_team = (
        f"{ident.match_id}::{ident.team_id}" if ident.role == "red" else ident.team_id
    )
    rows = conn.execute(
        """SELECT cid, COUNT(*) attempts, SUM(passed) successful_attempts,
           MIN(CASE WHEN passed=1 THEN ts END) completed_at, MAX(ts) last_attempt_at
           FROM submissions WHERE verified_subject=? AND team_id=? AND match_id=? AND side=?
           GROUP BY cid""",
        (ident.actor, audit_team, ident.match_id, ident.role),
    ).fetchall()
    observations = {row["cid"]: dict(row) for row in rows}
    starts = {
        row["cid"]: row["started_at"]
        for row in conn.execute(
            "SELECT cid,started_at FROM training_starts WHERE subject=? AND team_id=? AND match_id=? AND side=?",
            (ident.actor, ident.team_id, ident.match_id, ident.role),
        )
    }
    domains = {
        name: {
            "domain": name,
            "available": 0,
            "completed": 0,
            "attempts": 0,
            "proficiency": None,
        }
        for name in DOMAINS
    }
    activity = []
    recommendations = []
    for cid, challenge in catalog.items():
        observed = observations.get(cid)
        complete = bool(observed and observed["successful_attempts"])
        domain = CATEGORIES.get(str(challenge.get("category", "")).lower())
        if domain:
            domains[domain]["available"] += 1
            domains[domain]["completed"] += int(complete)
            domains[domain]["attempts"] += observed["attempts"] if observed else 0
        if observed or cid in starts:
            start = starts.get(cid)
            end = observed["completed_at"] if observed else None
            activity.append(
                {
                    "id": cid,
                    "title": challenge.get("title", cid),
                    "domain": domain,
                    "attempts": observed["attempts"] if observed else 0,
                    "completed": complete,
                    "completed_at": end,
                    "started_at": start,
                    "elapsed_sec": round(end - start, 1)
                    if end is not None and start is not None and end >= start
                    else None,
                    "last_attempt_at": observed["last_attempt_at"]
                    if observed
                    else None,
                    "hints_used": None,
                    "detection_quality": None,
                    "response_quality": None,
                }
            )
        if not complete:
            recommendations.append(
                {
                    "id": cid,
                    "title": challenge.get("title", cid),
                    "difficulty": challenge.get("difficulty"),
                    "reason": "Continue a recorded attempt"
                    if observed
                    else "No recorded personal completion; ordered by published difficulty",
                    "attempted": bool(observed),
                }
            )
    for row in domains.values():
        if row["available"]:
            row["proficiency"] = round(100 * row["completed"] / row["available"])
    recommendations.sort(
        key=lambda c: (
            not c["attempted"],
            {"easy": 0, "medium": 1, "hard": 2, "insane": 3}.get(c["difficulty"], 4),
            c["id"],
        )
    )
    activity.sort(
        key=lambda c: (-(c["last_attempt_at"] or c["started_at"] or 0), c["id"])
    )
    return {
        "scope": "individual",
        "collection_enabled": scope.enforced(),
        "subject": ident.actor,
        "team_id": ident.team_id,
        "match_id": ident.match_id,
        "side": ident.role,
        "domains": list(domains.values()),
        "activity": activity,
        "recommendations": recommendations[:6],
        "method": "Recorded personal grader results in this exercise. Coverage is completed catalog challenges / available challenges; it is not a mastery grade. Attempts count evaluated submissions, including repeat passes. Elapsed time includes idle time from explicit practice start to first recorded pass. Competition scores are unchanged.",
        "unavailable_inputs": [
            "hint count",
            "active working time",
            "detection quality",
            "response quality",
            "attribution of legacy attempts",
        ],
    }


def build_router(portal):
    router = APIRouter(prefix="/portal/training", tags=["Personal training"])

    # The portal can be loaded as main (Docker) or services.challenge_portal.main (tests).
    # Capture its existing catalog and database via callbacks rather than importing it twice.
    @router.get("/me")
    async def personal_profile(
        authorization: str = Header(default=""),
        cr_token: str | None = Cookie(default=None),
    ):
        ident = await member(authorization, cr_token)
        conn = portal["db"]()
        try:
            catalog = portal[ident.role]()
            return profile(conn, ident, catalog)
        finally:
            conn.close()

    @router.post("/challenges/{cid}/start")
    async def start(
        cid: str,
        authorization: str = Header(default=""),
        cr_token: str | None = Cookie(default=None),
    ):
        ident = await member(authorization, cr_token)
        if cid not in portal[ident.role]():
            raise HTTPException(404, "Challenge is unavailable in this workspace")
        conn = portal["db"]()
        try:
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO training_starts VALUES(?,?,?,?,?,?)",
                    (
                        ident.actor,
                        ident.team_id,
                        ident.match_id,
                        cid,
                        ident.role,
                        time.time(),
                    ),
                )
            row = conn.execute(
                "SELECT started_at FROM training_starts WHERE subject=? AND team_id=? AND match_id=? AND cid=? AND side=?",
                (ident.actor, ident.team_id, ident.match_id, cid, ident.role),
            ).fetchone()
            return {
                "challenge_id": cid,
                "started_at": row["started_at"],
                "scope": "individual",
            }
        finally:
            conn.close()

    return router
