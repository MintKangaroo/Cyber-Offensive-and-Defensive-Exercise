"""Personal training evidence, separate from competition scores and solve ownership.

Only authenticated, membership-bound observations enter the personal profile.
Unattributed legacy attempts are retained in the original audit without guessing who
performed them. No submitted answer, flag hash or another learner's evidence leaves
this module.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import yaml
from fastapi import APIRouter, Cookie, Header, HTTPException
from pydantic import BaseModel, Field

from shared import scope
from shared.rbac import Identity, require_role

# 정책 인지 힌트 기본값: 힌트 제공 허용(사용은 항상 기록). 교관이 끌 수 있다.
DEFAULT_HINT_POLICY = {"enabled": True}


class HintPolicyRequest(BaseModel):
    enabled: bool = True
    reason: str = Field(default="", max_length=2000)

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


def hint_policy(conn) -> dict:
    """정책 인지 힌트 게이트(교관 설정). 미설정 시 기본값."""
    row = conn.execute("SELECT value FROM training_policy WHERE key='hints'").fetchone()
    if not row:
        return dict(DEFAULT_HINT_POLICY)
    try:
        stored = json.loads(row["value"])
    except (ValueError, TypeError):
        return dict(DEFAULT_HINT_POLICY)
    return {"enabled": bool(stored.get("enabled", True))}


def challenge_hints(catalog: dict, cid: str) -> list[dict]:
    """챌린지 정의에서 red_task.hints 를 서버측 로드(공개 카탈로그엔 미노출).

    힌트는 학습 보조로 열람 대상이지만, 그레이더/정답과 달리 명시적 공개(reveal) 시에만
    본문이 나가고 그 사실이 기록된다.
    """
    entry = catalog.get(cid)
    if not entry or not entry.get("dir"):
        return []
    try:
        raw = (yaml.safe_load((Path(entry["dir"]) / "challenge.yaml").read_text()) or {})
        data = raw.get("challenge", {}) or {}
    except (OSError, yaml.YAMLError):
        return []
    out = []
    for h in (data.get("red_task", {}) or {}).get("hints", []) or []:
        if isinstance(h, dict) and isinstance(h.get("text"), str):
            out.append({"cost": int(h.get("cost", 0) or 0), "text": h["text"]})
    return out


def revealed_indices(conn, ident: Identity, cid: str) -> list[int]:
    return [
        r["hint_index"]
        for r in conn.execute(
            "SELECT hint_index FROM training_hints WHERE subject=? AND team_id=? AND match_id=? AND cid=? AND side=? ORDER BY hint_index",
            (ident.actor, ident.team_id, ident.match_id, cid, ident.role),
        )
    ]


async def instructor(authorization: str, cookie: str | None = None) -> Identity:
    auth = authorization or (f"Bearer {cookie}" if cookie else "")
    return require_role(auth, {"instructor"}, allow_dev=False)


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
    hint_counts = {
        row["cid"]: row["n"]
        for row in conn.execute(
            "SELECT cid, COUNT(*) n FROM training_hints WHERE subject=? AND team_id=? AND match_id=? AND side=? GROUP BY cid",
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
        if observed or cid in starts or cid in hint_counts:
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
                    "hints_used": hint_counts.get(cid, 0),
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
        "method": "Recorded personal grader results in this exercise. Coverage is completed catalog challenges / available challenges; it is not a mastery grade. Attempts count evaluated submissions, including repeat passes. Elapsed time includes idle time from explicit practice start to first recorded pass. Hints used counts hints this learner explicitly revealed (policy-gated); it does not change scoring. Competition scores are unchanged.",
        "unavailable_inputs": [
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

    @router.get("/hints/policy")
    async def get_hint_policy(
        authorization: str = Header(default=""),
        cr_token: str | None = Cookie(default=None),
    ):
        await member(authorization, cr_token)
        conn = portal["db"]()
        try:
            return hint_policy(conn)
        finally:
            conn.close()

    @router.post("/hints/policy")
    async def set_hint_policy(
        req: HintPolicyRequest,
        authorization: str = Header(default=""),
        cr_token: str | None = Cookie(default=None),
    ):
        ident = await instructor(authorization, cr_token)
        conn = portal["db"]()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO training_policy(key,value,updated_at,actor) VALUES('hints',?,?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at, actor=excluded.actor",
                    (json.dumps({"enabled": req.enabled}), time.time(), ident.actor),
                )
            return {"enabled": req.enabled, "actor": ident.actor}
        finally:
            conn.close()

    @router.get("/challenges/{cid}/hints")
    async def list_hints(
        cid: str,
        authorization: str = Header(default=""),
        cr_token: str | None = Cookie(default=None),
    ):
        ident = await member(authorization, cr_token)
        catalog = portal[ident.role]()
        if cid not in catalog:
            raise HTTPException(404, "Challenge is unavailable in this workspace")
        conn = portal["db"]()
        try:
            hints = challenge_hints(catalog, cid)
            revealed = set(revealed_indices(conn, ident, cid))
            policy = hint_policy(conn)
            # 미공개 힌트 본문은 절대 나가지 않는다(공개된 것만 text 포함).
            items = [
                {
                    "index": i,
                    "cost": h["cost"],
                    "revealed": i in revealed,
                    "text": h["text"] if i in revealed else None,
                }
                for i, h in enumerate(hints)
            ]
            next_index = len(revealed) if len(revealed) < len(hints) else None
            return {
                "challenge_id": cid,
                "policy_enabled": policy["enabled"],
                "total": len(hints),
                "revealed_count": len(revealed),
                "next_index": next_index,
                "hints": items,
            }
        finally:
            conn.close()

    @router.post("/challenges/{cid}/hints/{index}/reveal")
    async def reveal_hint(
        cid: str,
        index: int,
        authorization: str = Header(default=""),
        cr_token: str | None = Cookie(default=None),
    ):
        ident = await member(authorization, cr_token)
        catalog = portal[ident.role]()
        if cid not in catalog:
            raise HTTPException(404, "Challenge is unavailable in this workspace")
        conn = portal["db"]()
        try:
            if not hint_policy(conn)["enabled"]:
                raise HTTPException(403, "Hints are disabled by the instructor policy")
            hints = challenge_hints(catalog, cid)
            if index < 0 or index >= len(hints):
                raise HTTPException(404, "No such hint")
            revealed = revealed_indices(conn, ident, cid)
            # 진행형 공개: 앞 힌트를 건너뛸 수 없다. 이미 연 힌트 재열람은 멱등(그대로 반환).
            if index > len(revealed):
                raise HTTPException(409, "Reveal hints in order; open the next hint")
            already = index < len(revealed)
            if not already:
                with conn:
                    conn.execute(
                        "INSERT OR IGNORE INTO training_hints VALUES(?,?,?,?,?,?,?,?)",
                        (
                            ident.actor, ident.team_id, ident.match_id, cid, ident.role,
                            index, hints[index]["cost"], time.time(),
                        ),
                    )
            return {
                "challenge_id": cid,
                "index": index,
                "cost": hints[index]["cost"],
                "text": hints[index]["text"],
                "hints_used": len(revealed) if already else len(revealed) + 1,
            }
        finally:
            conn.close()

    return router
