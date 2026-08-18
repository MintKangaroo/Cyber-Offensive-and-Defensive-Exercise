"""
Incident Case Management 서비스(P1)
====================================
SIEM/EDR 알림(alert)을 인시던트로 **승격**해 라이프사이클로 추적한다. SOC 훈련의 핵심:
탐지에서 끝나지 않고 triage→억제→근절→복구→종결까지 팀이 케이스를 운영하게 한다.

- 알림→인시던트 승격(POST /incidents/from-alert). 원 alert_id 로 중복 승격 방지.
- 상태전이(POST /incidents/{id}/transition) — model.can_transition 규칙 강제, 타임라인 자동 기록.
- 배정/노트(assign/note) — 모든 변경이 타임라인에 남아 감사·AAR 근거가 된다.
- SLA(심각도별 응답/해결 시한) 위반 리포트(GET /incidents/sla).
- AAR 연동(GET /incidents/{id}/aar): 전체 타임라인 + MTTA/MTTR + SLA 결과.

RBAC: 쓰기는 blue/instructor, 읽기는 require_read 게이트(관전자 이상). 승격 시 Live Fire 에
blue_detection_success 이벤트를 발행해 상황판·점수에 연동.
영속: DATA_DIR/incidents.db (P0-3 볼륨).
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
import uuid
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))  # repo root
from shared.rbac import require_role, require_read  # noqa: E402
from shared.service_auth import service_headers  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
import model  # noqa: E402

DB_PATH = Path(os.environ.get("DATA_DIR", str(Path(__file__).parent))) / "incidents.db"
EVENT_COLLECTOR_URL = os.environ.get("EVENT_COLLECTOR_URL", "http://event_collector:8010")

app = FastAPI(title="Incident Case Management")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|(\d{1,3}\.){3}\d{1,3}|[\w-]+\.ts\.net)(:\d+)?",
    allow_methods=["*"], allow_headers=["*"], allow_credentials=True,
)


def _db():
    c = sqlite3.connect(DB_PATH, timeout=5.0)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")      # 감사 3.7: 동시성/내구성
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("PRAGMA busy_timeout=5000")
    return c


def _init():
    c = _db()
    c.execute("""CREATE TABLE IF NOT EXISTS incidents(
        id TEXT PRIMARY KEY, title TEXT, severity TEXT, status TEXT,
        source_alert_id TEXT, source TEXT, host TEXT, team_id TEXT, assignee TEXT,
        created_at REAL, acknowledged_at REAL, closed_at REAL, timeline TEXT)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_inc_status ON incidents(status)")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_inc_alert ON incidents(source_alert_id)")
    c.commit(); c.close()


_init()


def _row_to_dict(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["timeline"] = json.loads(d.get("timeline") or "[]")
    return d


def _append_timeline(inc: dict, actor: str, action: str, note: str = "") -> list:
    tl = inc.get("timeline") or []
    tl.append({"ts": time.time(), "actor": actor, "action": action, "note": note})
    return tl


def _save(c, inc: dict):
    c.execute("""UPDATE incidents SET status=?, assignee=?, acknowledged_at=?, closed_at=?, timeline=?
                 WHERE id=?""",
              (inc["status"], inc.get("assignee"), inc.get("acknowledged_at"),
               inc.get("closed_at"), json.dumps(inc["timeline"]), inc["id"]))
    c.commit()


async def _emit(team_id: str, title: str, sev: str):
    ev = {"event_id": str(uuid.uuid4()), "event_type": "blue_detection_success",
          "timestamp": time.time(), "actor": "blue", "team_id": team_id or "default",
          "scenario_id": "default", "target_asset": "soc", "phase": "objective",
          "metadata": {"source": "incident", "title": title, "severity": sev}}
    try:
        async with httpx.AsyncClient(timeout=2.0) as cl:
            await cl.post(f"{EVENT_COLLECTOR_URL}/events", json=ev, headers=service_headers())
    except httpx.HTTPError:
        pass


class FromAlertReq(BaseModel):
    alert_id: str
    title: str
    severity: str = "medium"
    source: str = "siem"        # siem | edr | manual
    host: str = ""
    team_id: str = ""


class TransitionReq(BaseModel):
    to: str
    note: str = ""


class NoteReq(BaseModel):
    note: str


class AssignReq(BaseModel):
    assignee: str


@app.get("/health")
def health():
    c = _db(); n = c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]; c.close()
    return {"service": "incident", "incidents": n}


@app.post("/incidents/from-alert")
async def from_alert(req: FromAlertReq, authorization: str = Header(default="")):
    ident = require_role(authorization, {"blue", "instructor"})
    if req.severity.lower() not in ("critical", "high", "medium", "low"):
        raise HTTPException(400, "severity must be critical|high|medium|low")
    c = _db()
    dup = c.execute("SELECT id FROM incidents WHERE source_alert_id=?", (req.alert_id,)).fetchone()
    if dup:
        c.close()
        raise HTTPException(409, f"이미 승격된 알림입니다: incident {dup['id']}")
    iid = "INC-" + uuid.uuid4().hex[:8]
    now = time.time()
    tl = [{"ts": now, "actor": ident.actor, "action": "promoted_from_alert",
           "note": f"alert {req.alert_id} ({req.source})"}]
    c.execute("""INSERT INTO incidents(id,title,severity,status,source_alert_id,source,host,
                 team_id,assignee,created_at,acknowledged_at,closed_at,timeline)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (iid, req.title, req.severity.lower(), "new", req.alert_id, req.source, req.host,
               req.team_id, None, now, None, None, json.dumps(tl)))
    c.commit(); c.close()
    await _emit(req.team_id, req.title, req.severity)
    return {"id": iid, "status": "new", "severity": req.severity.lower()}


@app.get("/incidents")
def list_incidents(status: str = "", team_id: str = "", authorization: str = Header(default="")):
    require_read(authorization)
    c = _db()
    q = "SELECT * FROM incidents"; cond = []; p = []
    if status:
        cond.append("status=?"); p.append(status)
    if team_id:
        cond.append("team_id=?"); p.append(team_id)
    if cond:
        q += " WHERE " + " AND ".join(cond)
    q += " ORDER BY created_at DESC"
    rows = [_row_to_dict(r) for r in c.execute(q, p).fetchall()]
    c.close()
    now = time.time()
    for r in rows:
        r["sla"] = model.sla_breaches(r, now)
    return {"count": len(rows), "incidents": rows}


def _get(c, iid: str) -> dict:
    r = c.execute("SELECT * FROM incidents WHERE id=?", (iid,)).fetchone()
    if not r:
        c.close()
        raise HTTPException(404, "incident not found")
    return _row_to_dict(r)


@app.get("/incidents/sla")
def sla_report(authorization: str = Header(default="")):
    require_read(authorization)
    c = _db()
    rows = [_row_to_dict(r) for r in c.execute("SELECT * FROM incidents").fetchall()]
    c.close()
    now = time.time()
    breached = []
    for r in rows:
        b = model.sla_breaches(r, now)
        if b["response_breached"] or b["resolution_breached"]:
            breached.append({"id": r["id"], "title": r["title"], "severity": r["severity"],
                             "status": r["status"], **b})
    return {"open": sum(1 for r in rows if r["status"] != "closed"),
            "breached_count": len(breached), "breached": breached}


@app.get("/incidents/{iid}")
def get_incident(iid: str, authorization: str = Header(default="")):
    require_read(authorization)
    c = _db(); inc = _get(c, iid); c.close()
    inc["sla"] = model.sla_breaches(inc, time.time())
    inc["metrics"] = model.compute_metrics(inc)
    return inc


@app.post("/incidents/{iid}/transition")
def transition(iid: str, req: TransitionReq, authorization: str = Header(default="")):
    ident = require_role(authorization, {"blue", "instructor"})
    if req.to not in model.STATUSES:
        raise HTTPException(400, f"unknown status '{req.to}'")
    c = _db(); inc = _get(c, iid)
    if not model.can_transition(inc["status"], req.to):
        c.close()
        raise HTTPException(409, f"전이 불가: {inc['status']} → {req.to} "
                                 f"(허용: {sorted(model._TRANSITIONS.get(inc['status'], set()))})")
    now = time.time()
    if inc.get("acknowledged_at") is None and inc["status"] == "new":
        inc["acknowledged_at"] = now   # new 를 벗어나는 첫 대응 = 응답 시각(MTTA)
    if req.to == "closed":
        inc["closed_at"] = now
    inc["status"] = req.to
    inc["timeline"] = _append_timeline(inc, ident.actor, f"transition:{req.to}", req.note)
    _save(c, inc); c.close()
    return {"id": iid, "status": req.to, "sla": model.sla_breaches(inc, now)}


@app.post("/incidents/{iid}/note")
def add_note(iid: str, req: NoteReq, authorization: str = Header(default="")):
    ident = require_role(authorization, {"blue", "instructor"})
    c = _db(); inc = _get(c, iid)
    inc["timeline"] = _append_timeline(inc, ident.actor, "note", req.note)
    _save(c, inc); c.close()
    return {"id": iid, "timeline_len": len(inc["timeline"])}


@app.post("/incidents/{iid}/assign")
def assign(iid: str, req: AssignReq, authorization: str = Header(default="")):
    ident = require_role(authorization, {"blue", "instructor"})
    c = _db(); inc = _get(c, iid)
    inc["assignee"] = req.assignee
    inc["timeline"] = _append_timeline(inc, ident.actor, "assign", req.assignee)
    _save(c, inc); c.close()
    return {"id": iid, "assignee": req.assignee}


@app.get("/incidents/{iid}/aar")
def aar(iid: str, authorization: str = Header(default="")):
    require_read(authorization)
    c = _db(); inc = _get(c, iid); c.close()
    now = time.time()
    return {
        "id": inc["id"], "title": inc["title"], "severity": inc["severity"],
        "status": inc["status"], "team_id": inc["team_id"], "assignee": inc.get("assignee"),
        "source": {"alert_id": inc["source_alert_id"], "type": inc["source"], "host": inc["host"]},
        "metrics": model.compute_metrics(inc),
        "sla": model.sla_breaches(inc, now),
        "timeline": inc["timeline"],
    }


@app.post("/admin/reset")
def admin_reset(authorization: str = Header(default="")):
    require_role(authorization, {"instructor"})
    c = _db(); n = c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    c.execute("DELETE FROM incidents"); c.commit(); c.close()
    return {"service": "incident", "cleared": {"incidents": n}}


# ---------------------------------------------------------------------------
# 자동 강화(이벤트 상관): 자산 복구(asset_recovered) → 관련 미해결 인시던트 타임라인에
# 해결 힌트 주석. 자동 close 하지 않음(Blue 가 검토·종결 — SOC 훈련 주체성 유지).
# ---------------------------------------------------------------------------
import asyncio  # noqa: E402
CORRELATE_ENABLED = os.environ.get("INCIDENT_CORRELATE", "true").lower() == "true"


async def _correlate_loop():
    while True:
        await asyncio.sleep(10)
        try:
            async with httpx.AsyncClient(timeout=3.0) as cl:
                r = await cl.get(f"{EVENT_COLLECTOR_URL}/events?limit=300")
                events = r.json().get("events", [])
            recovered = {e["target_asset"] for e in events
                         if e.get("event_type") == "asset_recovered" and e.get("target_asset")}
            if not recovered:
                continue
            c = _db()
            incs = [_row_to_dict(row) for row in
                    c.execute("SELECT * FROM incidents WHERE status != 'closed'").fetchall()]
            for iid in model.find_resolvable(incs, recovered):
                inc = next(i for i in incs if i["id"] == iid)
                inc["timeline"] = _append_timeline(inc, "system", "recovery_detected",
                                                    f"자산 {inc['host']} 복구 감지 — 해결 검토 권장")
                _save(c, inc)
            c.close()
        except Exception:
            pass


@app.on_event("startup")
async def _start_correlate():
    if CORRELATE_ENABLED:
        asyncio.create_task(_correlate_loop())


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8095)
