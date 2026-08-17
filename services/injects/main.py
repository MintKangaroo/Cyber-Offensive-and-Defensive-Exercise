"""
비기술 인젝트 서비스(P1-4)
===========================
훈련은 기술 공방만이 아니다. 침해 중 언론이 전화하고, 경영진이 답을 요구하고, 규제기관이
통보 시한을 건다. 이 서비스는 그런 **비기술 인젝트**를 팀 인박스로 배달하고, 마감 내 대응
여부와 응답 품질(교관 루브릭 채점)을 추적한다.

- 내장 인젝트 라이브러리(언론/경영/규제/법무) + 교관 커스텀 디스패치.
- 팀 인박스(도착·마감·상태). 응답 제출 → 정시/지각 자동 판정.
- 교관 루브릭 채점(항목별 상한) → 지각 감점 → 최종 점수. 채점 시 Live Fire 이벤트 발행.
- 팀별 인젝트 성과 스코어보드(대응률·정시율·평균 점수%).

RBAC: 디스패치·채점은 instructor, 응답은 팀(red/blue/instructor), 조회는 read 게이트.
영속: DATA_DIR/injects.db (P0-3 볼륨).
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

sys.path.append(str(Path(__file__).resolve().parent.parent.parent))
from shared.rbac import require_role, require_read  # noqa: E402
from shared.service_auth import service_headers  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
import model  # noqa: E402
import engine  # noqa: E402

DB_PATH = Path(os.environ.get("DATA_DIR", str(Path(__file__).parent))) / "injects.db"
EVENT_COLLECTOR_URL = os.environ.get("EVENT_COLLECTOR_URL", "http://event_collector:8010")

# 내장 인젝트 라이브러리 — 마감(deadline_min)과 루브릭 포함. 교관은 그대로 쓰거나 커스텀 가능.
LIBRARY = [
    {"id": "media-press-call", "channel": "media", "from": "데일리 크로니클 기자",
     "subject": "귀사 시스템 침해 루머 — 15분 내 입장?",
     "body": "익명 제보로 랜섬웨어 감염 정황을 입수했습니다. 공식 입장을 요청합니다. 마감이 촉박합니다.",
     "deadline_min": 15,
     "rubric": [{"criterion": "정확성(확정 안 된 사실 단정 회피)", "max": 10},
                {"criterion": "책임감 있는 톤", "max": 10},
                {"criterion": "후속 커뮤니케이션 약속", "max": 5}]},
    {"id": "exec-ciso-brief", "channel": "exec", "from": "CEO",
     "subject": "지금 상황과 사업 영향 3줄 요약 요구",
     "body": "이사회 통화 10분 전이다. 무엇이 멈췄고, 언제 복구되며, 고객 영향은 무엇인지 3줄로.",
     "deadline_min": 10,
     "rubric": [{"criterion": "핵심 요약(범위/복구ETA/영향)", "max": 15},
                {"criterion": "불확실성 정직 표기", "max": 5}]},
    {"id": "regulator-notice", "channel": "regulator", "from": "개인정보보호 규제기관",
     "subject": "72시간 침해 신고 의무 안내",
     "body": "개인정보 유출이 확인되면 72시간 내 신고 의무가 있습니다. 신고 필요 여부와 초기 판단 근거를 회신하십시오.",
     "deadline_min": 45,
     "rubric": [{"criterion": "신고 요건 판단 근거", "max": 10},
                {"criterion": "유출 범위 초기 평가", "max": 10},
                {"criterion": "법무/DPO 에스컬레이션", "max": 5}]},
    {"id": "legal-hold", "channel": "legal", "from": "법무팀",
     "subject": "증거 보전(legal hold) 요청",
     "body": "소송 대비 로그·디스크 이미지 보전이 필요합니다. 보전 대상과 절차를 회신 바랍니다.",
     "deadline_min": 30,
     "rubric": [{"criterion": "보전 대상 식별", "max": 10},
                {"criterion": "무결성 절차(해시/체인오브커스터디)", "max": 10}]},
]
_LIB_BY_ID = {t["id"]: t for t in LIBRARY}

# 내장 예시 캠페인 — 랜섬웨어 위기: 언론 문의(즉시) → 경영 브리핑(1분) → 규제 통보(경영 응답 후).
# 경영 브리핑 마감을 놓치면 이사회 긴급 재촉이 자동 에스컬레이션된다.
EXAMPLE_CAMPAIGN_SPECS = [
    {"spec_id": "media", "template_id": "media-press-call", "at_sec": 0},
    {"spec_id": "exec", "template_id": "exec-ciso-brief", "at_sec": 60},
    {"spec_id": "regulator", "template_id": "regulator-notice",
     "trigger": {"after": "exec", "on": "answered"}},
    {"spec_id": "exec-escalation", "channel": "exec", "sender": "이사회 의장",
     "subject": "[긴급] 경영진 브리핑 미제출 — 즉시 보고하라",
     "body": "요청한 3줄 요약이 마감까지 오지 않았다. 이사회가 대기 중이다. 5분 내 현황을 보고하라.",
     "deadline_min": 5,
     "rubric": [{"criterion": "지연 사유 + 현황", "max": 10},
                {"criterion": "복구 ETA 재확인", "max": 5}],
     "trigger": {"after": "exec", "on": "deadline_missed"}},
]

app = FastAPI(title="Non-technical Injects")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|(\d{1,3}\.){3}\d{1,3}|[\w-]+\.ts\.net)(:\d+)?",
    allow_methods=["*"], allow_headers=["*"], allow_credentials=True,
)


def _db():
    c = sqlite3.connect(DB_PATH, timeout=5.0); c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")      # 감사 3.7: 동시성/내구성
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("PRAGMA busy_timeout=5000")
    return c


def _init():
    c = _db()
    c.execute("""CREATE TABLE IF NOT EXISTS injects(
        id TEXT PRIMARY KEY, template_id TEXT, channel TEXT, sender TEXT, subject TEXT,
        body TEXT, team_id TEXT, delivered_at REAL, deadline_at REAL, rubric TEXT,
        response_text TEXT, response_at REAL, score INTEGER, max_score INTEGER,
        rubric_scores TEXT, feedback TEXT, status TEXT)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_inj_team ON injects(team_id)")
    c.execute("""CREATE TABLE IF NOT EXISTS campaigns(
        id TEXT PRIMARY KEY, name TEXT, start_time REAL, team_ids TEXT,
        specs TEXT, fired TEXT, status TEXT, created_at REAL)""")
    c.commit(); c.close()


_init()


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["rubric"] = json.loads(d.get("rubric") or "[]")
    d["rubric_scores"] = json.loads(d.get("rubric_scores") or "{}")
    return d


def _state(inc: dict, now: float) -> str:
    return model.deadline_state(inc["deadline_at"], now, inc.get("response_at"))


def _insert_inject(c, *, template_id, channel, sender, subject, body, team,
                   now, deadline, rubric) -> str:
    """인젝트 한 건을 인박스에 배달(INSERT)하고 id 반환. dispatch·tick 공용."""
    iid = "INJ-" + uuid.uuid4().hex[:8]
    c.execute("""INSERT INTO injects(id,template_id,channel,sender,subject,body,team_id,
                 delivered_at,deadline_at,rubric,response_text,response_at,score,max_score,
                 rubric_scores,feedback,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
              (iid, template_id, channel, sender, subject, body, team, now, deadline,
               json.dumps(rubric), None, None, None, None, None, None, "delivered"))
    return iid


class DispatchReq(BaseModel):
    template_id: str = ""       # 라이브러리 id (있으면 우선)
    team_ids: list[str] = []
    deadline_min: int = 0       # 0 이면 템플릿/기본값 사용
    # 커스텀(template_id 없을 때)
    channel: str = "media"
    sender: str = ""
    subject: str = ""
    body: str = ""
    rubric: list[dict] = []


class RespondReq(BaseModel):
    team_id: str
    response_text: str


class ScoreReq(BaseModel):
    scores: dict = {}
    feedback: str = ""
    late_penalty: float = 0.5   # 지각 시 배수


class CampaignReq(BaseModel):
    name: str = "ransomware-crisis"
    team_ids: list[str] = []
    specs: list[dict] = []        # 비우면 내장 예시 캠페인 사용
    use_example: bool = False
    start_time: float = 0.0       # 0 이면 로드 시각(now)


class TickReq(BaseModel):
    campaign_id: str = ""         # 비우면 모든 활성 캠페인 진행


@app.get("/health")
def health():
    c = _db(); n = c.execute("SELECT COUNT(*) FROM injects").fetchone()[0]; c.close()
    return {"service": "injects", "injects": n, "library": len(LIBRARY)}


@app.get("/injects/library")
def library(authorization: str = Header(default="")):
    require_read(authorization)
    return {"library": LIBRARY}


@app.post("/injects/dispatch")
async def dispatch(req: DispatchReq, authorization: str = Header(default="")):
    require_role(authorization, {"instructor"})
    if not req.team_ids:
        raise HTTPException(400, "team_ids 가 필요합니다.")
    tpl = _LIB_BY_ID.get(req.template_id) if req.template_id else None
    if req.template_id and not tpl:
        raise HTTPException(404, f"라이브러리에 없는 template_id: {req.template_id}")
    channel = (tpl or {}).get("channel", req.channel)
    if channel not in model.CHANNELS:
        raise HTTPException(400, f"channel must be one of {model.CHANNELS}")
    sender = (tpl or {}).get("from", req.sender)
    subject = (tpl or {}).get("subject", req.subject)
    body = (tpl or {}).get("body", req.body)
    rubric = (tpl or {}).get("rubric", req.rubric)
    dl_min = req.deadline_min or (tpl or {}).get("deadline_min", 30)
    now = time.time(); deadline = now + dl_min * 60
    created = []
    c = _db()
    for team in req.team_ids:
        iid = _insert_inject(c, template_id=req.template_id, channel=channel, sender=sender,
                             subject=subject, body=body, team=team, now=now, deadline=deadline,
                             rubric=rubric)
        created.append({"id": iid, "team_id": team})
    c.commit(); c.close()
    return {"dispatched": len(created), "deadline_min": dl_min, "injects": created}


@app.get("/injects/inbox")
def inbox(team_id: str, authorization: str = Header(default="")):
    require_read(authorization)
    if not team_id:
        raise HTTPException(400, "team_id 필요")
    now = time.time()
    c = _db()
    rows = [_row(r) for r in c.execute(
        "SELECT * FROM injects WHERE team_id=? ORDER BY delivered_at DESC", (team_id,)).fetchall()]
    c.close()
    out = []
    for r in rows:
        st = _state(r, now)
        out.append({"id": r["id"], "channel": r["channel"], "from": r["sender"],
                    "subject": r["subject"], "body": r["body"],
                    "deadline_at": r["deadline_at"], "seconds_left": max(0, int(r["deadline_at"] - now)),
                    "deadline_state": st, "responded": r["response_at"] is not None,
                    "status": r["status"], "score": r["score"], "max_score": r["max_score"]})
    return {"team_id": team_id, "count": len(out), "inbox": out}


def _get(c, iid: str) -> dict:
    r = c.execute("SELECT * FROM injects WHERE id=?", (iid,)).fetchone()
    if not r:
        c.close(); raise HTTPException(404, "inject not found")
    return _row(r)


@app.post("/injects/{iid}/respond")
def respond(iid: str, req: RespondReq, authorization: str = Header(default="")):
    require_role(authorization, {"red", "blue", "instructor"})
    c = _db(); inj = _get(c, iid)
    if inj["team_id"] != req.team_id:
        c.close(); raise HTTPException(403, "이 인젝트는 해당 팀의 것이 아닙니다.")
    if inj["response_at"] is not None:
        c.close(); raise HTTPException(409, "이미 응답했습니다.")
    now = time.time()
    st = model.deadline_state(inj["deadline_at"], now, now)   # 지금 응답 → 정시/지각 판정
    c.execute("UPDATE injects SET response_text=?, response_at=?, status=? WHERE id=?",
              (req.response_text, now, "responded", iid))
    c.commit(); c.close()
    return {"id": iid, "deadline_state": st,
            "on_time": st == "on_time", "responded_at": now}


@app.post("/injects/{iid}/score")
async def score(iid: str, req: ScoreReq, authorization: str = Header(default="")):
    require_role(authorization, {"instructor"})
    c = _db(); inj = _get(c, iid)
    total, max_total = model.rubric_total(inj["rubric"], req.scores)
    late = inj["response_at"] is not None and inj["response_at"] > inj["deadline_at"]
    final = model.apply_late_penalty(total, late, req.late_penalty)
    c.execute("UPDATE injects SET score=?, max_score=?, rubric_scores=?, feedback=?, status=? WHERE id=?",
              (final, max_total, json.dumps(req.scores), req.feedback, "scored", iid))
    c.commit(); c.close()
    await _emit(inj["team_id"], inj["subject"], final, max_total)
    return {"id": iid, "score": final, "max_score": max_total, "raw_total": total,
            "late": late, "late_penalty_applied": late}


async def _emit(team_id: str, subject: str, score_: int, max_: int):
    ev = {"event_id": str(uuid.uuid4()), "event_type": "stage_completed",
          "timestamp": time.time(), "actor": "blue", "team_id": team_id or "default",
          "scenario_id": "default", "target_asset": "crisis_comms", "phase": "objective",
          "metadata": {"source": "injects", "subject": subject, "points": score_,
                       "stage": "inject_response", "max": max_}}
    try:
        async with httpx.AsyncClient(timeout=2.0) as cl:
            await cl.post(f"{EVENT_COLLECTOR_URL}/events", json=ev, headers=service_headers())
    except httpx.HTTPError:
        pass


@app.get("/injects")
def list_all(team_id: str = "", status: str = "", authorization: str = Header(default="")):
    require_read(authorization)
    c = _db(); q = "SELECT * FROM injects"; cond = []; p = []
    if team_id:
        cond.append("team_id=?"); p.append(team_id)
    if status:
        cond.append("status=?"); p.append(status)
    if cond:
        q += " WHERE " + " AND ".join(cond)
    q += " ORDER BY delivered_at DESC"
    now = time.time()
    rows = []
    for r in c.execute(q, p).fetchall():
        d = _row(r); d["deadline_state"] = _state(d, now); rows.append(d)
    c.close()
    return {"count": len(rows), "injects": rows}


@app.get("/injects/scoreboard")
def scoreboard(authorization: str = Header(default="")):
    require_read(authorization)
    now = time.time()
    c = _db(); rows = [_row(r) for r in c.execute("SELECT * FROM injects").fetchall()]; c.close()
    agg: dict[str, dict] = {}
    for r in rows:
        a = agg.setdefault(r["team_id"], {"team_id": r["team_id"], "delivered": 0, "responded": 0,
                                          "on_time": 0, "late": 0, "expired": 0,
                                          "score_sum": 0, "max_sum": 0})
        a["delivered"] += 1
        st = _state(r, now)
        if r["response_at"] is not None:
            a["responded"] += 1
            a["on_time" if st == "on_time" else "late"] += 1
        elif st == "expired":
            a["expired"] += 1
        if r["score"] is not None:
            a["score_sum"] += r["score"]; a["max_sum"] += (r["max_score"] or 0)
    for a in agg.values():
        a["response_rate"] = round(100 * a["responded"] / a["delivered"]) if a["delivered"] else 0
        a["on_time_rate"] = round(100 * a["on_time"] / a["responded"]) if a["responded"] else 0
        a["score_pct"] = round(100 * a["score_sum"] / a["max_sum"]) if a["max_sum"] else 0
    board = sorted(agg.values(), key=lambda x: (-x["score_pct"], -x["response_rate"]))
    return {"scoreboard": board}


def _camp_dict(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["team_ids"] = json.loads(d.get("team_ids") or "[]")
    d["specs"] = json.loads(d.get("specs") or "[]")
    d["fired"] = json.loads(d.get("fired") or "{}")
    return d


def _tick_campaign(c, camp: dict, now: float) -> list[dict]:
    """캠페인 하나를 진행: 발사 예정 스펙을 팀별로 계산해 인박스에 배달. 발사 목록 반환."""
    elapsed = now - camp["start_time"]
    specs = camp["specs"]
    specs_by_id = {s["spec_id"]: s for s in specs}
    fired = camp["fired"]
    out = []
    for team in camp["team_ids"]:
        team_fired = fired.setdefault(team, {})
        # 이 팀의 발사된 인젝트 상태 계산
        states: dict = {}
        for sid, inj_id in team_fired.items():
            r = c.execute("SELECT deadline_at,response_at FROM injects WHERE id=?", (inj_id,)).fetchone()
            if r:
                states[sid] = engine.state_from_inject(r["deadline_at"], r["response_at"], now)
            else:
                states[sid] = engine.InjectState(fired=True)
        for sid in engine.compute_due(specs, elapsed, states):
            resolved = engine.resolve_spec(specs_by_id[sid], _LIB_BY_ID)
            if resolved["channel"] not in model.CHANNELS:
                resolved["channel"] = "internal"
            deadline = now + resolved["deadline_min"] * 60
            iid = _insert_inject(c, template_id=resolved["template_id"], channel=resolved["channel"],
                                 sender=resolved["sender"], subject=resolved["subject"],
                                 body=resolved["body"], team=team, now=now, deadline=deadline,
                                 rubric=resolved["rubric"])
            team_fired[sid] = iid
            trig = specs_by_id[sid].get("trigger") or {}
            out.append({"campaign_id": camp["id"], "team_id": team, "spec_id": sid,
                        "inject_id": iid, "subject": resolved["subject"],
                        "reason": trig.get("on", "scheduled")})
    status = "complete" if engine.campaign_progress(specs, camp["team_ids"], fired)["fired"] >= \
        len(specs) * max(1, len(camp["team_ids"])) else "running"
    c.execute("UPDATE campaigns SET fired=?, status=? WHERE id=?",
              (json.dumps(fired, ensure_ascii=False), status, camp["id"]))
    return out


@app.post("/injects/campaign")
def load_campaign(req: CampaignReq, authorization: str = Header(default="")):
    require_role(authorization, {"instructor"})
    if not req.team_ids:
        raise HTTPException(400, "team_ids 가 필요합니다.")
    specs = EXAMPLE_CAMPAIGN_SPECS if (req.use_example or not req.specs) else req.specs
    seen = set()
    for s in specs:
        if "spec_id" not in s:
            raise HTTPException(400, "각 스펙에 spec_id 가 필요합니다.")
        if s["spec_id"] in seen:
            raise HTTPException(400, f"중복 spec_id: {s['spec_id']}")
        seen.add(s["spec_id"])
    for s in specs:  # 트리거 참조 무결성 검사
        trig = s.get("trigger")
        if trig:
            if trig.get("after") not in seen:
                raise HTTPException(400, f"트리거 after 미존재: {trig.get('after')}")
            if trig.get("on") not in engine.TRIGGER_EVENTS:
                raise HTTPException(400, f"트리거 on 은 {engine.TRIGGER_EVENTS} 중 하나")
    now = time.time()
    cid = "CMP-" + uuid.uuid4().hex[:8]
    start = req.start_time or now
    c = _db()
    c.execute("""INSERT INTO campaigns(id,name,start_time,team_ids,specs,fired,status,created_at)
                 VALUES(?,?,?,?,?,?,?,?)""",
              (cid, req.name, start, json.dumps(req.team_ids, ensure_ascii=False),
               json.dumps(specs, ensure_ascii=False), "{}", "running", now))
    c.commit(); c.close()
    return {"campaign_id": cid, "name": req.name, "team_ids": req.team_ids,
            "specs": len(specs), "start_time": start, "status": "running"}


@app.post("/injects/tick")
def tick(req: TickReq, authorization: str = Header(default="")):
    require_role(authorization, {"instructor"})
    now = time.time()
    c = _db()
    if req.campaign_id:
        rows = c.execute("SELECT * FROM campaigns WHERE id=?", (req.campaign_id,)).fetchall()
        if not rows:
            c.close(); raise HTTPException(404, "campaign not found")
    else:
        rows = c.execute("SELECT * FROM campaigns WHERE status='running'").fetchall()
    fired = []
    for r in rows:
        fired.extend(_tick_campaign(c, _camp_dict(r), now))
    c.commit(); c.close()
    return {"ticked": len(rows), "fired": len(fired), "injects": fired}


@app.get("/injects/campaign/status")
def campaign_status(campaign_id: str = "", authorization: str = Header(default="")):
    require_read(authorization)
    now = time.time()
    c = _db()
    if campaign_id:
        rows = c.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchall()
    else:
        rows = c.execute("SELECT * FROM campaigns ORDER BY created_at DESC").fetchall()
    out = []
    for r in rows:
        camp = _camp_dict(r)
        prog = engine.campaign_progress(camp["specs"], camp["team_ids"], camp["fired"])
        out.append({"campaign_id": camp["id"], "name": camp["name"], "status": camp["status"],
                    "start_time": camp["start_time"], "elapsed_sec": round(now - camp["start_time"]),
                    "team_ids": camp["team_ids"], "progress": prog,
                    "fired": camp["fired"]})
    c.close()
    return {"count": len(out), "campaigns": out}


@app.post("/admin/reset")
def admin_reset(authorization: str = Header(default="")):
    require_role(authorization, {"instructor"})
    c = _db(); n = c.execute("SELECT COUNT(*) FROM injects").fetchone()[0]
    m = c.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
    c.execute("DELETE FROM injects"); c.execute("DELETE FROM campaigns"); c.commit(); c.close()
    return {"service": "injects", "cleared": {"injects": n, "campaigns": m}}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8096)
