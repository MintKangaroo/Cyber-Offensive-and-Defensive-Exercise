"""
Instructor API (24번 문서 0·3절)
===================================
교관 콘솔이 호출하는 단일 진입점. 이 서비스 자체는 상태를 거의 갖지 않고
scenario_engine / scoring_engine / event_collector를 오케스트레이션 + 인증 확인 +
통합 audit 기록만 담당한다(0절의 설계 결정).

실행: uvicorn services.instructor_api.main:app --port 8050
"""
from __future__ import annotations
import os
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

from . import audit_store

SCENARIO_ENGINE_URL = os.environ.get("SCENARIO_ENGINE_URL", "http://scenario_engine:8045")
SCORING_ENGINE_URL = os.environ.get("SCORING_ENGINE_URL", "http://scoring_engine:8020")
EVENT_COLLECTOR_URL = os.environ.get("EVENT_COLLECTOR_URL", "http://event_collector:8010")
INSTRUCTOR_TOKEN = os.environ.get("INSTRUCTOR_TOKEN", "")

app = FastAPI(title="Instructor API")

# Live Fire 대시보드(로컬 dev 5174 등)의 교관 콘솔이 브라우저에서 직접 호출하므로 CORS 필요.
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
app.add_middleware(
    CORSMiddleware, allow_origin_regex=r"https?://(localhost|127\.0\.0\.1|(\d{1,3}\.){3}\d{1,3}|[\w-]+\.ts\.net)(:\d+)?",
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)


from shared.rbac import require_role  # noqa: E402


def _require_instructor(authorization: str) -> str:
    """교관 전용 액션 인가(RBAC). instructor 역할만 허용. 24번 문서 4절.
    (하위호환: INSTRUCTOR_TOKEN만 설정된 환경은 그 토큰=instructor로 동작.)"""
    return require_role(authorization, {"instructor"}).actor


class ScenarioStartRequest(BaseModel):
    scenario_id: str
    team_ids: list[str] = []
    reason: str


class ScenarioEndRequest(BaseModel):
    scenario_id: str
    reason: str


class EventInjectRequest(BaseModel):
    event_type: str
    target_asset: str
    team_id: str = "default"
    scenario_id: str = "default"
    vuln_id: Optional[str] = None
    metadata: dict = {}
    reason: str


class ScoreAdjustProxyRequest(BaseModel):
    team_id: str
    scenario_id: str = "default"
    actor: str
    delta: int
    reason: str


@app.get("/health")
def health():
    return {"status": "ok", "service": "instructor_api"}


@app.post("/instructor/scenario/start")
async def scenario_start(req: ScenarioStartRequest, authorization: str = Header(default="")):
    if not req.reason.strip():
        raise HTTPException(400, "reason is required")
    actor = _require_instructor(authorization)
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{SCENARIO_ENGINE_URL}/scenario/activate",
                json={"scenario_id": req.scenario_id, "team_ids": req.team_ids},
            )
            r.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, e.response.text)
    except httpx.HTTPError as e:
        raise HTTPException(502, f"scenario_engine call failed: {e}")

    audit_store.record(actor, "scenario_start", req.scenario_id, req.reason)
    return r.json()


@app.post("/instructor/scenario/end")
async def scenario_end(req: ScenarioEndRequest, authorization: str = Header(default="")):
    if not req.reason.strip():
        raise HTTPException(400, "reason is required")
    actor = _require_instructor(authorization)
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{SCENARIO_ENGINE_URL}/scenario/deactivate", json={"scenario_id": req.scenario_id}
            )
            r.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, e.response.text)
    except httpx.HTTPError as e:
        raise HTTPException(502, f"scenario_engine call failed: {e}")

    audit_store.record(actor, "scenario_end", req.scenario_id, req.reason)
    return r.json()


@app.post("/instructor/event/inject")
async def event_inject(req: EventInjectRequest, authorization: str = Header(default="")):
    if not req.reason.strip():
        raise HTTPException(400, "reason is required")
    actor = _require_instructor(authorization)

    payload = req.model_dump(exclude={"reason"})
    payload["actor"] = "system"  # 교관 주입임을 명확히(Red/Blue 자동발생과 구분)
    payload["metadata"] = {**payload.get("metadata", {}), "injected_by_instructor": True}
    payload["event_id"] = f"instructor-inject-{actor}-{req.event_type}-{req.target_asset}"

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(f"{EVENT_COLLECTOR_URL}/events", json=payload)
            r.raise_for_status()
    except httpx.HTTPError as e:
        raise HTTPException(502, f"event_collector call failed: {e}")

    audit_store.record(actor, "event_inject", req.event_type, req.reason)
    return r.json()


@app.post("/instructor/score/adjust")
async def score_adjust(req: ScoreAdjustProxyRequest, authorization: str = Header(default="")):
    if not req.reason.strip():
        raise HTTPException(400, "reason is required")
    actor = _require_instructor(authorization)

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                f"{SCORING_ENGINE_URL}/score/adjust",
                json=req.model_dump(),   # scoring_engine의 ScoreAdjustRequest도 reason을 그대로 받음
                # S2S: scoring의 RBAC(instructor 전용)를 통과하도록 자체 INSTRUCTOR_TOKEN을 실어보낸다.
                headers={"Authorization": f"Bearer {INSTRUCTOR_TOKEN}"},
            )
            r.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise HTTPException(e.response.status_code, e.response.text)
    except httpx.HTTPError as e:
        raise HTTPException(502, f"scoring_engine call failed: {e}")

    audit_store.record(actor, "score_adjust", f"{req.team_id}:{req.actor}:{req.delta}", req.reason)
    return r.json()


@app.get("/instructor/audit")
def get_audit(limit: int = 200):
    return {"entries": audit_store.list_entries(limit)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8050)
