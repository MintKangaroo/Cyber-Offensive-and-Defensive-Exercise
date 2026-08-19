"""
Scenario Engine API (24번 문서 2절)
=====================================
scenario_engine의 loader/runner는 지금까지 라이브러리 형태였다. 교관(Instructor API)이
호출할 수 있도록 얇은 FastAPI 래퍼를 씌운다. 실제 판정 로직은 전부 runner.py에 있고,
여기는 (1) 이벤트 스트림 구독을 백그라운드로 돌리고 (2) 활성화/비활성화/조회 API만 제공한다.

실행: uvicorn services.scenario_engine.api:app --port 8045
"""
from __future__ import annotations
import asyncio
import json
import os
import time
from pathlib import Path
from typing import Optional

import httpx
import websockets
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from shared.lifespan import on_startup

from .loader import load_all_scenarios, inject_initial_state, LoadedScenario
from .runner import make_tracker, SingleScenarioTracker, CrossoverScenarioTracker

SCENARIOS_DIR = os.environ.get("SCENARIOS_DIR", str(Path(__file__).parent.parent.parent / "scenarios"))
EVENT_COLLECTOR_URL = os.environ.get("EVENT_COLLECTOR_URL", "http://event_collector:8010")
EVENT_COLLECTOR_WS_URL = os.environ.get("EVENT_COLLECTOR_WS_URL", "ws://event_collector:8010/ws")
CONFIG_SERVICE_URL = os.environ.get("CONFIG_SERVICE_URL", "http://config_service:8030")
INSTRUCTOR_TOKEN = os.environ.get("INSTRUCTOR_TOKEN", "")

app = FastAPI(title="Scenario Engine API")

_all_scenarios: dict[str, LoadedScenario] = {}
_active_trackers: dict[str, object] = {}  # scenario_id -> Single/CrossoverScenarioTracker
_ws_task: Optional[asyncio.Task] = None


class ConfigClientAsync:
    """loader.inject_initial_state가 기대하는 인터페이스(set_patch)의 async httpx 구현."""

    async def set_patch(self, asset: str, vuln_id: str, patched: bool, reason: str) -> None:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(
                    f"{CONFIG_SERVICE_URL}/instructor/patch/toggle",
                    json={"asset": asset, "vuln_id": vuln_id, "patched": patched, "reason": reason},
                    headers={"Authorization": f"Bearer {INSTRUCTOR_TOKEN}"},
                )
        except httpx.HTTPError:
            pass  # Config Service 다운이어도 시나리오 활성화 자체는 계속 진행(모든 로그는 남지 않음에 유의)


_config_client = ConfigClientAsync()


async def _emit_event_async(**kwargs) -> None:
    """runner.py의 tracker들이 stage_completed/chain_bonus 등을 발행할 때 호출."""
    payload = {
        "event_id": kwargs.get("event_id"),
        "event_type": kwargs.get("event_type").value if hasattr(kwargs.get("event_type"), "value") else kwargs.get("event_type"),
        "actor": kwargs.get("actor"),
        "target_asset": kwargs.get("target_asset"),
        "team_id": kwargs.get("team_id", "default"),
        "scenario_id": kwargs.get("scenario_id", "default"),
        "metadata": kwargs.get("metadata", {}),
    }
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(f"{EVENT_COLLECTOR_URL}/events", json=payload, headers=service_headers())
    except httpx.HTTPError:
        pass


async def _route_event(event: dict) -> None:
    """이벤트를 알맞은 활성 트래커(들)에 전달.

    라우팅 규칙:
    - 이벤트의 scenario_id가 활성 트래커 키와 정확히 일치하면 그 트래커로 전달
      (트래커 자신이 발행한 stage_completed/chain_bonus 등이 여기 해당).
    - 트윈이 발행하는 실제 공격 이벤트는 scenario_id를 모른 채 "default"로 나온다.
      트윈은 어떤 시나리오가 활성인지 알 수 없으므로, 이런 이벤트는 target_asset으로
      라우팅한다: single 시나리오는 target_asset이 일치할 때만, crossover 시나리오는
      여러 자산에 걸치므로 항상 전달한다. 각 트래커의 process_event가 자신의 stage
      match(event_type + vuln_id 등)로 다시 필터하므로 오탐/오완료는 발생하지 않는다.
    """
    sid = event.get("scenario_id", "default")
    exact = _active_trackers.get(sid) if sid != "default" else None
    if exact is not None:
        await exact.process_event(event)
        return
    asset = event.get("target_asset")
    for tracker in list(_active_trackers.values()):
        if isinstance(tracker, CrossoverScenarioTracker):
            await tracker.process_event(event)
        elif isinstance(tracker, SingleScenarioTracker) and tracker.scenario.target_asset == asset:
            await tracker.process_event(event)


async def _event_stream_loop() -> None:
    """Event Collector WS를 구독해 활성 시나리오 트래커들에 이벤트를 흘려보낸다.
    재연결 백오프 포함(연결이 끊겨도 시나리오 판정이 영구히 멈추지 않게)."""
    backoff = 1.0
    while True:
        try:
            async with websockets.connect(EVENT_COLLECTOR_WS_URL) as ws:
                backoff = 1.0
                async for message in ws:
                    event = json.loads(message)
                    await _route_event(event)
        except Exception:
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 15.0)


@on_startup(app)
async def startup():
    global _ws_task
    _all_scenarios.update(load_all_scenarios(SCENARIOS_DIR))
    _ws_task = asyncio.create_task(_event_stream_loop())


@app.get("/health")
def health():
    return {"status": "ok", "service": "scenario_engine", "loaded_scenarios": list(_all_scenarios.keys())}


class ActivateRequest(BaseModel):
    scenario_id: str
    team_ids: list[str] = []


@app.post("/scenario/activate")
async def activate_scenario(req: ActivateRequest):
    if req.scenario_id in _active_trackers:
        raise HTTPException(409, f"scenario '{req.scenario_id}' is already active")
    loaded = _all_scenarios.get(req.scenario_id)
    if loaded is None:
        raise HTTPException(404, f"scenario '{req.scenario_id}' not found in {SCENARIOS_DIR}")

    tracker = make_tracker(loaded, emit_event_fn=_emit_event_async)
    _active_trackers[req.scenario_id] = tracker

    await inject_initial_state(loaded, _config_client)

    target_asset = (loaded.single or loaded.crossover).target_asset
    await _emit_event_async(
        event_id=f"scenario-start-{req.scenario_id}-{int(time.time())}",
        event_type="scenario_started", actor="system", target_asset=target_asset,
        scenario_id=req.scenario_id, metadata={"team_ids": req.team_ids},
    )
    return {"scenario_id": req.scenario_id, "status": "active", "kind": loaded.kind}


class DeactivateRequest(BaseModel):
    scenario_id: str


@app.post("/scenario/deactivate")
async def deactivate_scenario(req: DeactivateRequest):
    tracker = _active_trackers.pop(req.scenario_id, None)
    if tracker is None:
        raise HTTPException(404, f"scenario '{req.scenario_id}' is not active")
    loaded = _all_scenarios.get(req.scenario_id)
    target_asset = (loaded.single or loaded.crossover).target_asset if loaded else ""
    await _emit_event_async(
        event_id=f"scenario-end-{req.scenario_id}-{int(time.time())}",
        event_type="scenario_ended", actor="system", target_asset=target_asset,
        scenario_id=req.scenario_id, metadata={},
    )
    return {"scenario_id": req.scenario_id, "status": "ended"}


@app.get("/scenario/{scenario_id}/progress")
def scenario_progress(scenario_id: str, team_id: str = "default"):
    tracker = _active_trackers.get(scenario_id)
    if tracker is None:
        raise HTTPException(404, f"scenario '{scenario_id}' is not active")
    if hasattr(tracker, "get_progress_summary"):
        return tracker.get_progress_summary(team_id)
    # SingleScenarioTracker
    progress = tracker._get(team_id)  # noqa: SLF001 (내부 상태 조회용, 조회 전용 API라 허용)
    return {
        "completed_stages": list(progress.completed_stages.keys()),
        "chain_bonus_awarded": progress.chain_bonus_awarded,
    }


class ObjectiveSubmitReq(BaseModel):
    team_id: str = "default"
    phase: str
    objective: str          # objective의 name 또는 submit 키
    value: str              # 참가자가 제출한 값


@app.post("/scenario/{scenario_id}/objective/submit")
async def submit_objective(scenario_id: str, req: ObjectiveSubmitReq):
    """감사 4.9: 크로스오버(조사형) 목표 제출 API. 정답은 서버측 objective.answer에서 조회해
    채점한다(정답을 클라이언트가 넘기지 않음). 크로스오버 트래커에만 존재."""
    tracker = _active_trackers.get(scenario_id)
    if tracker is None:
        raise HTTPException(404, f"scenario '{scenario_id}' is not active")
    if not hasattr(tracker, "submit_objective"):
        raise HTTPException(400, "이 시나리오는 조사형 목표 제출을 지원하지 않습니다(크로스오버 전용).")
    try:
        ok = await tracker.submit_objective(req.team_id, req.phase, req.objective, req.value)
    except KeyError:
        raise HTTPException(404, f"phase '{req.phase}' 없음")
    return {"scenario_id": scenario_id, "phase": req.phase, "objective": req.objective, "correct": ok}


@app.get("/scenario/list")
def list_scenarios():
    return {
        "available": list(_all_scenarios.keys()),
        "active": list(_active_trackers.keys()),
    }


# --- 저작 지원(P1-3): 검증(dry-run)·린트·페이즈 클록 ---------------------------
import yaml  # noqa: E402
from .authoring import dry_run, lint_scenario, phase_clock  # noqa: E402
from shared.service_auth import service_headers


class ValidateReq(BaseModel):
    yaml: str


def _scenario_dict(doc: dict) -> dict:
    """YAML 문서에서 scenario 하위 딕셔너리 추출(단일/크로스오버 루트 허용)."""
    return doc.get("scenario") or doc.get("crossover_scenario") or {}


def _raw_scenarios() -> dict[str, dict]:
    """scenarios/ 의 원본 scenario 딕셔너리(저작 검증용, 파싱된 모델과 별개)."""
    out: dict[str, dict] = {}
    for p in Path(SCENARIOS_DIR).rglob("*.yaml"):
        try:
            for doc in yaml.safe_load_all(p.read_text()):
                if not doc:
                    continue
                sc = _scenario_dict(doc)
                if sc.get("id"):
                    out[sc["id"]] = sc
        except (yaml.YAMLError, OSError):
            continue
    return out


@app.post("/scenario/validate")
def scenario_validate(req: ValidateReq):
    """YAML 텍스트를 저장/실행 없이 검증 + 타임라인 투영(dry-run). 저작 UI의 핵심."""
    try:
        doc = yaml.safe_load(req.yaml)
    except yaml.YAMLError as e:
        raise HTTPException(400, f"YAML 파싱 오류: {e}")
    if not isinstance(doc, dict):
        raise HTTPException(400, "YAML 최상위는 매핑이어야 합니다(scenario: ...).")
    sc = _scenario_dict(doc)
    if not sc:
        raise HTTPException(400, "scenario 또는 crossover_scenario 루트 키가 필요합니다.")
    return dry_run(sc)


@app.get("/scenario/lint-all")
def scenario_lint_all():
    """저장된 전 시나리오 린트(CI 게이트용). error 가 하나라도 있으면 ok=False."""
    raw = _raw_scenarios()
    report = {}
    total_err = 0
    for sid, sc in raw.items():
        issues = lint_scenario(sc)
        errs = [i for i in issues if i["level"] == "error"]
        total_err += len(errs)
        report[sid] = {"errors": len(errs),
                       "warnings": len([i for i in issues if i["level"] == "warning"]),
                       "issues": issues}
    return {"ok": total_err == 0, "scenarios": len(raw), "total_errors": total_err, "report": report}


@app.get("/scenario/{scenario_id}/phase-clock")
def scenario_phase_clock(scenario_id: str, elapsed_sec: float = 0):
    """경과 시간 → 현재 예상 stage·잔여(교관 페이싱용 페이즈 클록)."""
    sc = _raw_scenarios().get(scenario_id)
    if not sc:
        raise HTTPException(404, f"scenario not found: {scenario_id}")
    return phase_clock(sc, elapsed_sec)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8045)
