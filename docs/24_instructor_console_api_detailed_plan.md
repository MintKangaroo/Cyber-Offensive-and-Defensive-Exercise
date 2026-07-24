# Instructor Console API — 상세 구현 계획 (04번 문서 4절의 실행 사양)

> Config Service에는 이미 patch/quarantine/killswitch + audit이 있다(구현 완료).
> 여기서는 **아직 없는** 시나리오 시작/종료, 이벤트 수동주입, 점수 수동조정을 신규 서비스로
> 설계하고, 이를 위해 scoring_engine/scenario_engine에 추가해야 할 엔드포인트까지 명시한다.

---

## 0. 서비스 배치 결정

새 서비스 `services/instructor_api/`(포트 8050, `api_contract.py`의 `Ports.INSTRUCTOR_API`와 일치)를
둔다. 이 서비스는 로직을 직접 갖지 않고 **오케스트레이션 레이어**로만 동작한다 — 실제 상태 변경은
각 도메인 서비스(scenario_engine/scoring_engine/event_collector)가 하고, Instructor API는
"교관 인증 확인 + 여러 서비스 호출 + 통합 audit"만 담당한다.

```
services/instructor_api/
├─ main.py
└─ audit_store.py   # 이 서비스 자체의 audit 기록(scenario/event/score 액션용)
```

**이유**: Config Service의 audit은 patch/quarantine/killswitch 전용으로 이미 굳어있음(구현 완료
상태를 건드리지 않기 위해 분리). 대시보드의 `AuditLogView`는 두 소스를 합쳐서 보여준다
(6절 참고).

---

## 1. scoring_engine에 추가할 엔드포인트

```python
# scoring_engine/main.py 에 추가

class ScoreAdjustRequest(BaseModel):
    team_id: str
    scenario_id: str = "default"
    actor: str          # "red" | "blue"
    delta: int           # 음수 허용(감점)
    reason: str          # 필수

@app.post("/score/adjust")
def adjust_score(req: ScoreAdjustRequest):
    if not req.reason.strip():
        raise HTTPException(400, "reason is required")
    conn = get_db()
    adjustment_id = str(uuid.uuid4())
    # achievements에도 기록 -> reconcile(정합성 감사)이 수동조정까지 포함해서 계산되게 함
    conn.execute(
        "INSERT INTO achievements (achievement_key, team_id, scenario_id, actor, category, points, source_event_id) "
        "VALUES (?, ?, ?, ?, 'manual_adjustment', ?, ?)",
        (f"manual:{adjustment_id}", req.team_id, req.scenario_id, req.actor, req.delta, adjustment_id),
    )
    conn.execute(
        """INSERT INTO team_scores (team_id, scenario_id, actor, score) VALUES (?, ?, ?, ?)
           ON CONFLICT(team_id, scenario_id, actor) DO UPDATE SET score = score + excluded.score""",
        (req.team_id, req.scenario_id, req.actor, req.delta),
    )
    conn.commit()
    conn.close()
    return {"adjustment_id": adjustment_id, "new_delta": req.delta}
```
**정합성 포인트**: 수동조정도 achievements 테이블에 들어가므로 이미 구현된 `/scores/reconcile`이
수동조정까지 포함해 자동으로 검증 대상에 넣는다(추가 코드 불필요 — 기존 reconcile 쿼리가
`WHERE points > 0`로 되어 있었다면 감점(음수)도 잡히도록 조건을 `points != 0`으로 수정 필요).

---

## 2. scenario_engine에 추가할 엔드포인트

`services/scenario_engine/`는 지금 라이브러리(loader/runner) 형태다. 교관이 호출할 수 있도록
얇은 FastAPI 래퍼를 씌운다.

```python
# services/scenario_engine/api.py (신규)

_active_trackers: dict[str, SingleScenarioTracker | CrossoverScenarioTracker] = {}

@app.post("/scenario/activate")
async def activate_scenario(scenario_id: str, team_ids: list[str]):
    loaded = load_all_scenarios("scenarios/")[scenario_id]
    tracker = make_tracker(loaded, emit_event_fn=emit_event_async)
    _active_trackers[scenario_id] = tracker
    await inject_initial_state(loaded, config_client)  # 04번 5절 Config Service 연동
    await emit_event_async(event_type="scenario_started", actor="system",
                           target_asset=(loaded.single or loaded.crossover).target_asset,
                           scenario_id=scenario_id, metadata={"team_ids": team_ids})
    return {"scenario_id": scenario_id, "status": "active"}

@app.post("/scenario/deactivate")
async def deactivate_scenario(scenario_id: str):
    tracker = _active_trackers.pop(scenario_id, None)
    if tracker is None:
        raise HTTPException(404, "scenario not active")
    await emit_event_async(event_type="scenario_ended", actor="system",
                           scenario_id=scenario_id, target_asset="", metadata={})
    return {"scenario_id": scenario_id, "status": "ended"}

@app.get("/scenario/{scenario_id}/progress")
def scenario_progress(scenario_id: str, team_id: str):
    tracker = _active_trackers.get(scenario_id)
    if tracker is None:
        raise HTTPException(404, "scenario not active")
    if isinstance(tracker, CrossoverScenarioTracker):
        return tracker.get_progress_summary(team_id)
    return {"completed_stages": list(tracker._get(team_id).completed_stages.keys())}
```
이 API가 Event Collector의 WS를 구독해 `tracker.process_event()`를 호출하는 백그라운드 태스크도
`services/scenario_engine/api.py`의 startup 이벤트에 둔다(패턴은 noc_monitor의 `_subscribe_
compromise_events`와 동일).

---

## 3. Instructor API 본체

```python
# services/instructor_api/main.py

SCENARIO_ENGINE_URL = "http://scenario_engine:8040"   # 포트는 배치 시 확정
SCORING_ENGINE_URL = "http://scoring_engine:8020"
EVENT_COLLECTOR_URL = "http://event_collector:8010"

def _require_instructor(authorization: str) -> str: ...  # config_service와 동일 패턴 재사용

@app.post("/instructor/scenario/start")
async def scenario_start(req: ScenarioStartRequest, authorization: str = Header(default="")):
    actor = _require_instructor(authorization)
    async with httpx.AsyncClient() as client:
        r = await client.post(f"{SCENARIO_ENGINE_URL}/scenario/activate",
                              json={"scenario_id": req.scenario_id, "team_ids": req.team_ids})
    audit_store.record(actor, "scenario_start", req.scenario_id, req.reason)
    return r.json()

@app.post("/instructor/scenario/end")
async def scenario_end(req: ScenarioEndRequest, authorization: str = Header(default="")):
    actor = _require_instructor(authorization)
    async with httpx.AsyncClient() as client:
        r = await client.post(f"{SCENARIO_ENGINE_URL}/scenario/deactivate",
                              json={"scenario_id": req.scenario_id})
    audit_store.record(actor, "scenario_end", req.scenario_id, req.reason)
    return r.json()

@app.post("/instructor/event/inject")
async def event_inject(req: EventInjectRequest, authorization: str = Header(default="")):
    actor = _require_instructor(authorization)
    payload = req.model_dump()
    payload["actor"] = "system"  # 교관 주입임을 명확히(Red/Blue 자동발생과 구분)
    payload["metadata"] = {**payload.get("metadata", {}), "injected_by_instructor": True}
    async with httpx.AsyncClient() as client:
        r = await client.post(f"{EVENT_COLLECTOR_URL}/events", json=payload)
    audit_store.record(actor, "event_inject", payload.get("event_type", "?"), req.reason)
    return r.json()

@app.post("/instructor/score/adjust")
async def score_adjust(req: ScoreAdjustProxyRequest, authorization: str = Header(default="")):
    actor = _require_instructor(authorization)
    async with httpx.AsyncClient() as client:
        r = await client.post(f"{SCORING_ENGINE_URL}/score/adjust", json=req.model_dump())
    audit_store.record(actor, "score_adjust", f"{req.team_id}:{req.actor}:{req.delta}", req.reason)
    return r.json()

@app.get("/instructor/audit")
def get_audit(limit: int = 200):
    return {"entries": audit_store.list(limit)}
```

### `audit_store.py`
```python
# config_service의 _audit()과 동일한 append-only 패턴, 별도 SQLite 파일
def record(actor: str, action: str, target: str, reason: str) -> None: ...
def list(limit: int) -> list[dict]: ...
```

**요청 모델(전부 reason 필수 — pydantic validator로 강제)**:
```python
class ScenarioStartRequest(BaseModel):
    scenario_id: str
    team_ids: list[str]
    reason: str

class ScenarioEndRequest(BaseModel):
    scenario_id: str
    reason: str

class EventInjectRequest(BaseModel):
    event_type: str
    target_asset: str
    team_id: str = "default"
    scenario_id: str = "default"
    vuln_id: str | None = None
    metadata: dict = {}
    reason: str

class ScoreAdjustProxyRequest(BaseModel):
    team_id: str
    scenario_id: str = "default"
    actor: str
    delta: int
    reason: str
```

---

## 4. 인증 방식 (MVP -> 확장 경로)

- **MVP**: Config Service와 동일하게 단일 `INSTRUCTOR_TOKEN` 환경변수 Bearer 비교.
- **확장(대회 규모 커지면)**: JWT 기반 역할(role: instructor/red/blue/observer) 발급,
  Instructor API뿐 아니라 Event Collector/Scoring Engine의 조회 API도 역할별 스코프 필터링
  (07번 문서 2절 "역할별 뷰"가 실제로 치팅 방지가 되려면 이 확장이 필수 — MVP 토큰 방식은
  "교관이냐 아니냐"만 구분하고 Red/Blue/Observer 구분은 아직 못 함).

---

## 5. 대시보드 연동 지점 (23번 문서 7절과 연결)

`InstructorConsole.tsx`가 호출할 엔드포인트:
```
POST http://instructor_api:8050/instructor/scenario/start
POST http://instructor_api:8050/instructor/scenario/end
POST http://instructor_api:8050/instructor/event/inject
POST http://instructor_api:8050/instructor/score/adjust
GET  http://instructor_api:8050/instructor/audit
```

`AuditLogView.tsx`는 이 엔드포인트와 Config Service의 `/instructor/audit`를 **둘 다 호출해
시간순으로 병합** — 프론트에서 두 배열을 합쳐 정렬하면 됨(백엔드 통합은 다음 단계 제안 참고).

---

## 6. 다음 단계 제안 (통합 audit 뷰)

지금 설계는 audit이 Config Service와 Instructor API 두 곳에 나뉜다. 대회 규모가 커지면
`GET /audit/unified` 하나로 합치는 조회 전용 서비스(또는 Instructor API가 Config Service의
audit도 프록시해서 합쳐 반환)를 추가하는 게 좋다 — 지금 단계에서는 프론트 병합으로 충분.

---

## 7. 마일스톤

| 마일스톤 | 내용 | 완료 판정 | 상태 |
|---|---|---|---|
| M-Instr.1 | scoring_engine `/score/adjust` 추가 | curl로 감점 → `/scores`에 반영, `/scores/reconcile` 정합 유지 | ✅ 구현+검증 완료(감점 포함 reconcile 정합성 실제 SQL로 확인) |
| M-Instr.2 | scenario_engine에 FastAPI 래퍼(`api.py`) | `/scenario/activate` 호출 → 초기 취약점 상태가 Config Service에 반영 | ✅ 구현 완료(services/scenario_engine/api.py) |
| M-Instr.3 | Instructor API 신규 서비스 | 4개 엔드포인트 전부 reason 없으면 400, 있으면 정상 동작 + audit 기록 | ✅ 구현 완료. audit_store는 실제 SQLite 기록/최신순 조회 검증 완료 |
| M-Instr.4 | 대시보드 InstructorConsole 연동 | 대시보드에서 시나리오 시작 클릭 → 실제로 트윈 취약점 상태 바뀜 | ⬜ 대시보드(23번 문서) 구현 후 진행 |
