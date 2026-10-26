# Live-Fire Ops Console (`dashboards/livefire-ops`)

CCE/Locked Shields 방송톤의 **몰입형 Red 라이브파이어 작전 콘솔**. 2단 구조:

1. **국가 기반시설 현황 아레나** — 방사형 돔 + 시설 노드 성좌, 타이머 3종, 스코어보드, Solve Log.
2. **시설별 작전 콘솔** — 노드 클릭 드릴다운. OT 침투맵 · 물리 트윈 스키매틱 · 라이브 레지스터
   테이블 · 서비스 상태 · 킬체인 셰브론 · EXECUTE STRIKE.

플래그 제출 UI 가 아니라, 공격 행위가 **실제 ICS 트윈의 물리 상태**(터빈 RPM·냉각수·SIS·DAMAGE 등)에
즉시 반영되는 라이브 경험. 자산명·프로토콜·포트·레지스터·취약점 ID·점수는 모두 실제 코드에서 가져온다.

디자인 계약은 [`DESIGN.md`](./DESIGN.md) 참조(red↔blue 듀얼리티·플랫 하드엣지 패널·브래킷 HUD·tri-font).

## 빌드 / 테스트

```bash
npm install
npm run dev        # 개발 서버
npm run build      # tsc -b && vite build → dist/
npx vitest run     # 유닛/계약/접근성 테스트
```

## 라이브 트윈 연결

콘솔은 선택된 섹터의 트윈에 대해 (1) `/api/telemetry` 를 1.5초 간격 폴링해 게이지를 움직이고,
(2) 킬체인 `EXECUTE STRIKE` 가 트윈의 공격 엔드포인트를 호출해 실제 물리 파국을 유발하며,
(3) `event_collector` SSE `/stream` 으로 스트라이크/점수/타이머를 받는다. 트윈 미도달 시 정적
데모(mock)로 폴백한다(오프라인에서도 UI 동작, 상태 badge 가 `DEMO`/`LIVE` 로 표시).

트윈 URL 주입(빌드 타임, Vite 환경변수):

| 변수 | 대상 | 기본값 |
|---|---|---|
| `VITE_COLLECTOR_URL` | event_collector | `http://localhost:8010` |
| `VITE_POWER_TWIN_URL` | 발전소 트윈 | `http://localhost:8002` |
| `VITE_TWIN_<SECTOR>` | 그 외 섹터 트윈 | 미설정 시 폴백 |

`<SECTOR>` 는 대문자 섹터 id(예: `VITE_TWIN_WATER`, `VITE_TWIN_HOSPITAL`). 미설정 섹터는
라이브로 표시하지 않는다(정직 — no-op 애니메이션 금지).

### 예: 상수도 섹터 라이브(E2E 검증됨)

```bash
# 1) 상수도 트윈 기동
PYTHONPATH="$REPO" RBAC_ALLOW_INSECURE_DEV=true \
  python3 -m uvicorn services.water_utility.main:app --host 127.0.0.1 --port 8203

# 2) 콘솔을 트윈 URL 로 빌드 후 서브
echo 'VITE_TWIN_WATER=http://127.0.0.1:8203' > .env.local   # .gitignore 아님 — 커밋 금지
npm run build && npx vite preview --port 5177
# → http://localhost:5177/?v=facility&sector=water
```

콘솔 킬체인(SCADA HMI 기본계정 → 펌프 제어 → 염소 과투입 → **SIS 무력화**)을 실행하면 상수도
트윈이 실제로 구동된다: 안전 인터록(SIS)이 ARMED 인 동안은 `RESERVOIR_PPM` 이 redline(4ppm)에서
캡되고, `/api/safety/override` 로 SIS 를 BYPASS 하면 염소 과투입이 지속돼 `RESERVOIR_PPM` 이
한계를 넘고 `CONTAMINATION` 이 누적, `CATASTROPHIC_FAILURE`(급수 오염 파국)에 도달한다 —
콘솔 게이지·푸터 티커가 이를 라이브로 반영.

### 예: 병원 섹터 라이브(E2E 검증됨)

```bash
# 1) 병원 트윈 기동 (MODBUS_PORT 는 502 특권포트 회피용 고포트)
PYTHONPATH="$REPO" RBAC_ALLOW_INSECURE_DEV=true MODBUS_PORT=8508 \
  python3 -m uvicorn services.hospital_ot.main:app --host 127.0.0.1 --port 8208

# 2) 콘솔을 트윈 URL 로 빌드 후 서브
echo 'VITE_TWIN_HOSPITAL=http://127.0.0.1:8208' > .env.local   # .gitignore 아님 — 커밋 금지
npm run build && npx vite preview --port 5177
# → http://localhost:5177/?v=facility&sector=hospital
```

콘솔 킬체인(HIS 환자정보 SQLi → PACS 영상 IDOR → **주입펌프 과투여(RATE 900)** → **SIS 무력화**)을
실행하면 병원 트윈이 실제로 구동된다: SIS 가 ARMED 인 동안은 주입펌프 명령(900mL/h)이 `INFUSION_RATE`
에 반영돼도 `ACTUAL` 은 redline(200mL/h)에서 캡되고 손상 0 이다. `/api/safety/override` 로 SIS 를
BYPASS 하면 `ACTUAL` 이 redline 을 넘어 900 까지 치솟고 `DAMAGE` 가 누적, `CATASTROPHIC_FAILURE`
(약물 과투여 환자안전 파국)에 도달한다 — 콘솔 게이지·`05 IMPACT`·푸터 티커가 라이브로 반영.

> **라이브 게이지 전제**: 게이지가 '움직이는' 것은 트윈의 배경 물리 루프(`attach_modbus_ics._sim_loop`)
> 때문이다. 이 루프는 `MODBUS_ENABLED`(기본 `1`)일 때만 스케줄된다. 유닛 테스트처럼 `MODBUS_ENABLED=0`
> 으로 띄우면 502 리스너뿐 아니라 물리 루프도 꺼져 `ACTUAL`/`DAMAGE` 가 정지한다(명령 `cmd` 만 반영).

## 섹터 라이브 커버리지

- **발전소(power)** — 전용 트윈, 완전 라이브(냉각수/온도 포함). 기함 수직 슬라이스.
- **상수도(water)·병원(hospital)** — 통일 `/api/telemetry` 규약, 킬체인 전 단계 라이브 액션.
  둘 다 콘솔 EXECUTE STRIKE 구동으로 ARMED 캡 → SIS BYPASS → 물리 파국까지 **E2E 검증됨**.
  엔드포인트는 실제 트윈 라우트와 일치(회귀: `src/sector-live.test.tsx` +
  `tests/unit/test_twin_telemetry.py` · `test_twin_safety_override.py` · `test_twin_sim_loop.py`
  — 마지막은 배경 물리 루프가 뱅크/파국 플래그를 실제로 구동함을 고정).
- **그 외 섹터** — 아레나 노드로 표시, 콘솔은 확장 패턴(트윈 + `VITE_TWIN_<SECTOR>` 추가 시 라이브).

## 라이브 타이머 (phase_clock 오케스트레이션)

아레나의 **TIME REMAINING·NEXT ATTACK** 과 시설 콘솔의 **T+ ENGAGE** 는 정적 카운트다운이 아니라,
`event_collector` 의 `phase_clock` 토픽을 SSE 로 구독해 실시간으로 움직인다. 이 토픽에 프레임을
1초 간격으로 미는 주체는 `scenario_engine` 의 `_phase_clock_loop` 이고, 루프는 **활성 시나리오가
있을 때만** 발행한다. 시나리오를 활성화하는 경로는 `POST /scenario/activate`(instructor) 하나다.

```bash
# 1) event_collector(:8010) + scenario_engine(:8045) 기동
PYTHONPATH="$REPO" RBAC_ALLOW_INSECURE_DEV=true \
  python3 -m uvicorn services.event_collector.main:app --host 127.0.0.1 --port 8010 &
PYTHONPATH="$REPO" RBAC_ALLOW_INSECURE_DEV=true EVENT_COLLECTOR_URL=http://127.0.0.1:8010 \
  python3 -m uvicorn services.scenario_engine.api:app --host 127.0.0.1 --port 8045 &

# 2) 시나리오 활성화 → phase_clock 이 1Hz 로 흐르기 시작
curl -X POST http://127.0.0.1:8045/scenario/activate \
  -H 'Authorization: Bearer dev' -H 'Content-Type: application/json' \
  -d '{"scenario_id":"POWERPLANT-MODBUS-SABOTAGE-01","team_ids":["RED-01"]}'

# 3) 콘솔을 collector URL 로 빌드 후 서브
echo 'VITE_COLLECTOR_URL=http://127.0.0.1:8010' > .env.local   # .gitignore 아님 — 커밋 금지
npm run build && npx vite preview --port 5177        # → http://localhost:5177/ (아레나)
```

활성화 직후 아레나 상태 badge 가 `LIVE` 로 바뀌고 TIME REMAINING(예: 30분 한계면 29:5x…)·NEXT ATTACK
(현재 stage 잔여)이 매초 감소한다. `POST /scenario/deactivate` 로 틱이 멈춘다.

- **라이브**: TIME REMAINING(`remaining_sec`) · NEXT ATTACK(`stage_remaining_sec`) · T+ ENGAGE(`elapsed_sec`).
- **정적(정직)**: PATCH COUNT 는 phase_clock 필드가 아니라 패치/복구 이벤트 집계값이므로 이 타이머
  배선에 포함되지 않는다(정적 표기). `current_stage` 는 발행되지만 현재 콘솔은 stage '잔여시간'만 쓰고
  stage 식별자는 렌더하지 않는다.
- 회귀: `tests/unit/test_phase_clock_push.py`(루프 발행) + `test_phase_clock_activation.py`(활성화→틱
  linkage: activate 가 시드를 심어 루프가 발행, deactivate 가 멈춤) + `test_scenario_authoring.py`(투영).

> **S2S 전제**: `/internal/publish`·`/scenario/activate` 는 instructor 역할을 요구한다. 운영에선
> `scenario_engine` 이 `service_headers()` 로 유효한 S2S 토큰을 실어야 하며, 로컬 데모는
> `RBAC_ALLOW_INSECURE_DEV=true` 로 우회한다. 토큰이 없으면 발행이 조용히 실패(에러 삼킴)해 타이머가 멈춘다.

## 라이브 채점 / 스코어보드 / SolveLog (scores 토픽)

아레나·콘솔의 **스코어보드·점수·Solve Log** 도 정적 데모가 아니라, 실제 공격이 점수를 만든다.
경로: 콘솔 EXECUTE STRIKE → 트윈 공격 엔드포인트가 이벤트 발행 → `event_collector POST /events` →
`event_collector` 가 `scoring_engine POST /score/ingest` 로 포워딩 → `RED_POINTS`(initial_access 20·
lateral_movement 30·objective 100 …)로 가점 → **awarded 면** `event_collector` 가 `scores` 토픽을
`/stream` 으로 발행 → 콘솔이 팀별로 누적(red→attack·blue→defense)해 스코어보드·Solve Log 를 갱신.

```bash
# 1) event_collector(8010) + scoring_engine(8020) + 발전소 트윈(8002) 기동
PYTHONPATH="$REPO" RBAC_ALLOW_INSECURE_DEV=true SCORING_ENGINE_URL=http://127.0.0.1:8020 \
  python3 -m uvicorn services.event_collector.main:app --host 127.0.0.1 --port 8010 &
PYTHONPATH="$REPO" RBAC_ALLOW_INSECURE_DEV=true DATA_DIR="$TMP/scoredb" \
  python3 -m uvicorn services.scoring_engine.main:app --host 127.0.0.1 --port 8020 &
PYTHONPATH="$REPO" RBAC_ALLOW_INSECURE_DEV=true MODBUS_PORT=8502 EVENT_COLLECTOR_URL=http://127.0.0.1:8010 \
  python3 -m uvicorn services.power_plant.main:app --host 127.0.0.1 --port 8002 &

# 2) 콘솔을 collector + 발전소 트윈 URL 로 빌드 후 서브
printf 'VITE_COLLECTOR_URL=http://127.0.0.1:8010\nVITE_POWER_TWIN_URL=http://127.0.0.1:8002\n' > .env.local
npm run build && npx vite preview --port 5177   # → http://localhost:5177/?v=facility&sector=power
```

발전소 콘솔에서 킬체인(HMI 기본계정 → PLC 터빈 RPM → 냉각수 차단 → SIS 무력화)을 EXECUTE STRIKE 로
실행하면 `scoring_engine /scores` 의 `teams.default.red` 가 **20 → 50 → (멱등) → 150** 으로 오르고,
콘솔 스코어보드가 정적 5행에서 **RED·TEAM-01 150/0 단일 라이브 행**으로, Solve Log 가 `objective +100`·
`lateral_movement +30`·`initial_access +20` 라이브 어워드로 바뀐다(상단 ATTACK 150·DEFENSE 0).

- **라이브**: 스코어보드(`scores` 누적 → atk/def) · Solve Log(awards) · Strike Log(`events` 토픽 원시 이벤트).
- **정직한 동작**: 채점에 '시나리오 활성' 게이트가 없다(매칭되는 이벤트는 항상 채점). milestone 당
  **멱등**(같은 vuln/phase 재공격은 재가점 없음 — 위 2번째 PLC 쓰기가 점수 변화 없음으로 실증). 라이브
  스코어보드는 **실제 어워드가 있는 팀만** 행으로 표시(단독 플레이 시 1행).
- 회귀: `tests/unit/test_scores_publish.py`(awarded ⇒ `scores` 발행 + 프런트 계약 payload shape 고정,
  awarded=False/5xx/전송예외 시 미발행) + `test_scoring_engine.py`(가점 분기·멱등·랭킹) +
  `test_event_loss_visibility.py`(포워드 무손실 DLQ).

> **무손실 주의**: 트윈 `emit_event` 는 best-effort — `event_collector` 미도달 시 공격은 트윈에서
> '성공'해도 **점수가 안 생긴다**(드롭 카운터만 증가). `scoring_engine` 다운 시 포워드는 DLQ 로 가고
> 드레인 루프가 복구 시 재전달한다. `scoring_engine/scores.db` 는 영속 볼륨이라 스테일 DB 가 이전 점수를
> 끌고 온다 — 새 런은 `DATA_DIR` 격리나 `POST /admin/reset`(instructor)로 초기화.
