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
- **확장 섹터 6종 — 정유(refinery)·스마트팩토리(factory)·LNG(lng)·철도(railway)·공항(airport)·
  데이터센터(finance=datacenter_bms)** — `attach_modbus_ics` 통일 트윈으로 **텔레메트리 표시 라이브
  연결 가능**(E2E 검증됨). 6개 트윈을 각각 띄워 `/api/telemetry` 가 통일 규약(cmd_name = COLUMN_PRESSURE·
  ROBOT_SPEED·TANK_PRESSURE·TRAIN_SPEED·FUEL_PRESSURE·RACK_TEMP)을 내는 것을 실측했고, 섹터에
  `VITE_TWIN_<SECTOR>`(예: `VITE_TWIN_AIRPORT=http://…:8206`)를 주입하면 콘솔이 그 트윈의 실제 레지스터를
  라이브 렌더한다(제어 레지스터 테이블 + SAFETY_INTERLOCK coil0).
  - 회귀: 트윈 쪽 계약은 `tests/unit/test_twin_telemetry.py` 가 7개 통일 트윈 전부로 전수 고정(과거
    'hospital 대표' 지름길 제거), 콘솔 소비 쪽은 `src/sector-telemetry.test.ts` 가
    `registersFromSectorTelemetry`/`fetchSectorTelemetry`(cmd=SET·over-redline=O-LIMIT·damage=red·SIS
    토글·발전소 전용 스키마 reject)로 고정.
  - **정직한 한계**: 이들 섹터의 콘솔 **EXECUTE STRIKE 라이브 배선은 아직 없다** — generic facility
    설정의 attackChain 은 서사-전용(`step.action` 없음)이라 strike 는 데모로 떨어진다(물리 cmd 구동은
    Modbus/실프로토콜 쓰기 경로이며 full-config 섹터와 달리 콘솔 액션에 미연결). 라이브는 **텔레메트리
    표시** 범위. `nuclear`·`telecom`·`satellite` 는 통일 트윈 미존재(또는 비호환) — 아레나 노드 표시만.

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

### 방어(Blue) 측 — DEFENSE 열 라이브(E2E 검증됨)

같은 `scores` 파이프라인이 방어도 올린다: `actor="blue"` 프레임은 콘솔에서 **DEFENSE 열**과 Solve Log
**방어** 측으로 누적된다(`BLUE_POINTS`: patch_verified 50·detection_success 20(+dwell)·block_success 30·
asset_recovered 50). 공격과 동일 스택(collector+scoring+발전소 트윈)으로 두 실제 방어 생산자를 구동해 실증:

```bash
# (위 라이브 채점 스택이 떠 있는 상태에서)
# ① 패치 검증 → blue_patch_verified(+50): 실제 safe_probe 생산자
PYTHONPATH="$REPO" EVENT_COLLECTOR_URL=http://127.0.0.1:8010 RBAC_ALLOW_INSECURE_DEV=true python3 - <<'PY'
from shared import safe_probe
safe_probe.report_patch_verified("PP-002", "power_plant")   # +50 defense
PY

# ② 안전계통 재무장 → asset_recovered(+50): red 로 자산 손상 후 SIS 재무장 → 배경 물리루프가
#    damage 를 0 으로 회복(heal_rate)하면 트윈이 asset_recovered 발행
curl -X POST http://127.0.0.1:8002/api/safety/override -d '{"override":true}'      # red: SIS BYPASS(손상 시작)
# ...damage 가 0<d<100 일 때...
curl -X POST http://127.0.0.1:8002/api/safety/override -d '{"override":false}'     # blue: 재무장 → heal → asset_recovered +50
```

콘솔: 상단 **DEFENSE 0 → 150**, 리더보드 `RED·TEAM-01 150/150`, Solve Log 에 `방어 … patch_verified +50`·
`asset_recovered +50`(시안 방어 태그)가 `공격` 항목과 듀얼리티로 구분, 레지스터 `SAFETY_INTERLOCK ON·ARMED`·
`DAMAGE 0%`(복구). `/scores` → `{red:150, blue:150}`.

- **라이브 검증됨**: patch_verified(safe_probe) · asset_recovered(트윈 heal) · block_success(SIS 재무장,
  아래 참조) · detection_success(SIEM 매칭, 아래 참조) → DEFENSE 열·방어 Solve Log. 콘솔 red/blue
  라우팅은 `src/live-scoring.test.tsx` 가 고정.

### 차단 성공 — block_success 라이브(SIS 코일0 재무장, E2E 검증됨)

block_success(+30)는 `asset_recovered`(손상이 0 으로 회복될 때, +50)와 다르다: 공격으로 **위험에 빠진**
공정(과속·손상 진행)을 Blue 가 **아직 파국 전에** 안전계통(SIS) 코일을 되살려(coil0→ON) 막은 **그 순간**
발행된다. 발전소 트윈에선 HTTP `/api/safety/override` 가 아니라 **실 Modbus 코일 쓰기(FC5)만**
`_on_modbus_write` 를 거쳐 이 분기를 탄다(그래서 "차단"은 실제 제어 프로토콜 행위).

```bash
# 번들: event_collector(8010) + scoring_engine(8020) + power_plant 트윈(8002, MODBUS_ENABLED=1 MODBUS_PORT=15020)
# red: FC6 TURBINE_RPM<-5600(>redline 4500) + FC5 coil0<-OFF(SIS BYPASS) → actual 이 redline 초과·damage 누적
# blue: 위험 중(0<damage<100, 미파국) FC5 coil0<-ON(재무장) → 그 순간 blue_block_success
# (원시 Modbus 클라이언트로 FC6/FC5 프레임 전송 — 플랫폼 자체 Modbus 서버, pymodbus 불필요)
# → /stream scores 프레임: {actor:"blue", category:"block_success", points:30}
# → 이후 배경 물리루프가 damage 를 heal→0 하면 asset_recovered(+50)도 연이어 발행(이중 크레딧 정상)
# → /scores: {"default":{"red":30, "blue":80}}   (blue 80 = block_success 30 + asset_recovered 50)
```

실측(라이브): red 로 actual 5000(>4500)·damage 4 까지 몰고 그 상태에서 FC5 재무장 → `scores` 프레임
`{actor:"blue", category:"block_success", points:30}`, 재무장 직후 actual 이 redline(4500)으로 캡되고
damage 가 heal 되어 `asset_recovered +50` 까지 연이어. 미가드 갭이었던 **발행 경계**(위험 중 + 미파국 +
코일 ON 에서만 발행; 위험 아님/파국 후/코일 OFF 엔 금지)는 `tests/unit/test_twin_block_success.py` 가
실 트윈 `_on_modbus_write` + 원시 FC5 와이어 프레임(`handle_pdu`)으로 고정한다.

### 탐지(SIEM) 라이브 — detection_success 자동 발행(E2E 검증됨)

detection_success 는 사람이 발행하는 게 아니라 **SIEM 이 공격을 규칙 매칭하면 자동으로** 뜬다. 경로:
red 공격 → 트윈이 `/var/log/siem/{asset}/{asset}_access.log` 에 `vuln_id` 포함 JSON 한 줄 기록 →
SIEM file_tailer 가 집어 `parse_twin_log_line` → `detection_engine.evaluate` 규칙 매칭 →
`_push_detection_to_livefire` 가 `blue_detection_success` 를 event_collector 로 POST → scoring
`detection_success` +20(+dwell) → `scores` 토픽 → 콘솔 DEFENSE 열.

```bash
# 번들: event_collector(8010) + scoring_engine(8020) + power_plant 트윈(8002) + siem(8040)
#  트윈 SIEM_LOG_DIR=$LOGDIR/power_plant · SIEM SIEM_LOG_DIR=$LOGDIR (섹터 격리: SIEM 은 {asset}/ 하위를 tail)
#  SIEM: PUSH_TO_LIVEFIRE=true · EVENT_COLLECTOR_URL=http://127.0.0.1:8010 · RBAC_ALLOW_INSECURE_DEV=true
# red 공격 1회 = PP-001(미인증 PLC 쓰기) → TWIN-PLC-WRITE-001 규칙 매칭
curl -X POST http://127.0.0.1:8002/api/plc/write -d '{"register":"TURBINE_RPM","value":5200}'
# → SIEM /alerts: TWIN-PLC-WRITE-001 matched {'vuln_id':'PP-001'} (severity 4, T0836)
# → /stream scores 프레임: {actor:"blue", category:"detection_success", points:20}
# → /scores: {"default":{"red":30, "blue":20}}  (red 공격 +30 과 blue 탐지 +20 듀얼리티)
```

콘솔: `actor="blue"` 프레임이므로 위 patch/recover 와 **동일한** DEFENSE 열·방어 Solve Log 경로를 탄다
(`category="detection_success"` → `detection_success · +20`). 미가드 갭이었던 **SIEM 매칭→발행** 경계
(`_push_detection_to_livefire` 의 payload: event_type/actor/target_asset/vuln_id/matched_event_id/metadata)는
`tests/unit/test_siem_detection_push.py` 가 실 파서+실 규칙엔진 체인으로 고정한다. 콘솔 쪽 라우팅은
`src/live-scoring.test.tsx` 가 이미 고정(blue→DEFENSE).
