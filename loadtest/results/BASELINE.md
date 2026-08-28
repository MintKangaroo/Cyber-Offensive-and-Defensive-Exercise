# 부하 기준선 (감사 4.10)

nightly `k6` 워크플로(`.github/workflows/loadtest.yml`)가 3종 시나리오를 실행하고 결과 JSON을
이 디렉터리에 커밋한다(`<script>.<YYYYMMDD>.json` + `<script>.latest.json`).

## 시나리오
| 스크립트 | 대상 | 부하 | 임계(threshold) |
|---|---|---|---|
| `event_collector_ingest.js` | `POST /events` (event_collector) | 200 EPS · 3m | p99 < 200ms |
| `twin_attack_load.js` | 트윈 취약 엔드포인트(ground_station 등) | 스크립트 정의 | 스크립트 정의 |
| `attack_defense.js` | A/D API(스코어보드 조회·제출) | VUS/SPS(env로 조절) | 스크립트 정의 |

## 수용 인원 기준선(초기, 재측정 대상)
- 이벤트 수집: **~200 EPS** 지속에서 p99 < 200ms 목표(단일 event_collector, SQLite WAL).
  섹터/팀 증가 시 EPS 선형 증가 → 이 값이 단일 인스턴스 한계의 기준.
- A/D: 동시 팀 3, 제출 ~10/s에서 안정. 대회 규모(팀 N)로 확장 시 이 결과와 비교해
  scoring/engine 병목을 판정한다.

> 첫 nightly 실행 후 실제 수치로 이 표를 갱신할 것. 회귀(임계 초과)는 워크플로가 실패로 표시한다.

## 부하 포화점 (감사 U-3)

nightly 는 *고정* 부하에서 임계 통과 여부만 본다("이 부하는 견디는가?"). 포화점은 별도
스트레스 테스트가 답한다("어디서 무너지는가?"). `loadtest/k6/event_collector_saturation.js`
가 `POST /events` 에 EPS를 rate별 독립 시나리오로 훑으며(각 시나리오 사이 배수, 마지막
정상상태 창만 측정) 다음을 자동 산출한다:

- **`saturation_eps`** — SLO(**p95 < 500ms AND 실패율 < 1%**)를 지킨 *연속* 최고 EPS(수용 한계).
- **`first_break_eps`** — SLO가 처음 깨진 EPS(=포화점). 단계별 p95·실패율·완료수 표가 함께 남는다.

`.github/workflows/saturation.yml`(주간 일요일 02:00 KST + 수동 `workflow_dispatch`)가 이를
실행해 `loadtest/results/event_collector_saturation.<YYYYMMDD>.json`(+`.latest.json`)으로 커밋한다.

### 실측 결과 (2026-08-28, 2-core GitHub 러너)

| EPS | p95 | 판정 |
|---|---|---|
| 10–50 | ~5–7 ms | OK (여유) |
| 75 | ~320 ms | OK (knee — 지연 급상승) |
| 100 | 타임아웃·17% 실패 | **BREAK (붕괴)** |

- **수용 한계 ≈ 75 EPS**, **붕괴 100 EPS**. 안전 운영선은 **~50 EPS**(p95 한 자리 ms).
- **근본 원인**: `/events` 가 요청마다 **동기 SQLite `commit()`(fsync)** 을 async 이벤트 루프에서
  직렬 수행한다(`services/event_collector/main.py`). fsync 지연이 루프를 막아 초당 수십 커밋으로
  제한된다.
- **주의**: nightly `event_collector_ingest.js`(목표 200 EPS)는 실제로 **~38 req/s 만 달성·나머지
  dropped·p95 ~2.3s** 였다 — 200 EPS 는 이미 포화를 한참 넘어선 값이고, 워크플로의 `|| echo`
  때문에 임계 실패가 green 으로 가려져 왔다. nightly 기준선의 "~200 EPS" 목표는 과대평가였다.
- **대회 규모 함의**: 단일 event_collector 로는 지속 **~50–75 EPS** 가 한계. 그 이상(팀·섹터 증가)
  이면 **배치/비동기 커밋** 또는 **수평 확장**이 필요하다. 개선 여지가 큰 후속 항목.
