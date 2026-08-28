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

**개선 전** — 수용 한계 **75 EPS**, 붕괴 100 EPS(60s 타임아웃·17% 실패). 원인:
- ① `/events` 가 요청마다 커넥션 open+PRAGMA + 동기 SQLite 작업을 async 이벤트 루프에서
  수행해 요청을 직렬화(fsync 자체는 이미 WAL+synchronous=NORMAL 로 완화돼 있었음).
- ② scoring 포워딩이 호출마다 `httpx.AsyncClient` 를 새로 만들어 연결 처닝, fire-and-forget
  으로 무제한 태스크 누적(100 EPS 절벽의 실주범).

**개선 후** — 수용 한계 **450 EPS**(≈6배), 붕괴 600 EPS. 개선 커밋:
- **PR #38** — ingest 쓰기(중복검사+INSERT+commit)를 단일 워커 executor의 영속 커넥션으로
  오프로드(`run_in_executor`) → 이벤트 루프 비블록. 75 EPS p95 124ms→~2ms.
- **PR #39** — scoring 포워딩에 연결 풀 공유 `httpx.AsyncClient` 재사용 + 세마포어(기본 64,
  `FORWARD_MAX_CONCURRENCY`)로 동시성 제한. 100 EPS 절벽 제거.

| EPS | 개선 전 p95 | 개선 후 p95 |
|---|---|---|
| 75 | ~124 ms | ~2 ms |
| 100 | 붕괴 | ~1 ms |
| 300 | — | ~490 ms |
| 450 | — | ~3 ms (수용 한계) |
| 600 | — | **BREAK** |

- 안전 운영선 **~300 EPS**, 수용 한계 **450 EPS**. 그 위(≥600 EPS)의 다음 병목은 scoring_engine
  또는 SQLite 단일 writer 한계로 추정(후속 여지).
- **주의**: nightly `event_collector_ingest.js`(목표 200 EPS)는 개선 전 실제로 **~38 req/s 만
  달성·대부분 dropped·p95 ~2.3s** 였고 워크플로의 `|| echo` 가 임계 실패를 green 으로 가려왔다.
  개선 후엔 200 EPS 가 p95 ~1ms 로 여유롭게 통과한다. → 후속: nightly 임계 실패를 실제 실패로
  노출(게이트에 이빨 달기).
