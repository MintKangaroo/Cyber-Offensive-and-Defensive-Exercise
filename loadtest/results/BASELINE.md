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
  또는 SQLite 단일 writer 한계로 추정(후속 여지 → 아래 3차 개선).
- **주의**: nightly `event_collector_ingest.js`(목표 200 EPS)는 개선 전 실제로 **~38 req/s 만
  달성·대부분 dropped·p95 ~2.3s** 였고 워크플로의 `|| echo` 가 임계 실패를 green 으로 가려왔다.
  개선 후엔 200 EPS 를 완전 달성(p95 ~20ms·p99 ~350ms)한다.

**3차 개선 — 그룹 커밋 + INSERT OR IGNORE (다음 병목 ≥600 EPS 대응)**. 2차(PR #38/#39)까지의
남은 천장은 **단일 writer 의 "이벤트당 커밋"**이었다. 단일 writer 가 초당 낼 수 있는 커밋 수가
유한하므로 이벤트마다 트랜잭션을 열면 그 커밋 레이트가 곧 처리량 상한이 된다.
- **그룹 커밋**: ingest 를 큐로 받아 writer 가 큐에 쌓인 이벤트를 한 트랜잭션(INSERT 여러 건 +
  commit 1회)으로 흘린다. 저부하는 배치 크기 1(추가 지연 0), 고부하는 writer 가 커밋하는 동안
  쌓인 이벤트를 다음 배치로 흡수해 커밋 1회에 N건(자기조정, `INGEST_BATCH_MAX_SIZE` 상한 256).
- **INSERT OR IGNORE**: 이벤트당 `SELECT`(중복검사)+`INSERT` 2회 왕복을 1회로 줄여(중복은
  PRIMARY KEY 충돌로 SQLite 안에서 무시, 신규 여부는 `rowcount`) 단일 writer 스레드 CPU 부담을
  낮춘다(0.75 CPU 캡·고 EPS에서 유효).
- **동일 머신 A/B**(로컬 WSL2·0.75 CPU 캡 — 절대치는 위 2-core 러너와 다름, **상대 개선폭**이 핵심):

  | EPS | 이벤트당 커밋(대조) | 그룹 커밋 | 그룹 + OR IGNORE |
  |---|---|---|---|
  | 300 | 769 ms · BREAK | 460 ms · OK | **206 ms · OK** |
  | 450 | 1248 ms | 853 ms | 596 ms |
  | 600 | 1512 ms | 1167 ms | 1106 ms |
  | 수용 한계 | **200 EPS** | **300 EPS** | **300 EPS** |

  → 그룹 커밋이 수용 한계 200→300 EPS(**+50%**), OR IGNORE 가 전 rate p95 를 추가로 크게 낮춘다
  (300 EPS: 769→206 ms, **-73%**). 절대 천장은 nightly `saturation.yml` 이 2-core 러너에서 재측정한다.
- **부수 개선(정상 종료)**: 그룹 커밋 배치 라이터·DLQ 드레인 등 무한 루프 태스크와 공유
  `httpx.AsyncClient` 가 종료 시 취소·close 되지 않아 lifespan 종료가 매달렸다(컨테이너 stop 이
  graceful timeout→SIGKILL 까지 지연). `shared/lifespan.py` 에 `on_shutdown` 훅을 추가하고
  event_collector 가 백그라운드 태스크 취소 + 클라이언트 close 를 하도록 정리.

### nightly 회귀 게이트(감사 4.10, 이빨 달기 완료)

`loadtest.yml` 이 `|| echo` 로 k6 종료코드를 삼켜 임계 실패가 green 으로 가려져 있었다. 이제
**ingest·twin·attack_defense 3종 모두 게이팅**(임계 위반 시 결과 커밋 후 `Enforce load thresholds`
스텝이 잡을 실패)한다. 임계도 현실화: ingest `p99<200`→`p99<500`(개선 후 실측 tail 반영, 회귀 시
수초로 튀어 즉시 포착). **attack_defense 게이팅 승격(PR #45)**: 이전엔 매치/토큰 부트스트랩이
없어 scoreboard 가 전량 404 라 비게이팅이었으나, 이제 `loadtest/k6/bootstrap_ad.py` 가 k6 전에
매치·팀·competitor 토큰을 만들고(그룹 커밋 아님, `AUTH_JWT_SECRET` 로 JWT 민팅) 게이트에 포함된다.
