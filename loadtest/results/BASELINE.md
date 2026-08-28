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
가 `POST /events` 에 EPS를 단계적으로 올리며(100 → 200 → 400 → 700 → 1000 → 1400 → 1800
→ 2400, 각 25s 독립 측정) 다음을 자동 산출한다:

- **`saturation_eps`** — SLO(**p95 < 500ms AND 실패율 < 1%**)를 마지막으로 지킨 EPS(수용 한계).
- **`first_break_eps`** — SLO가 처음 깨진 EPS(=포화점). 단계별 p95·실패율 표가 함께 남는다.

`.github/workflows/saturation.yml`(주간 일요일 02:00 KST + 수동 `workflow_dispatch`)가 이를
실행해 `loadtest/results/event_collector_saturation.<YYYYMMDD>.json`(+`.latest.json`)으로 커밋한다.
nightly 와 분리한 이유: 램프는 의도적으로 SLO를 깨뜨리므로 회귀 게이트와 성격이 다르고,
매일 돌릴 필요가 없다.

> 수치는 첫 주간 실행(또는 `gh workflow run saturation.yml`)이 채운다. 단일 event_collector·
> SQLite WAL 기준이므로, 대회 규모(팀 N·섹터 M)가 이 수용 한계를 넘으면 event_collector
> 수평 확장 또는 배치 ingest 가 필요하다는 신호다.
