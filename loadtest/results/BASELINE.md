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
