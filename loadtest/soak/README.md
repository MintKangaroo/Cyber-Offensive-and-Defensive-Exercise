# U-6 소크 테스트 하네스 (장시간 메모리 안정성)

기존 `loadtest/k6/*`는 90초~5분 버스트라 **시간-비례 누수**(타이머·백그라운드 루프·브로드캐스트
팬아웃 누적)를 못 잡는다. 이 하네스는 낮은~중간 rate 로 몇 시간 지속부하를 걸며 코어 서비스의
RSS 추세를 추적해 메모리 누수/OOM 을 판정한다.

## 구성

| 파일 | 역할 |
|---|---|
| `soak_load.py` | 지속부하 생성기. event_collector `/events` 수집(→ scoring S2S 팬아웃 + WS 브로드캐스트) 80% + siem_api 조회 20%. 목표 rate 오픈루프 페이싱. |
| `soak_sample.sh` | `INTERVAL`초마다 대상 컨테이너 RSS/CPU/RestartCount → CSV. |
| `soak_analyze.py` | 컨테이너별 RSS 선형회귀(MiB/h). warmup 램프 제외, 재시작(OOM 의심) 감지 → PASS/WARN/FAIL. |
| `run_soak.sh` | 단일 엔트리포인트: 코어 스택 기동 → health → 부하+샘플링 → teardown → 분석. |

## 실행

```bash
# 가속 소크 2h (기본)
bash loadtest/soak/run_soak.sh

# 8시간 정식 소크
SOAK_DURATION_SEC=28800 bash loadtest/soak/run_soak.sh

# 백그라운드(권장, 장시간)
SOAK_DURATION_SEC=28800 nohup bash loadtest/soak/run_soak.sh &
```

### 주요 환경변수
- `SOAK_DURATION_SEC`(기본 7200) · `SOAK_RATE`(기본 40 req/s) · `SOAK_SAMPLE_INTERVAL`(기본 60)
- `SOAK_SLOPE_WARN_MIB_H`(기본 5) · `SOAK_SLOPE_FAIL_MIB_H`(기본 20) · `SOAK_WARMUP_SKIP`(기본 5 샘플)
- `SOAK_KEEP_UP=1` — 분석 후 스택 유지(디버깅용)

> `run_soak.sh`는 이 격리 소크 스택을 CI `loadtest.yml`과 동일하게 **dev-mode ingest**로 띄운다
> (`SERVICE_TOKEN=""` + `RBAC_ALLOW_INSECURE_DEV=true`) — 토큰 없는 부하가 `/events`를 통과하도록.

## 판정 기준
- **PASS** — 전 컨테이너 steady-state 기울기 < 5 MiB/h 이고 재시작 0
- **WARN** — 기울기 5~20 MiB/h(관찰 필요)
- **FAIL** — 기울기 ≥ 20 MiB/h 또는 재시작 발생(OOM/crash 의심)

## 최근 결과 (`results/`)
2시간 가속 소크(2026-08): 217,010/217,014 요청 2xx, 코어 4서비스 RSS 평탄~하락(slope ≤ 0 MiB/h),
재시작 0·OOM 0 → **PASS**. 상세는 `results/soak_report.json` / `results/analysis.*.txt`.
