# 103 — 장시간·부하 실측 (Phase 4)

- 작성일: 2026-09-30
- 방식: 8시간 정식 소크는 이 세션(대화형·샌드박스 RAM 제약)에서 완주 불가 → 규칙 4대로
  하네스·실행 명령·과거 실측을 기록하고, 미실행분은 **UNVERIFIED**로 남긴다.

---

## 0. 상태 요약

| 항목 | 상태 | 근거 |
|---|---|---|
| 소크 하네스 | ✅ 존재 | `loadtest/soak/`(run_soak.sh·soak_load.py·soak_sample.sh·soak_analyze.py) |
| 2h 가속 소크 | ✅ PASS(과거) | `loadtest/soak/results/soak_report.json` overall=PASS, 4서비스 slope ≤ 0 MiB/h, restart 0 |
| 8h 정식 소크 | ⏳ **UNVERIFIED** | 세션 내 완주 불가. 실행 명령 아래. |
| U-3 포화점(≥450 EPS) | ✅ 코드/CI | `saturation.yml` weekly(Phase 0 gh: 2026-09-27 success), [[u3-saturation-finding]] |
| U-5 Zeek 헤더 레이스 | ✅ FIXED | `tests/unit/test_file_tailer_header.py`(Phase 1에서 실행 통과) |

과거 2h 소크(`soak_report.json`): config_service slope −6.13·event_collector −1.12·scoring_engine
−5.11 MiB/h, 전부 PASS(임계 warn 5 / fail 20), 재시작 0, 441 샘플.

## 1. 8h 정식 소크 실행 명령 (미실행 — 여유 RAM/실HW 세션에서)

```bash
# 코어 4서비스(event_collector·scoring_engine·config_service·siem_api) 8h 지속부하 + RSS 회귀분석.
SOAK_DURATION_SEC=28800 ASSET_CHECKPOINT_EVERY=250 SOAK_SCENARIO_ID=soak \
  bash loadtest/soak/run_soak.sh
# 결과: loadtest/soak/results/soak_report.json (overall PASS/FAIL, 서비스별 slope_mib_per_h)
```

## 2. Phase 3에서 발견한 소크 관련 결함 (R-1) — 8h 소크 전 처리 권장

- **R-1**: `/replay/events` 무한 fetchall 이 대용량 events.db 에서 event_collector 를 OOMKill
  (실측 761MB에서 재현, audit/102 §3). 8h 소크는 event_collector events.db 를 크게 키우므로,
  소크 종료 시점의 **AAR PDF 생성·scoring reconcile 크로스체크가 OOM**으로 실패할 수 있다.
- 과거 소크 하네스는 코어 4서비스의 RSS 기울기만 판정했고 **대용량 DB에서의 replay/AAR 경로는
  미포함**이라 이 결함을 놓쳤다. → 8h 정식 소크 전에 R-1 수정(POST_V1_BACKLOG, 설계 승인 필요) +
  소크 종료 후 AAR PDF 생성/ reconcile 크로스체크를 판정 항목에 추가할 것.

## 3. 남은 UNVERIFIED

- 8h 정식 소크(실HW/여유 RAM 세션). 명령은 §1.
- 대회 규모(다팀·다관전자) 동시성 실측(U-3의 실부하 재현) — saturation.yml 는 event_collector
  단일 축. 전체 스택 동시성은 실HW 필요.
