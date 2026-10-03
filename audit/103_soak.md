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

## 1b. 소크 하네스 R-1 게이트 추가 (2026-09-30, 이 세션)
`run_soak.sh` 에 **R-1 게이트**를 추가했다: 부하로 events.db 가 커진 뒤(종료 시점) event_collector
health → scoring reconcile(events 크로스체크) → AAR PDF → event_collector health 재확인을 순서로
판정한다. 무한 replay 회귀가 재발하면 event_collector 가 OOM 으로 죽어 게이트가 FAIL 한다.
- `aar_report` 를 CORE 에 포함, INSTRUCTOR_TOKEN 은 `.env` 에서 로드(컨테이너와 동일 값).
- **라이브 검증(6분 가속 소크, scenario=soak, 11,182 이벤트)**: R-1 게이트 **PASS** —
  reconcile `checked=true total_events=11182`(페이지네이션, OOM 없음), AAR PDF `200 %PDF`(1.1s),
  event_collector health 200(무거운 replay 전·후). → **R-1 수정이 소크 규모에서 검증됨.**
- ⚠️ 단, 6분·6샘플 RSS 슬로프는 외삽 노이즈가 커(siem_api 0.7MiB 상승이 23MiB/h 로 확대) 신뢰
  불가 — RSS 슬로프 판정은 장시간(2h/8h) 실행에서만 유효. 이 짧은 실행의 목적은 R-1 게이트 검증.

## 2. Phase 3에서 발견한 소크 관련 결함 (R-1) — v1.1.0 에서 FIXED

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

---

## 6. 8시간 정식 소크 실측 완료 (2026-10-02~03)
`SOAK_DURATION_SEC=28800 SOAK_RATE=40 SOAK_SCENARIO_ID=soak` — detached 완주(stamp 20261002T231634Z).

**부하**: 1,120,816 요청 / 8h, 실패 **2건**(fail_rate 1.8e-6), avg 6.6ms, rate_actual 38.9/s. **사실상 무유실**.

**RSS 슬로프(warmup 제외 회귀)** — `soak_report.json`:
| 서비스 | first→last MiB | peak | slope MiB/h | 판정 |
|---|---|---|---|---|
| config_service | 42.0→35.3 | 43.6 | -1.17 | PASS |
| event_collector | 76.0→157.6 | 177.7 | **+13.28** | **WARN** |
| scoring_engine | 55.2→52.7 | 57.9 | -0.51 | PASS |
| siem_api | 57.2→54.3 | 59.6 | -0.50 | PASS |
| **OVERALL** | | | | **WARN** |

### 발견 F-1: event_collector 지속부하 워킹셋 성장(WARN, 누수 아님)
- 8h간 76→158 MiB(+13.3 MiB/h). 단, **부하 중단 후 재시작 시 53 MiB 로 회수** → 영구 힙 누수가
  아니라 부하 중 워킹셋(쓰기 버퍼·SSE 링버퍼·SQLite 페이지 캐시). 512m 한도엔 한참 여유.
- 연관: events.db 가 **740MB**(약 91만 유니크 이벤트)까지 성장 — retention(`_prune_old_events`)이
  효과적으로 못 막음(S-11 rollover 계열, 백로그). 워킹셋 성장은 DB 성장과 상관.

### 발견 R-2: reconcile/AAR 이 초대형 events.db(~90만+)에서 실용 불가 (성능)
- R-1(무한 fetchall OOM)은 FIXED(event_collector 전후 health 200, OOM 없음)지만, 종료 시점 R-1 게이트가
  reconcile checked=false(ReadTimeout)·AAR PDF 미완(>180s, RSS 368MiB)으로 FAIL.
- **근본원인**: `/replay/page` 가 `event_id IN (stream_journal 전체 subquery)` + **매 페이지 TEMP B-TREE
  로 ~91만 행 재정렬** → 페이지당 **6.5초**(사실상 O(N²)). `idx_events_scope` 는 team_id 선두라
  scenario-only 필터에 무용.
- **검증된 수정안(R-2 fix, 설계 승인 대기)**: 복합 인덱스 `events(scenario_id,timestamp,event_id)` +
  `/replay/page` 를 커서 범위스캔으로 재작성(스냅샷 상한을 journal-IN 대신 (timestamp,event_id) 상한 커서로).
  실측: 페이지당 6.5s → **<0.01s (~650배)**, 플랜서 TEMP B-TREE 제거. 전체 페이지네이션 ~45분→~5초.
- 영향: 다음 주 짧은 테스트엔 무관(소량 이벤트). 실 8h+ 훈련의 **종료 시 AAR PDF** 생성에 중요.
