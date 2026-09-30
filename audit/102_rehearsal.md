# 102 — 무인 리허설 (Phase 3)

- 실행일: 2026-09-30
- 대상: `main` (Phase 2 머지 후) + `scripts/rehearsal/` 신규 하네스
- 방식: 실제 도커 서브셋 기동 + 봇 기반 E2E. 메모리 제약(가용 ~4Gi)상 전체 스택 대신
  리허설에 필요한 서브셋만 순차/병행 기동(이벤트 파이프라인 + A/D notes 서브셋).
- 산출물: `scripts/rehearsal/`(레드·교관 봇 + 오케스트레이터), `make rehearsal` 타깃,
  `loadtest/results/rehearsal_*.json`.

---

## 0. 결과 요약

**`python3 -m scripts.rehearsal.run_rehearsal --stage all` → PASS=13 FAIL=0 → ✅ 완주(무결함)**

| 검증 | 결과 | 근거 |
|---|---|---|
| Live Fire: 킬체인 5단계 이벤트 발행 | ✅ | codes=[200×5] |
| 이벤트 원장 완전성(발행=원장) | ✅ | emitted=5 == ledger=5 |
| **이벤트 유실 0** | ✅ | dlq_drop=0, dlq_pending=0, forwarded_ok +5 |
| **점수 합계 일치**(stored==computed) | ✅ | reconcile score_consistency=true |
| **이벤트-점수 원장 일치(유실 0)** | ✅ | reconcile total=5 scoreable_without_achievement=0 missing=[] |
| **SIEM 경보 팀 귀속** | ✅ | 공격 후 fresh alert, matched_event.raw.src_ip 채워짐 |
| **AAR PDF 생성(한글)** | ✅ | 200 · application/pdf · HYSMyeongJo(한글 CID) 폰트 |
| A/D 교관 매치 시작 | ✅ | status=running |
| A/D 라운드1 레드 공격 accepted | ✅ | IDOR 탈취→제출 accepted +10 |
| A/D 교관 라운드1 확정→라운드2 | ✅ | finalize http=200 |
| A/D 라운드2 레드 공격 accepted | ✅ | accepted +10 |

---

## 1. 리허설 하네스 구성 (`scripts/rehearsal/`)

- `common.py` — .env 로드·서비스 URL·서비스 토큰·`Reporter`(PASS/FAIL 집계).
- `livefire.py` — 이벤트 파이프라인 Live Fire + 3대 검증(원장 0유실·SIEM 귀속·AAR PDF 한글).
  격리 `scenario_id`(reh-livefire-*)를 써서 이전 매치/소크 잔여와 섞이지 않게 함.
- `red_bot.py` — 레드 공격: 타깃 notes 등록/로그인 → `GET /api/notes/{id}` IDOR 로 FLAG 수집
  → competitor JWT(HS256·AUTH_JWT_SECRET·team_id/match_id) 로 `flags/submit`.
- `instructor.py` — 교관: 매치 시작(bootstrap 재사용)·라운드 상태·확정(finalize)·일시정지/재개.
- `run_rehearsal.py` — 오케스트레이터: Live Fire + A/D 2라운드 완주, `Reporter` 집계, JSON 산출.
- `make rehearsal` — 서브셋 기동(--build) 후 오케스트레이터 실행. `make rehearsal-down` 서브셋 해제.
- 회귀: `tests/unit/test_rehearsal_harness.py`(competitor JWT 형식·플래그 추출·리포터 집계).

## 2. 핵심 검증 근거(라이브 실측)

- **점수-원장 유실 0**: 격리 scenario 로 킬체인 5단계(phase 당 1 achievement) 발행 → event_collector
  `/replay/events` 에 5건 전량 존재, `/metrics` dlq_drop=0·pending=0, scoring `/scores/reconcile`
  가 `score_consistency=true` + `events_crosscheck.scoreable_without_achievement=0`.
  ★주의: 동일 phase 를 반복하면 scoring 이 phase 당 1회만 가점(정상 dedup)하므로 reconcile 의
  `scoreable_without_achievement`가 올라간다 — 유실이 아니라 dedup. 하네스는 phase 별 1건으로 검증.
- **SIEM 팀 귀속**: 트윈 게이트웨이로 실 공격을 흘리면 SIEM 경보 `matched_event.raw.src_ip` 가
  채워짐(트윈 게이트웨이는 `$remote_addr` 로 실 클라이언트 기록). A/D 팀별 귀속은 Phase 2 의
  ad_target_gateway XFF 수정(S-9, PR #105)으로 담보(회귀 테스트 존재).
- **AAR PDF(한글)**: aar_report `/report/aar/pdf` → 200·application/pdf, reportlab 내장 한글 CID
  폰트 `HYSMyeongJo-Medium`(UniKS-UCS2-H) 임베드 확인(Helvetica 는 한글 ■ 깨짐).
- **A/D 2라운드 + 리셋**: fresh 매치(seq 리셋)에서 레드가 라운드마다 현재 플래그를 IDOR 로 탈취해
  제출 → accepted +10. 교관 finalize 로 라운드 진행. 스테일 매치(누적 플래그)에서는 전량 rejected →
  **리셋이 A/D 리허설의 전제**임을 실증(S-10 리셋 메커니즘의 실효성 확인).

## 3. 리허설 중 발견한 결함

### R-1. `/replay/events` 무한 fetchall 이 대용량 events.db 에서 event_collector 를 OOM — **OPEN(설계 승인 대기)**
- 증상: 과거 소크/부하 테스트로 누적된 `events.db`(실측 **761MB**)가 있는 상태에서
  `GET /replay/events`(스코어링 reconcile 크로스체크·aar_report AAR PDF 가 호출)가
  `SELECT * FROM events ... fetchall()` 로 전체를 메모리에 적재 → event_collector 가
  자기 cgroup 상한(512m) 초과로 **OOMKilled(exit 137)** → reconcile 크로스체크·AAR PDF 실패.
- 근거: `services/event_collector/main.py` `replay_events()` 무한 경로(`limit is None` → 전량 fetchall).
  fresh(빈) DB 에서는 3ms 정상. 761MB DB 에서 20s 행 후 OOM 재현.
- 영향: **AAR PDF 는 훈련 종료 시점(events.db 최대)에 생성**되므로, 장시간 실전에서 재현될 실질
  리스크. 스코어 reconcile 도 동일. (S-11 자원상한·S-8 reconcile 과 연관.)
- 리허설 조치: 스테일 761MB DB 를 초기화(실훈련 데이터 아님, 소크 잔여)해 진행.
- **제안 설계(구조 변경 → 승인 필요)**: reconcile/aar 가 무한 `/replay/events` 대신 이미 존재하는
  커서 페이지네이션 `/replay/page`(services/event_collector/main.py) 를 배치 소비하도록 전환.
  또는 `/replay/events` 에 방어적 상한(스트리밍/청크) 도입. → 백로그 등재(POST_V1_BACKLOG).

## 4. 메모리 운영 메모(재현성)

- 서비스 정상상태 RSS 는 각 ~50–80MiB(캡 512m 은 여유). **동시 다중 이미지 `--build` 시 스파이크로
  event_collector 가 일시 OOM** 관측 → 이미지 사전 빌드 후 `--no-build` 기동이 안전.
- 리허설 서브셋(이벤트 파이프라인 8 + A/D 7 = 15 컨테이너) 병행 시 가용 ~2Gi 로 완주(호스트 11Gi).
- edr_backend 는 override 미로드(Makefile -f 경로) 시 8080 충돌 — 리허설엔 불필요(제외).

## 5. 남은 UNVERIFIED(환경/장시간)

- A/D 팀 귀속 src_ip 의 **라이브** 검증(ad_target_gateway XFF): 팀별 컨테이너에서 서로 다른 출발지
  트래픽 필요 → Phase 4/실HW. 현재는 Phase 2 회귀 테스트 + 트윈 경로 라이브로 담보.
- 8h 정식 소크(U-6)·U-3 포화점: Phase 4.
- R-1 대용량 replay OOM 의 실전 규모 재현·수정: 설계 승인 후.
