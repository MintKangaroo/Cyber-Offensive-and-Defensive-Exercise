# 인수인계 (HANDOFF) — Cyber Range Platform

**갱신일**: 2026-09-30 (v1.0 마감 라운드). 이전 7월 판 내용은 폐기됨.
**목적**: 다음 세션이 "어디까지 실제로 실행·검증했는지"를 이어받는다. 운영 지침은 `CLAUDE.md`.

---

## 1. 현재 상태 한눈에
- 백엔드 테스트 **752 passed / 6 skipped**(skip = PostgreSQL HA, 로컬 DB 없음; CI 는 postgres 로 통과).
- 챌린지 **130종** 검증 통과(web24·pwn23·crypto21·detection14·ics13·ai9·forensics9·network9·reversing8).
- CI `ci.yml` **13 잡 green**(main). nightly/weekly 부하 워크플로 green.
- 무인 리허설 `make rehearsal` **완주(PASS=13 FAIL=0)** — Live Fire + A/D 2라운드.

## 2. v1.0 마감 라운드에서 한 일 (audit/100~103)
- **Phase 0 (audit/100)**: 기준선 실측. 문서 드리프트(README 챌린지 수 70/112 → 실제 130 등)와
  **v1.0.0 태그가 stale**(`dc8f526`, #27 시점)임을 확인.
- **Phase 1 (audit/101)**: 감사 Showstopper S-1~S-11 재판정 → **7 FIXED · 4 PARTIAL**(S-3·S-8·S-9·S-10).
  §2 T-1~30, §6 U-1~10 재판정 포함.
- **Phase 2**: Showstopper 잔여 코드 마감(PR #105~108) + 백로그(#109) + pyjwt CVE 범프(#110) + 감사
  산출물(#111). 이후 리허설 하네스(#112)·env 오염 fix(#113).
  - **S-9(#105)**: `ad_target_gateway.conf` 에 XFF 주입 → A/D 팀 src_ip 귀속 복구.
  - **S-8(#106)**: `event_client`·`sse_bus` 드롭 카운터+로그, `/metrics` `sse_dropped`, DLQ 드레인 분리.
  - **S-3(#107)**: 서비스형 배포 스캐폴드 dev 시크릿 140개 제거(`:?` fail-fast).
  - **S-1/S-2(#108)**: safe_probe CLI fail-closed 종료코드, 망 주석 정정.
  - **pyjwt(#110)**: 2.13.0→2.14.0 (CVE-2026-102265~102274 10건).
- **Phase 3 (audit/102)**: `scripts/rehearsal/` 봇 하네스 + `make rehearsal`. 라이브 완주 검증:
  점수-이벤트 원장 유실 0, SIEM 경보 src_ip 귀속, AAR PDF 한글(HYSMyeongJo), A/D 2라운드 accepted.
- **Phase 4 (audit/103)**: 소크 하네스 존재·2h 가속 PASS(과거). 8h 정식 소크는 **UNVERIFIED**(명령 기록).

## 3. 위험 수용 / 백로그 (docs/POST_V1_BACKLOG.md)
- Showstopper 잔여: S-10 prod k8s PVC 웹셸 잔존, S-11 8h 실OOM/rollover 실측 → 위험 수용(사유 명시).
- **R-1(신규, 우선)**: `/replay/events` 무한 fetchall 이 대용량 events.db(실측 761MB)에서 event_collector
  OOM → AAR PDF·reconcile 실패. **AAR 은 훈련 종료 시점(DB 최대)에 생성**되므로 장시간 실전 리스크.
  수정안(reconcile/AAR 을 `/replay/page` 배치 소비로 전환)은 **구조 변경 → 설계 승인 필요**.
- §2 OPEN(신규기능=스코프 동결): T-13 lateral·T-14 Sigma 로더·T-17 EDR 초단기·T-18 L3 격리·
  T-19 NOC 자산·T-23 PCAP. 채점품질: T-1·T-7·T-30.

## 4. 남은 작업 (다음 세션)
1. **v1.0.0 태그 결정(승인 필요)**: 기존 stale 태그(`dc8f526`)를 현재 HEAD 로 옮길지 / 새 버전으로 갈지.
   CHANGELOG `[Unreleased]` → `[1.0.0]` 정리(이미 존재하는 `[1.0.0] - 이전` 섹션과 충돌 정리).
2. **R-1 수정**(설계 승인 후): reconcile/AAR 의 replay 페이지네이션.
3. **8h 정식 소크**(여유 RAM/실HW): `SOAK_DURATION_SEC=28800 bash loadtest/soak/run_soak.sh`.
   R-1 수정 후 소크 종료 시 AAR/reconcile 판정 추가.
4. A/D 팀 src_ip **라이브** 귀속(팀별 컨테이너 출발지 구분) — 실HW.
5. 수동 접근성/키보드 감사·로컬 AI 모델 평가(환경/수동 필수).

## 5. 시작 절차 (clean host)
```bash
cp .env.example .env && ./scripts/gen_secrets.sh   # 시크릿 생성(CHALLENGE_SECRET·SERVICE_TOKEN 등)
pip install -r requirements.txt                     # 런타임(파이썬)
python3 -m pytest tests/ -q                          # 유닛 검증
bash scripts/validate_challenges.sh                  # 챌린지 검증
# 도커 훈련: python3 -m scripts.training_environment up  (메모리 여유 필요 — CLAUDE.md 참고)
```
자세한 구조·검증·도커 주의는 `CLAUDE.md`.
