# 104 — 남은 항목 처리 결과 (v1.1 후속)

- 작성일: 2026-09-30
- 대상: v1.0 완료기준 밖으로 분류했던 "환경/수동" 잔여 항목을 실제로 진행한 결과.
- 원칙: 이 환경에서 완결 가능한 것은 실행·검증하고, 사람/실HW/실모델이 필요한 것은
  사유와 실행 방법을 명시(허위 보증 금지).

---

## 요약

| 항목 | 결과 | 근거 |
|---|---|---|
| A/D 팀 src_ip 라이브 귀속(S-9) | ✅ **VERIFIED(라이브)** | 서로 다른 출발지 IP 가 구분 기록됨 |
| 8h 소크 — R-1 규모 게이트 | ✅ **하네스 검증(라이브)** | 11,182 이벤트에서 reconcile·AAR OOM 없음 |
| 8h 정식 소크(벽시계) | ⏳ UNVERIFIED | 세션 내 8h 불가. 명령 기록(audit/103) |
| 자동 접근성(axe) | ✅ **PASS** | 대시보드 4종 a11y 테스트(CI + 로컬 재확인) |
| 수동 접근성(키보드·스크린리더) | 🚫 사람 필요 | 자동화 대체 불가 |
| 로컬 AI 모델 평가 | 🚫 실모델/환경 필요 | 저장소에 LLM 연동 없음 |
| §2 기능성 OPEN(T-13/14/17/18/19/23) | ⏸ 백로그(위험수용) | 스코프 동결 결정 |

---

## 1. A/D 팀 src_ip 라이브 귀속 — VERIFIED

S-9(PR #105)의 `ad_target_gateway.conf` X-Forwarded-For 주입이 실제로 팀별 공격 출발지를
구분 기록하는지 라이브 확인. 최소 A/D 타깃 스택(ad_target_gateway + ad_team_01_notes + siem_logs)을
기동하고, `ad_target_ingress` 망에서 **서로 다른 IP** 의 공격 컨테이너로 게이트웨이(9101)를 공격.

- 게이트웨이 자기 IP: `172.20.0.2`.
- 팀 서비스 access 로그(`siem_logs/attack_defense/attack_defense_access.log`) 기록된 공격 src_ip:
  **`172.20.0.3` / `172.20.0.50` / `172.20.0.51`** — 각 공격자의 실제 IP.
- 즉 **게이트웨이 IP 하나로 뭉개지지 않고 출발지별로 구분**됨 → 팀 귀속 성립(원 S-9 시나리오 해소).
- (참고: 단일 호스트라 IP 는 컨테이너 고정 할당으로 시뮬레이션. 실 대회는 팀별 컨테이너가
  자연히 서로 다른 IP 를 가진다.)

## 2. 8h 소크 / R-1 규모 게이트 — 하네스 검증

- `run_soak.sh` 에 R-1 게이트 추가(PR #117): 부하로 커진 events.db 에서 종료 시 reconcile·AAR PDF 가
  OOM 없이 성공하는지 판정. 6분 가속 소크(11,182 이벤트)에서 **게이트 PASS**
  (reconcile checked=true total=11182, AAR PDF 200, event_collector health 전·후 200).
- **8h 정식 소크는 세션 벽시계 제약으로 미실행(UNVERIFIED)**. 실행:
  `SOAK_DURATION_SEC=28800 SOAK_SCENARIO_ID=soak bash loadtest/soak/run_soak.sh`.
  (RSS 슬로프 판정은 장시간에서만 신뢰 — 짧은 창은 외삽 노이즈.)

## 3. 접근성 — 자동 PASS / 수동은 사람 필요

- **자동(axe-core)**: `dashboards/{siem,blueportal,redportal}/src/a11y.test.tsx`,
  `services/edr/console/src/a11y.test.tsx` — 구조적 a11y 회귀(landmark·label·role). CI
  `specialist-dashboards` 잡 green + 로컬 재확인(siem 4 passed).
- **수동**: 실제 키보드 전용 내비게이션·스크린리더(NVDA/VoiceOver) 통과 여부는 사람이 보조기술로
  수행해야 하며 코드로 대체 불가. → 운영 전 체크리스트 항목으로 유지.

## 4. 로컬 AI 모델 평가 — 실모델/환경 필요

- 저장소에 로컬 LLM/AI 모델 런타임 연동(ollama·model server 등)이 **없음**. AI 챌린지(AI-000~009)는
  결정론적 grader 로 채점되며 실 모델이 필요 없다. "로컬 AI 모델 평가"(AI-hint 등 P6 아이디어)는
  실제 모델 배포 + 평가 기준이 있어야 가능한 **환경 작업**이라 이 세션에서 코드 완결 불가.

## 5. §2 기능성 OPEN — 백로그(위험 수용)

T-13(lateral movement 문제)·T-14(Sigma 로더)·T-17(EDR 초단기 프로세스)·T-18(L3 격리)·
T-19(NOC 자산)·T-23(PCAP 캡처)는 **신규 기능**이라 스코프 동결(마감 규칙 3)에 따라 구현하지 않고
`docs/POST_V1_BACKLOG.md` 에 위험 수용으로 유지(릴리스 책임자 결정).

## 6. 부수 관찰
- `siem_logs/attack_defense/attack_defense_access.log` 가 169MB 로 누적(과거 세션 잔여) — SIEM 저장소
  rollover 부재(S-11 백로그)와 동일 계열. logrotate/보존 정책은 백로그 유지.
