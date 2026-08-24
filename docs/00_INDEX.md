# Cyber Range — Claude Code 빌드 문서 인덱스

Live Fire 사이버 모의공방훈련 플랫폼을 Claude Code 팀 에이전트로 구축하기 위한 기획·프롬프트 문서 모음.
아래 순서대로 읽고, 09번 역할 정의에 따라 에이전트에 분배한다.

> ℹ️ **`01`~`31`은 빌드 착수 시점의 설계·프롬프트 문서(design-time spec)입니다.** 구현이 진행되며
> 코드가 이 스펙을 넘어선 부분이 많으므로, **현재 플랫폼의 정본 상태는 [`../README.md`](../README.md)와
> [`../CHANGELOG.md`](../CHANGELOG.md)** 입니다. 갭 해소 현황은 [`GAP_ANALYSIS.md`](GAP_ANALYSIS.md) 상단 배너를,
> 실 ICS 프로토콜 공방은 [`ICS-KILLCHAIN.md`](ICS-KILLCHAIN.md)를 참고하세요. 이 스펙 문서들은
> "왜 이렇게 지었나"의 설계 의도 기록으로 보존됩니다.

## 읽는 순서

**0. 시작점**
- `09_team_agents_roles.md` — 팀 에이전트 구성(빌드 B0~B6 + 콘텐츠 C0~C6). **여기서 역할 분배부터.**

**1. 플랫폼 빌드 (빌드 계층)**
- `04_backend_enhancements_spec.md` — 코어 백엔드(점수 연결/복구/dwell/Instructor/Config). **기반.**
- `05_scenario_as_code_spec.md` — 시나리오 as-code(다단계 킬체인).
- `01_siem_build_prompt.md` — 자체 SIEM(수집/정규화/탐지/대시보드).
- `06_detection_content_spec.md` — 탐지 룰셋 20종 + ATT&CK 커버리지 + 노이즈.
- `02_livefire_dashboard_prompt.md` — 공방 지휘통제 대시보드.
- `07_dashboard_extensions_spec.md` — 리플레이/분리뷰/AAR.
- `08_safety_hardening_spec.md` — 안전장치(격리/하드닝/킬스위치). **횡단, 필수.**

**2. 문제 출제 (콘텐츠 계층)**
- `10_challenge_design_by_domain.md` — 분야별 문제 기획(웹/포렌식/탐지/AI/리버싱/네트워크).
- `11_authoring_standard_and_qa.md` — 출제 표준 + C-QA 자동 검수.
- `12_reference_challenge_web002.md` — 레퍼런스 문제 패키지(모든 분야의 템플릿).

**3. 참고**
- `03_feature_roadmap.md` — 기능 우선순위 로드맵(★ 표기).
- `19_ansible_patch_console_and_noc_spec.md` — Blue팀 Ansible 패치 콘솔 + NOC 모니터링 대시보드.
- `20_edr_console_spec.md` — EDR 콘솔(팔콘 스타일): 프로세스/네트워크 텔레메트리, 행위기반 탐지, 호스트 격리.
- `21_build_environment_guide.md` — **다음 주 실제 빌드용**: GCP 서버 사양, 소프트웨어 준비, 리포 통합, 마일스톤별 진행 순서, 트러블슈팅.

**4. 아직 코드 없는 영역의 상세 계획 (파일/함수 시그니처 수준)**
- `22_siem_core_detailed_plan.md` — SIEM 코어(01번의 실행 사양). 파서/저장소/탐지엔진 함수 시그니처, 세부 마일스톤 M5.0~M5.6.
- `23_livefire_dashboard_detailed_plan.md` — Live Fire Dashboard(02·07번의 실행 사양). 컴포넌트 트리, zustand 스토어, 마일스톤 M6.0~M6.6.
- `24_instructor_console_api_detailed_plan.md` — Instructor Console API(04번 4절의 실행 사양). 신규 서비스 설계 + scoring_engine/scenario_engine에 추가할 엔드포인트.
- `25_cqa_pipeline_and_remaining_challenges_plan.md` — C-QA 검수 스크립트 8개 시그니처 + 분야당 7개로 채우는 챌린지 20개 목록 + 세션 배정.
- `26_wazuh_suricata_zeek_integration_plan.md` — Docker 네트워크 네임스페이스 공유 방식의 실제 연동법, Wazuh 우선순위 낮춤 판단 근거.
- `27_aar_sound_attack_coverage_detailed_plan.md` — AAR 리포트(MTTD/MTTR 계산 함수), 사운드 훅, ATT&CK 커버리지 컴포넌트.
- `28_load_testing_plan.md` — k6 시나리오, 임계치표, 실행 순서.
- `29_instructor_operations_manual.md` — 훈련 당일 런북(D-1 ~ 디브리핑), 이상상황 대응표.
- `31_challenge_verification_guide.md` — **챌린지 7개 전부 손으로 직접 검증하는 복붙 가능한 명령어 가이드** (전체 재현 확인 완료).

## 기존 산출물(코드)

- `cyber-range.zip` — 이미 구현된 트윈 3종 + Event Collector + Scoring Engine + safe_probe.
- `cyber-range-contracts.zip` — B0 공통 계약(스키마) + **실행 코드**:
  - `services/scenario_engine/` — 시나리오 로더 + 러너(단일 킬체인 순서판정, **크로스오버 phase 잠금해제**)
  - `services/config_service/` — 패치 무중단 토글 + 킬스위치 + 자산 격리(quarantine) + audit log
  - `services/patch_console/` — Ansible 패치 콘솔(화이트리스트 플레이북, 경로탈출 방어 검증됨)
  - `services/noc_monitor/` — NOC 모니터링(Health Poller, uptime/latency/에러율)
  - `services/edr/` — **EDR 콘솔 백엔드+프론트엔드**: 프로세스/네트워크 텔레메트리, 행위기반 탐지(EDR-001~003 검증됨), 호스트 격리, **Kill Process 실제 종료(SIGTERM→SIGKILL 승격, server_pid 기반 보호, 실제 프로세스로 검증됨)**, React 콘솔(`services/edr/console/`)
  - `services/core/recovery_watcher.py` — asset_recovered 3조건 판정(다운이력+패치확인+health)
  - `scenarios/` — 단일 3종 + 크로스오버 2종 YAML(실제 검증 통과)
  - `infra/ci/` — 시크릿 스캔, 네트워크 격리 회귀 테스트(실행 확인됨)
  - `infra/hardening/` — cap_drop/read-only/리소스제한 오버레이 + seccomp 생성 가이드
  - `infra/deploy/checklist.py` — 배포 전 체크리스트 자동화(7항목, 실행 확인됨)
  - `INTEGRATION.md` — cyber-range와 cyber-range-contracts를 함께 띄우는 통합 배포 가이드
- `cyber-range.zip` — 트윈 3종(**전부 Config Service + EDR 에이전트 연결 완료**) + Event Collector +
  Scoring Engine(v1.1) + docker-compose(config_service/edr_backend 포함)

위 문서들은 이 코드베이스를 확장하는 사양이다.

## 의존성 요약

```
09(역할) ─▶ 04(백엔드) ─┬─▶ 05(시나리오) ─▶ 콘텐츠(10,11,12)
                        ├─▶ 01(SIEM) ─▶ 06(탐지)
                        └─▶ 02(대시보드) ─▶ 07(확장)
08(안전) ─── 전 단계 횡단 적용
```

## 핵심 원칙(전 문서 공통)

- 모든 데이터/자격증명/취약점은 **더미·훈련용**. 실환경 격리 필수(08).
- Red↔Blue 균형: 모든 문제·시나리오가 공격 과제와 방어 과제를 함께 정의.
- 점수는 achievement 단위 멱등. 탐지·차단·복구가 모두 점수로 연결되어야 훈련 완결.
- 계약 우선: B0가 스키마/API 확정 후 병렬 개발.
