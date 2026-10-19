# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

기존 코드베이스가 답함: `dashboards/` 프런트는 React + Vite + 공유 디자인시스템(`dashboards/shared`).
이 콘솔은 그 스택을 재사용하는 **신규 서피스**로 신설하고(기존 `dashboards/redportal` 은 before
비교용으로 보존), 공유 토큰·빌드 관례를 상속한다. (사용자 확정, 2026-10-19.)

## Users

1차 사용자 = **라이브파이어 사이버 훈련의 Red 팀 작전자**(Locked Shields / Cyber Flag / 한국 CCE
급 국가 훈련 상황). 워룸/작전센터에서 정해진 교전 시간 안에 국가 기반시설 시설(발전소 등)을
정찰→침투→측면이동→물리/운영 피해로 몰아가는 임무를 수행한다. 플래그 제출자가 아니라 작전을
지휘·실행하는 operator 다. (블루 SOC 모니터링 사용자는 이 서피스의 대상이 아님 — 별도 SOC
Dashboard 프로젝트.)

## Product Purpose

현재 Red 포털(`dashboards/redportal`)이 "CTF 플래그 제출 UI"처럼 느껴지는 문제를 해결한다. 목표는
**실제 시뮬레이션 디지털 트윈에 라이브로 연결된 몰입형 Red 라이브파이어 작전 콘솔**: 작전자가
"내가 지금 발전소의 취약점을 파고들어 시설을 다운/파괴하고 있다"고 느끼도록, 공격 행위가 트윈의
실제 물리 상태(터빈 RPM·냉각수·SIS·DAMAGE)에 즉시 반영되는 경험. 성공 = 작전자가 단일 문제풀이가
아니라 **자격증명 탈취 → 내부망 측면이동 → 제어망 장악 → 물리 파국**의 킬체인을 작전으로 체감한다.

## Positioning

추상 데모 서비스(vulnerable_notes 등) 대신 **실 프로토콜(Modbus/TCP 502, DNP3 20000, IEC 104,
GOOSE)과 실제 물리 결과 모델을 가진 11개 ICS 섹터 트윈**에 근거한다는 점이 경쟁 CTF/레인지 UI가
베낄 수 없는 차별점. 공격→이벤트(킬체인 phase·점수)→물리 파국이 전부 기존 코드에 실제 구현돼 있고,
콘솔은 그 진실을 서사·피해 연출로 드러낸다(지어내지 않음).

## Operating Context

- 기함 트윈: `services/power_plant/main.py` — 홀딩 레지스터 HR0=TURBINE_RPM(명령), HR1=COOLANT_FLOW,
  HR2=ACTUAL_RPM(동역학 응답, slew 400rpm/s, nominal 3000), HR3=COOLANT_TEMP, HR4=DAMAGE%,
  coil0=SAFETY_INTERLOCK(SIS). 과속 한계 4500, 지속 과속+SIS 무력화 → `asset_compromised`(물리 파괴).
- 취약점 7종(내부망 호스트로 매핑): PP-002 기본 HMI 계정(초기 침투·자격증명) → PP-001 무인증 PLC
  쓰기 / PP-006 미인가 Modbus 쓰기(측면이동) → PP-003 진단 CMDi / PP-004 Historian 역직렬화(권한상승)
  → PP-005 안전 오버라이드 / PP-007 미서명 펌웨어(목표 달성). 각 라우트·이벤트 phase 매핑 확인됨.
- 킬체인 phase·점수: `shared/event_schema.py` RedPhase(initial_access/privilege_escalation/
  lateral_movement/data_exfiltration/objective). 라이브 이벤트는 `event_collector` 로 수집·스트림.
- 콘솔은 **라이브 트윈을 직접 구동**(사용자 확정): 콘솔이 트윈의 훈련용 엔드포인트를 호출 → 물리
  게이지가 event_collector 라이브 스트림으로 실제 반영. 자유 입력 + 가이드 어포던스 혼합.

## Capabilities and Constraints

- **범위**: Red 공격 경험만. ★블루 SOC 모니터링 대시보드는 만들지 않는다(별도 프로젝트).
- **시나리오 축**: 단일 취약점이 아니라 다단계 킬체인(자격증명 → 내부망 측면이동 → 제어망 장악)을
  중심 서사로. 시설 내부망 세그먼트(IT/엔지니어링WS → HMI → Historian → PLC/Modbus → SIS/안전망)를
  노드로 표현하고, 장악 phase 가 전진하도록 설계.
- **수직 슬라이스**: 발전소 기함 1개를 라이브로 완성, 나머지 10개 섹터는 확장 패턴으로 제시.
- **환경 제약**: 전체 스택(75+ 컨테이너) 동시 기동 금지. 발전소 트윈 + event_collector 등 최소
  묶음만 기동, 검증 후 내린다(메모리 ~11Gi, CPU 는 타 랩 부하 주의). 결함 1건=브랜치+회귀테스트.
- **진행 규약**: 결정·승인 필요 시 AskUserQuestion 설문으로 질문(사용자 확정, 2026-10-19).

## Evidence on Hand

실제 코드가 근거(지어내지 않음): 11 ICS 트윈 `services/<sector>/main.py` 상단 docstring(시설 정체성·
자산·취약점), 시설 테마 CTF 챌린지 서사 `challenges/`, 이벤트/채점 `shared/event_schema.py`·
`event_collector`, 공유 디자인시스템 `dashboards/shared`. 안티레퍼런스 = 기존 `dashboards/redportal`.

## Product Principles

1. **라이브가 몰입이다.** 모든 공격 행위는 실제 트윈 물리/이벤트에 반영된다 — 가짜 애니메이션 금지.
2. **단일 취약점이 아니라 작전이다.** 정찰→자격증명→측면이동→제어망 장악→물리 파국의 킬체인 서사.
3. **지어내지 않는다.** 자산명·프로토콜·포트·레지스터·취약점ID·점수는 전부 실제 코드에서 가져온다.
4. **작전센터 톤, CTF 금지.** 플래그 제출 UI 가 아니라 국가급 라이브파이어 훈련의 워룸 경험.
5. **블루 미구축.** SOC 모니터링은 범위 밖(별도 프로젝트) — Red 작전 경험에만 집중.

## Accessibility & Inclusion

플랫폼 공통 접근성 유지(공유 디자인시스템 기준). 작전센터 다크 환경 가독성(저조도 대비) 고려.
