# 변경 이력 (Changelog)

형식: [Keep a Changelog](https://keepachangelog.com/), 버전: [SemVer](https://semver.org/).

## [Unreleased]
### Added
- **Incident 자동 강화(이벤트 상관)**: incident 서비스가 event_collector 이벤트를 폴링해 자산 복구
  (asset_recovered)를 관련 미해결 인시던트(host 일치)의 타임라인에 **해결 힌트 주석**(recovery_detected)
  으로 자동 기록. **자동 close 하지 않음**(Blue 가 검토·종결 — SOC 훈련 주체성 유지). 중복 주석 방지.
  순수 상관 로직 `model.find_resolvable()` + 유닛 6개(248→254). 실측: airport 공격→SIEM 자동인시던트→
  복구→타임라인 `recovery_detected` 주석·status 미변경(new 유지) 확인.
- **SIEM 알림 → Incident 자동 승격(SOC 워크플로)**: SIEM 이 고심각도 알림(severity ≥ INCIDENT_MIN_SEVERITY,
  기본 5)을 감지하면 incident 서비스로 자동 승격(`/incidents/from-alert`). `rule_id:asset` 키로 **dedup**
  (자산당 위협 1건, 재공격에도 미증가). SIEM 탐지 → 자동 케이스 생성 → 인시던트 라이프사이클(triage→
  closed·SLA·MTTR) 로 연결. 실측: railway 크리티컬 공격 → 2 규칙 → 인시던트 2건 자동생성, 재공격 시
  dedup 유지(2 고정). compose env INCIDENT_URL/AUTO_PROMOTE/MIN_SEVERITY.
- **AAR PDF ICS 섹션**: `pdf/render.py` 가 `ics_lifecycle` 를 PDF 에 렌더 — 자산별 공격/침해/방어/
  복구/MTTR/기법 표 + 총계. 인쇄 리포트로도 ICS 공방 확인. 실측: 라이브 /report/aar/pdf 200·
  application/pdf·5816B(ICS 섹션 포함), 무회귀.
- **AAR ICS 라이프사이클 종합**: `/report/aar` 에 `ics_lifecycle` 섹션 — 이벤트 스트림에서 9개 ICS
  자산별 공방(공격/침해/방어/복구 횟수·**MTTR**·MITRE 기법) + 총계(침해/복구 자산 수·평균 MTTR)
  집계. 순수 요약 + 유닛 5개(243→248). 실측: 라이브 AAR 에서 자산별 라이프사이클·smart_factory
  MTTR 402s 등 집계 확인.
- **Control Tower ICS 자산 상태판**: SSE 이벤트(red_attack_started/asset_compromised/blue_block_success/
  asset_recovered)만으로 9개 ICS 트윈 상태를 색상 추적(공격중·파괴/침해·방어됨·복구됨) + MITRE 기법
  표시 — 백엔드 추가 없이 이벤트 스트림 파생. 실측 캡처(control-tower-ics.png): 9개 트윈 상태·라이브
  피드(asset_compromised·asset_recovered·blue_block_success·점수) 동시 표시.
- **복구 채점 연동 + 복구 포함 ICS 시나리오**: asset_recovered → scoring 이 Blue **복구 크레딧 +50**
  부여 확인(실측: 자산당 1회, achievements 기록). `scenarios/single/RAILWAY-MODBUS-SABOTAGE-01.yaml`
  저작 — 신호조작→Modbus 연동 우회→열차 탈선 킬체인 + Blue 탐지·**복구 목표**(blue_objective
  `match_event: asset_recovered`). P1-3 도구 검증(lint-all 15→16 시나리오 0-error·dry-run 150점·
  phase-clock) + 러너 테스트 2개(238→243). 완전 라이프사이클(compromise→block→recover) 저작·채점.
- **ICS 자산 회복(damage heal + asset_recovered) — 재실행 가능**: `process_sim.step()` 에 회복 추가 —
  인터록 재무장 + 안전 상태에서 손상(damage)이 heal_rate 로 회복(누적은 인터록 해제 시에만). 손상
  자산이 확보돼 0 으로 회복되면 트윈이 **asset_recovered** 발행(Blue 복구 크레딧). 파국 상태 고착
  해소 → **같은 트윈으로 공격/방어 재실행 가능**. 전 9개 트윈 적용(헬퍼 + power_plant/water_utility
  인라인). 유닛 3개(238→241). 실측: smart_factory·power_plant 공격→확보→DAMAGE 0 회복→asset_recovered.
  검증 과정에서 발견(damage 비회복으로 재실행 불가 → 수정).
- **ICS 실 Modbus 전 섹터 확장(9개 트윈)**: 재사용 헬퍼(`twin_modbus.attach_modbus_ics`)로
  smart_factory(로봇 충돌 FAC-004)·railway_signaling(탈선 RWY-002)·airport_ot(급유 화재 AIR-003)·
  datacenter_bms(열폭주 DCX-001)·hospital_ot(약물 과다투여 HSP-003)에 실 Modbus 502 추가 → **9개 ICS
  섹터 전부 실 Modbus**(각 ~15줄). SIEM 규칙 ICS-MODBUS-WRITE-FAC/RWY/AIR/DCX/HSP 추가(총 9종).
  실측: 5개 신규 트윈 컨테이너 내 실 Modbus 응답, railway 공격 → 라이브 탐지(ICS-MODBUS-WRITE-RWY
  → blue_detection_success 5×) → Blue +100.
- **ICS 실 Modbus 트윈 확장(refinery·lng) + 재사용 헬퍼**: `shared/ics/twin_modbus.py` —
  검증된 power_plant/water_utility 배선(실 Modbus+연속물리+안전결과+MITRE 탐지+Blue 방어)을
  `attach_modbus_ics(app, cfg)` 한 줄로 패키징. **refinery_plant**(증류탑 과압→폭발, REF-004)·
  **lng_terminal**(탱크 과압→파열, LNG-001)에 적용 → 실 Modbus 502. SIEM 규칙 ICS-MODBUS-WRITE-REF/LNG
  추가. 헬퍼 유닛 3개(235→238). 실측: 4개 ICS 트윈 컨테이너 내 실 Modbus, refinery 공격 → 라이브
  탐지(ICS-MODBUS-WRITE-REF 3× blue_detection_success) → Blue 점수 +60.
- **역할별 홈(App Shell)**: gateway `/`(홈)이 `/auth/me`로 역할을 확인해 RBAC상 허용 앱 카드만
  노출 + 주 화면 강조 + 사용자/역할/로그아웃 바(`infra/gateway/landing.html`). 로그인 후 `/`(홈)으로
  라우팅. 실측(gateway+로그인, Playwright): instructor 6장·red 2장(Red·LiveFire)·blue 4장 필터 확인.

### Verified / CI
- **풀스택 도커 통합 검증**: 신규 3종 + 변경 13종 서비스 컨테이너 빌드·기동(11/11 헬스 200) →
  스모크 36/36(SSE 포함) → 챌린지 QA 69/69 → 신규 서비스 E2E(observability 12/12 스크레이프) →
  컨테이너 내 실제 Modbus(pp_twin:502) 전부 실배포 확인.
- **ICS 탐지→채점 라이브 폐루프 검증**: 컨테이너 간 Modbus 공격(T0878 인터록무력화·T0836 과속) →
  트윈 SIEM 로그 → 라이브 SIEM DetectionEngine(ICS 규칙) → blue_detection_success → **Blue 점수
  200→260(+60)** 실측. (siem_api 재빌드로 ICS 규칙 로드)
- **CI 확장**: `.github/workflows/ci.yml` integration 잡에 신규 서비스(auth·incident·injects·
  observability·challenge_portal·range_control·water_utility) 빌드/기동/헬스 + SSE·관측성·컨테이너
  Modbus(`infra/ci/modbus_probe.py`) E2E 스텝 추가. unit 잡은 235 유닛 자동 실행.

### Added
- **water_utility 대칭 확장 — 화학 과투입 연속물리·파국·Blue 방어**: `process_sim` 재사용(터빈=농도
  유추)으로 두 번째 ICS 트윈을 power_plant 수준으로. 저수조 염소농도(HR2)가 투입설정으로 수렴(혼합
  slew), 인터록 정상이면 4ppm 캡, 해제되면 오염 손상(HR5) 누적 → 급수오염 파국(asset_compromised,
  water_supply_contamination). 위험 중 Blue 인터록 재무장 → blue_block_success. 실측: 인터록 ON 4ppm
  캡·손상0, OFF 오염누적, Blue 재무장 → blue_block_success·손상 플래토 확인.
- **ICS 시나리오 러너 런타임 검증**: 저작한 POWERPLANT-MODBUS-SABOTAGE-01 을 실제
  `SingleScenarioTracker` 에 통과 — Modbus 공격 이벤트(PP-002→PP-006→asset_compromised)로
  스테이지 자동판정(1/2/3)·점수(25/45/80)·chain_bonus(50)·requires_stage 순서강제 검증. 유닛 5개
  (230→235). ICS 공방이 취약트윈→공격→물리결과→탐지→방어→시나리오 채점까지 런타임 폐루프.
- **ICS 킬체인 시나리오 저작**: `scenarios/single/POWERPLANT-MODBUS-SABOTAGE-01.yaml` — 실제 Modbus
  SIS 무력화 킬체인(HMI 접근 → 인터록 OFF → 지속 과속 파괴)을 교관용 훈련 시나리오로 저작. Blue
  탐지목표(ICS-MODBUS-WRITE-PP·ICS-SAFETY-INTERLOCK-SUPPRESS) 포함. P1-3 도구로 검증: 스키마 로드·
  lint 0-error·dry-run(150점, expected_sec 타임라인)·phase-clock 통과. lint-all 14→15 시나리오 0-error.
- **P1-1 — Blue 방어 액션 채점(SIS 재무장)**: 위험 상태에서 Blue 가 안전 인터록을 재무장
  (Modbus coil0→ON)하면 `blue_block_success` 발행 → Blue 점수. `process_sim.in_danger()` 순수판정.
  재무장 시 다음 tick 부터 트립이 걸려 파국 방지 — Red 의 T0878 무력화와 대칭. 유닛 1개(229→230).
  실측: 공격 중(DAMAGE=10) Blue 재무장 → blue_block_success·DAMAGE 플래토(파국 없음) 확인.
- **P1-1 심화 — 물리 손상·SIS 트립 연결**: `process_sim.step()` 에 인터록 인지 추가 — 인터록 정상이면
  redline(4500)에서 **트립(RPM 캡)·손상 0**, 해제되면 지속 과속/과열이 **누적 손상 → 파국**
  (failure_threshold). power_plant 배경 루프가 HR4=DAMAGE 갱신 + 파국 에지에 `asset_compromised`
  (catastrophic_failure) 1회 발행. 유닛 4개(225→229). 실측: 인터록 ON=4500 캡·손상 0, OFF+냉각차단
  → DAMAGE 3→42→100 → catastrophic_failure(rpm 6900) 확인. 공격자는 SIS 무력화 후 '지속'해야 파괴.
- **P1-1 심화 — ICS 연속 물리 시뮬**: `shared/ics/process_sim.py` — 레지스터가 순간값이 아니라
  동역학적으로 반응. 터빈 RPM 은 명령값으로 slew-rate(400rpm/s) 제한 상승, 냉각수 온도는 RPM 발열·
  유량 냉각으로 변화(주변온도 하한). power_plant 배경 루프가 HR2=ACTUAL_RPM/HR3=COOLANT_TEMP
  텔레메트리 갱신(읽기전용). 순수 step() 유닛 7개(218→225). 실측: 6000 명령+유량 차단 → ACTUAL
  3000→3400→3800→4200(slew), TEMP 40→46→60→82(승온) Modbus 읽기로 확인.
- **P1-2 슬라이스 — defense_network 실제 SMTP + 오픈 릴레이(DN-004)**: `shared/net/smtp_server.py`
  세션 상태머신(HELO/MAIL/RCPT/DATA/QUIT) + asyncio 서버. defense_network 가 25 에서 진짜 SMTP 를
  말하고, 인증 없이 외부 도메인 릴레이 수락 시 취약(패치되면 550). 릴레이 시 DN-004 이벤트 + SIEM
  로그(기존 DN-004 규칙이 blue_detection_success 로 연결). 유닛 8개(210→218). 실측: stdlib smtplib
  로 외부 릴레이 성공(open relay)·패치 시 550 거부·DN-004 이벤트/SIEM 로그 확인.
- **P1-1 red→blue 폐루프 — ICS Modbus 탐지→채점**: ICS 트윈이 Modbus 활동을 SIEM access 로그로
  발행(`get_siem_logger`), SIEM 탐지 규칙(`ics_layer.yaml`: ICS-MODBUS-WRITE-PP/WU·
  ICS-SAFETY-INTERLOCK-SUPPRESS, `raw.ics_technique` 매칭) → 알림 → 기존 `blue_detection_success`
  push → Blue 점수+dwell 보너스. 실제 엔진+트윈 파서 통과 유닛 5개(205→210). 실측: 트윈이 T0836/
  T0878 로그 라인 기록·규칙 매칭·정상 이벤트 오탐 없음 확인.
- **P1-1 red→blue — ICS Modbus 이상탐지**: `shared/ics/anomaly.py` — Modbus 쓰기를 MITRE ATT&CK
  for ICS 로 분류(T0836 Modify Parameter·T0855 Unauthorized Command·T0878 Suppression of Alarms).
  power_plant·water_utility 트윈이 각 Modbus 이벤트 metadata 에 ics_technique/severity/reason 을
  실어 발행 → Blue/SIEM 탐지 신호. 유닛 7개(198→205). 실측: in-band 보호쓰기=T0855, 밴드이탈=T0836
  critical, 인터록 해제=T0878 확인.
- **P1-1 확장 — water_utility 실제 Modbus**: 두 번째 ICS 트윈도 502 에서 진짜 Modbus 를 말한다
  (`shared/ics/modbus.py`+`safety.py` 재사용 실증). 홀딩 0=CHLORINE_PPM/1=INTAKE_PUMP_RATE,
  코일 0=인터록. 무인증 쓰기 → WTR-001 이벤트, 염소 >4ppm+인터록 해제 → asset_compromised
  (chemical_overdose_public_health). 실측: 실 Modbus 로 8ppm 과투입, 인터록 ON=억제·OFF 후=임팩트.
- **P2-3 반응형(태블릿/모바일)**: Control Tower 를 ≤900px(태블릿)·≤600px(모바일)에서 세로 스택
  (flex-column)으로 재배치 — 라이브 피드 우선(order), 헬스 칩 가로 스크롤, 조작 바 하단, 피드 2열
  (시간+내용), 터치 타깃 확대. 실측 캡처(control-tower-mobile.png): 390px 가로 스크롤 없음·풀폭
  단일 컬럼·820px 태블릿 스택 확인.
- **P2-2 워룸 모드**: Control Tower 에 대형 화면(프로젝터) 모드 — `▣ WARROOM` 버튼·키보드 `W`
  로 고대비·대형 폰트(피드 19px/점수 26px)·조작바 숨김(읽기전용) 토글, localStorage 유지.
  실측 캡처(docs/images/control-tower-warroom.png): warroom 활성·controls 숨김·피드 70행 확인.
- **P1-1 심화 — ICS 물리 안전 결과**: `shared/ics/safety.py` — 레지스터 한계(min/max)+안전
  인터록 프로파일로 위험 상태 판정. 인터록 걸림=억제(high), 해제=임팩트(critical). power_plant
  Modbus 쓰기에 배선 → 과속(>4500)·저유량(<50) + 인터록 해제 시 `asset_compromised` 발행
  (scenario 안전임팩트 목표 연동). 유닛 6개(192→198). 실측: 인터록 ON 과속=억제(PP-006만),
  인터록 OFF 후=asset_compromised(over_max/critical) 확인.
- **P2-4 AAR 확장**: `services/aar_report/integrations.py` — `/report/aar` 에 이번 세션 하위시스템
  종합 섹션 추가: incident_management(SLA·MTTA/MTTR·심각도별), crisis_comms(인젝트 대응률·정시율·
  점수%), integrity(플래그 공유 담합), ics_protocol_attacks(실제 Modbus 등 프로토콜 공격). 각 서비스
  best-effort 수집(없으면 빈 섹션), replay metadata 문자열 정규화. 유닛 8개(184→192). 실측: 인시던트
  MTTA/MTTR·인젝트 88%·Modbus TURBINE_RPM 공격 집계·PDF 무회귀(200) 확인.
- **P1-1 트윈 프로토콜 리얼리즘(실제 Modbus/TCP)**: `shared/ics/modbus.py` — 순수 PDU 처리
  (FC1 코일읽기·FC3/4 레지스터읽기·FC5 코일쓰기·FC6 단일쓰기·FC16 다중쓰기·예외응답 01/02/03)
  + asyncio TCP 서버(MBAP 프레이밍). power_plant 트윈이 502 에서 **진짜 Modbus 를 말한다** —
  홀딩 0=TURBINE_RPM/1=COOLANT_FLOW, 코일 0=SAFETY_INTERLOCK. Modbus 무인증 쓰기는 PP-006
  이벤트 발행(scoring 연동), HTTP `/api/plc/read` 와 상태 일관. 유닛 8개(176→184). 실측: 실 Modbus
  클라이언트로 RPM 6000 과속·안전인터록 OFF 공격 → 상태 반영·PP-006 이벤트 2건 확인.
- **P1-3 시나리오 저작 지원**: `services/scenario_engine/authoring.py` — 스키마 너머 의미 검증
  (lint: 중복 stage·requires 참조·전방참조·vuln 참조·최종 stage·blue 목표), 실행 없는 dry-run
  (타임라인 투영·총점·errors/warnings), phase_clock(경과→현재 예상 stage/잔여). 단일+크로스오버
  (phase_*.stages 수집) 모두 지원. 엔드포인트 /scenario/validate·/lint-all·/{id}/phase-clock,
  gateway /api/scenario. 유닛 16개(160→176). 실측: 저장된 14시나리오 lint 0-error·깨진 YAML 오류탐지·
  phase-clock(1800s/3stage) current_stage 판정 확인.
- **P2-5 플랫폼 관측성**: `services/observability`(8097) — 컨트롤플레인 전 서비스 /health 를
  비동기 스크레이프해 Prometheus 노출형식(`/metrics`: cr_service_up·scrape_ms·health 숫자필드
  게이지·cr_platform_services_up)과 JSON 요약(`/observability/summary`)으로 노출(무계측·최소침습).
  gateway `/metrics`(Prometheus용 비인증)·`/api/observability`(인증), Control Tower 헤더에 plat N/M up
  지표. model.py 순수로직 + 유닛 8개(152→160). 실측: docker 서비스 스크레이프·다운서비스 up 0·
  payload 카운터(challenges=56) 확인.
- **P1-4 비기술 인젝트**: `services/injects`(8096) — 위기 커뮤니케이션 훈련. 내장 인젝트
  라이브러리(언론/경영/규제/법무, 마감·루브릭 포함) + 교관 커스텀 디스패치, 팀 인박스(도착·마감·
  상태), 응답 제출 시 정시/지각 자동판정, 교관 루브릭 채점(항목별 상한 clamp)→지각 감점→최종점수,
  팀별 성과 스코어보드(대응률·정시율·점수%). 채점 시 stage_completed 이벤트. model.py 순수로직 +
  유닛 10개(142→152). docker-compose+gateway+prod env, Control Tower 헬스 연동. 실측: 디스패치·인박스·
  정시응답·중복409·루브릭 22/25·지각 감점(20→10) 확인.
- **Incident Case Management(P1)**: `services/incident`(8095) — SIEM/EDR 알림→인시던트 승격
  (alert_id 중복방지), 라이프사이클 상태머신(new→triage→contained→eradicated→recovered→closed,
  역행·건너뛰기 거부), 전 변경 타임라인, 심각도별 SLA(응답/해결) 위반 리포트, AAR 연동(MTTA/MTTR).
  RBAC(쓰기 blue/instructor·읽기 게이트), 승격 시 blue_detection_success 이벤트. docker-compose
  +gateway `/api/incident` +prod env, Control Tower Incidents 패널(SLA 위반 강조). 유닛 17개(125→142).
  실측: 승격·중복409·불법전이409·풀 라이프사이클·SLA위반 리포트·AAR 타임라인 확인.
- **P1-5 공정성/안티치트**: `services/challenge_portal/anticheat.py` — 플래그 제출 rate-limit
  (슬라이딩 윈도)·연속오답 lockout(백오프)·전 제출 감사(sqlite, 플래그는 해시만)·팀간 동일플래그
  공유 탐지. red/blue submit 에 배선(429 차단), 담합 시 unmatched_detection 이벤트로 교관 가시화.
  교관 조회 엔드포인트 /portal/anticheat/audit·/flagged. 유닛 9개(116→125). 실측: 4회초과 429,
  감사 기록, /flagged 담합(team_a·team_b 동일플래그) 탐지 확인.
- **Control Tower(통합 관리 콘솔)**: `dashboards/control-tower/index.html` — 단일 화면에서 11개
  서비스 헬스·SSE 실시간 피드(P0-4)·라이브 스코어보드·매치·안전상태 + 시나리오/긴급정지/초기화
  컨트롤. gateway `/control/`(auth 게이트) + 랜딩 카드, dev 직접포트 모드 자동감지. self-contained
  HTML(빌드 불필요). 실측 캡처(docs/images/control-tower.png): SSE 170행·헬스 8/11·초기화 write 확인.
- **P0-4 실시간 푸시(폴링 제거)**: `shared/sse_bus.py` SSE 단일 허브 + `event_collector`
  `GET /stream`(토픽 events/detections/scores/safety/phase_clock, JWT 역할·매치 필터, 관전자 30초
  지연, Last-Event-ID 리플레이) + `POST /internal/publish`(S2S safety/phase_clock). 대시보드 `useSSE()`
  (EventSource+백오프)로 폴링→구독 전환(Live Fire 리더보드 push). `loadtest/sse_loadtest.py`(스레드).
  실측: 관전자 100+팀 8 동시 108연결에서 반영 지연 **p95 77ms**(목표<1s). ingest 상한 ~23/s(sqlite
  fsync·단일워커, SSE 무관)는 정직히 기록. SSE 버스 유닛테스트 10개(총 106→116).
- **P0-2 인증/세션/감사**: `auth` 서비스(8051) — 사용자 계정(PBKDF2 해시)·CSV 일괄등록, 로그인 →
  단기 access JWT(15분)+refresh(8h, role/team_id/match_id 클레임)·httpOnly 쿠키, `/auth/revoke`
  즉시 폐기. `shared/rbac.py`가 JWT 서명 검증(정적 토큰 하위호환). gateway 로그인 게이트
  (auth_request로 무인증 차단→/login, 쿠키→Bearer 주입). 역할×엔드포인트 pytest 매트릭스(25).
  실측: 무인증 302→/login, red→instructor 전용 403, instructor 200, 위조/오답 401.
- **P0-1 단일 진입점/프로덕션 배포**: `gateway`(nginx) 서비스 — 5개 대시보드를 프로덕션 빌드해
  서브경로(/ops·/red·/blue·/blue/siem·/blue/edr)로 정적 서빙 + `/api/*` 백엔드 프록시 + self-signed
  TLS 자동 생성 + http→https. 랜딩(역할 선택). `docker-compose.prod.yml`(fail-fast·OBSERVER_READ_ENFORCE).
  프론트는 same-origin `/api/<svc>`로 연결(포트 하드코딩 제거, 상대 WS 지원). 스모크 35/35 유지.
- **P0-3 영속성**: event/scoring/config/siem/edr/instructor/noc/portal/range_control 상태를 named
  볼륨(`DATA_DIR=/data`)으로 백업 → force-recreate/crash-replace 생존. 크래시복구 스모크
  (`SMOKE_CRASH_RECOVERY=1`) 추가.
- **저장소 위생**: LICENSE(Apache-2.0), SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, `.env.example`,
  `scripts/gen_secrets.sh`.
- **실전 운영(P1 #9/#10/#11)**: Range Control 서비스(8055) — Match 레지스트리·Reset/Snapshot/
  Drift/Verify-Baseline·Safety Control(긴급정지·격리 상태). 교관 콘솔 UI.
- **멀티테넌트**: 매치별 물리 트윈 셋(11섹터, `deploy_match.sh`)·매치별 플래그 회전·관전자 지연
  큐(`/events/delayed`)·매치 vhost(`match_proxy` 8088). (docs/MULTI-TENANT.md)
- **Red/Blue Portal**: 챌린지 목록·아티팩트·제출·채점·스코어보드·CTF 시각화. 팀 드롭다운.
- **챌린지**: BACnet/Foundation Fieldbus/EtherNet-IP·CIP/S7comm/MQTT-Sparkplug red+blue(69종,
  12대 OT 프로토콜). ProcessImpact 패널·vitest.
- **문서**: docs/GAP_ANALYSIS.md(코드 실측 갭 분석), docs/writeups/(공방 가이드·답지), docs/TEAMS.md.

### Fixed
- 원격 접속(WSL/Tailscale): 대시보드 hostname 기반 백엔드 연결 + CORS 확장.

## [1.0.0] - 이전
- 초기 플랫폼: 11 ICS/OT 섹터 트윈·EDR·SIEM·시나리오 엔진·Live Fire·AAR·RBAC·CTF 챌린지.
