# 다음 세션 프롬프트 — 몰입형 Red 라이브파이어 작전 콘솔

> 이 파일을 다음 세션 첫 메시지로 붙여넣고 시작하세요. 아래 "프롬프트" 블록이 본문입니다.

---

## 프롬프트 (복사해서 사용)

너는 이 저장소(`cyber-range-platform`)의 시니어 제품 디자이너 겸 풀스택 엔지니어다.
플랫폼 자체(v1.1.0, 130 챌린지·11 ICS 트윈·A/D 엔진·SIEM/EDR·8h 소크 검증 완료)는 이미
탄탄하다. 이번 임무는 **"CTF 문제풀이처럼 느껴지는 Red 팀 경험"을 Locked Shields 급
라이브파이어 작전 몰입 경험으로 재설계**하는 것이다.

### 목표(사용자 원문 정리)
- "진짜 내가 **병원을 공격하고 있구나**, **발전소의 취약점을 발견해 파고들어 공격하고
  있다**"는 몰입. 지금 Red 포털은 그냥 플래그 제출 UI라 아쉽다.
- **레드 관점**: 목표 = **시설을 다운/파괴**. 정찰(recon) → 취약점 발견 → 익스플로잇 →
  **실제 물리/운영 피해**(터빈 과속·SIS 무력화 → 파국/정전) → 킬체인 진행.
- **블루**: 탐지·사전 패치 메커닉은 존재하되, **SOC 모니터링 대시보드는 별도 "SOC Dashboard"
  프로젝트가 담당** → 이 작업에선 **SOC 대시보드를 만들지 말고 Red 공격 경험에 집중**.
- **톤/미학**: Locked Shields(NATO CCDCOE)·Cyber Flag(US CYBERCOM)·한국 CCE 같은
  **국가급 라이브파이어 훈련의 작전/워룸(command-center) 분위기**. CTF 느낌 금지.
  (참고: Locked Shields 2026 = 41개국 4,000명, ~6,000건 공격 방어, 보호대상=에너지그리드·
  방공·전자투표·5G·위성.)

### 왜 지금 CTF처럼 느껴지나(진단, 이미 확인함)
- 내가 띄운 A/D 공방 타깃이 **추상 데모 서비스**: `services/attack_defense/demo_services/`
  의 `vulnerable_notes`·`file_vault`·`grid_scada` → "문제 푸는" 느낌.
- 반면 **진짜 몰입 재료는 11개 ICS 트윈**(실 프로토콜 Modbus/DNP3 + 물리 결과)인데 Red
  포털이 그걸 서사/피해로 안 보여주고 플래그 UI로만 노출함.

### 진짜 도메인에 근거할 것(지어내지 마라)
- **발전소 기함**: `services/power_plant/main.py` — 실 Modbus/TCP·DNP3, holding registers
  (터빈 RPM·냉각수 유량 등), **SIS 안전 인터록(coil 0)**, 취약점 PP-001~007(각 엔드포인트:
  `/api/plc/write`·`/api/modbus/write-register`·`/api/safety/override` 등), 그리고
  **과속+SIS무력화 → `asset_compromised`(물리적 파괴) 체인**이 실제 구현돼 있음. 포트 Modbus
  502/DNP3 20000.
- **킬체인 단계**: `shared/event_schema.py` `RedPhase`(initial_access+20 / privilege_escalation
  +30 / lateral_movement+30 / data_exfiltration+50 / objective+100), `EventType`.
- **11개 섹터 트윈**: `services/` 의 power_plant·hospital_ot·water_utility·lng_terminal·
  railway_signaling·airport_ot·refinery_plant·datacenter_bms·ground_station·smart_factory·
  defense_network (각 main.py 상단 docstring에 시설 정체성·자산·취약점).
- **시설 테마 챌린지 서사**: `challenges/` 에 한국석유공사·인천 LNG·철도관제·상수도 등
  실 기반시설 서사 문구 다수(challenge.yaml name/description).
- ★다음 세션 시작 시 이 재료부터 Explore 서브에이전트로 정밀 수집(이전 세션에서 수집 중
  중단됨): 실 레지스터 값·취약점명·물리결과·서사 문구.

### 만들 것 (deliverable)
1. **몰입형 Red 라이브파이어 작전 콘솔** — `impeccable` 스킬로 최고 craft.
   - 섹터 선택(국가 기반시설), 미션 브리핑(목표=시설 다운), **정찰 뷰**(시설 자산맵·실
     프로토콜·노출 서비스), **취약점 발견→익스플로잇 워크벤치**, **실시간 물리 상태 게이지**
     (터빈 RPM·압력·SIS 상태 — 공격하면 실제로 움직임), **피해/파국 연출**(정전·파괴 알람),
     **킬체인 진행 트래커**, 점수.
   - 실제 트윈에 연결: 발전소 트윈을 띄워 공격→물리결과가 UI에 진짜로 반영되게(최소 기함 1개
     수직 슬라이스 완성, 다른 섹터로 확장 패턴 제시).
2. **before/after 스크린샷**(desktop+mobile): before=기존 `dashboards/redportal`(CTF스러움),
   after=새 작전 콘솔. (스크린샷 도구: REA `capture_web_screenshot` 또는 built-in browser.)

### 범위/주의
- **SOC/블루 모니터링 대시보드는 만들지 말 것**(별도 SOC Dashboard 프로젝트 협업 예정).
- 기존 `dashboards/redportal`(React/vite, 포트 5176)을 재설계/대체할지, 새 콘솔로 갈지는
  impeccable new-work 로 판단(기존은 anti-reference).
- 결함 1건당 브랜치+회귀테스트, push→PR→CI(13잡)→squash 머지. 커밋/PR attribution 라인 유지.
- **세션 말 프로젝트 도커 전부 down**(사용자 타 프로젝트 `rampart-lab-*`·`pentagi`는 유지).

### 환경/운영 메모
- RAM 11Gi. **CPU 주의**: 사용자 타 랩 `rampart-lab-wazuh`가 CPU 절반 이상 먹어 load ~20
  스파이크 → 대시보드 느림의 주원인(이 프로젝트 스택은 ~4%). 사용자 동의 시
  `docker pause rampart-lab-*`로 코어 확보 가능(되돌림: unpause).
- 포트 **8080 점유**(다른 랩 web) → edr 충돌. A/D 공방은 edr 불필요(무관).
- A/D 기동: `set -a; source .env; set +a; make attack-defense-demo`(엔진 8100·auth 8051·
  게이트웨이 9101~9303·팀서비스). 플래그는 라운드마다(~60s) 로테이션. fresh:
  `make attack-defense-reset`.
- 팀 로그인: auth 8051 `/auth/login` team01/`demo-team-01-change-me`(team-1), 02/03도.
  이 토큰에 team_id·match_id 클레임 있어 flags/submit 바로 됨. CORS는 localhost:5176 허용.
- 데모 타깃 취약점 예: Vulnerable Notes IDOR(`GET /api/notes/{id}` 소유권 미검증).
- 참고 스크립트: `<scratchpad>/ad_solve.py`(등록→IDOR→제출 자동, 이전 세션 산출).
- 상태: main `ea15695`, 태그 v1.0.0/v1.1.0, 백엔드 758 passed/6 skip, CI green, open PR 0.

### 먼저 할 일
1. Explore 서브에이전트로 발전소 물리·취약점·킬체인·11섹터·서사 재료 정밀 수집.
2. `impeccable` 스킬 로드 → new-work 로 작전 콘솔 비주얼 월드 결정(워룸/라이브파이어).
3. 발전소 트윈+event_collector 최소 기동(CPU 여유 확인 후) → 콘솔 라이브 연결.
4. 콘솔 구현 → before/after 스크린샷 → 사용자에게 제시.
