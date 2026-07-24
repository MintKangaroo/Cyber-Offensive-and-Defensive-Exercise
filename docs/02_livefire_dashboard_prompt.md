# Live Fire Dashboard — Claude Code 멀티에이전트 빌드 프롬프트

> Live Fire 공방 플랫폼의 **실시간 지휘통제 대시보드**. SIEM 대시보드와는 **분리된 별도 앱**입니다.
> 백엔드는 이미 구축된 Event Collector(:8010)와 Scoring Engine(:8020)을 소비합니다.
> 데이터 소스는 SIEM과 다릅니다: SIEM은 "로그/탐지"를, 이 대시보드는 "공방 진행/점수/자산 상태/플래그"를 봅니다.

---

## 0. 한 줄 정의

**Red vs Blue 공방을 실시간으로 지휘·관전하는 SOC 워룸형 대시보드. 자산 지도, 이벤트 타임라인, 점수판, 패치 현황, 플래그 추적, 교관 콘솔을 한 화면에서 제공.**

---

## 1. 디자인 방향 (중요 — 템플릿 회피)

- **컨셉**: 전술 지휘통제(command-center) HUD. Red팀/Blue팀 대립을 **색으로 인코딩**.
- **팔레트**:
  - base 딥 네이비블랙 `#0A0E1A`, panel `#111725`, border `#1E2A3F`
  - Red team: 앰버 `#F5A623` / 레드 `#FF4D4D`
  - Blue team: 시안 `#22D3EE`
  - flag/exfil 경보: 마젠타 `#E84BC9`
  - text: `#E8EDF5`(주), `#6B7A99`(보조)
- **타이포**: 디스플레이=전술 지오메트릭(예: Chakra Petch/Rajdhani 계열), 데이터/텔레메트리=모노스페이스(JetBrains Mono 계열). 헤더는 넓은 자간 대문자.
- **모션**: 신규 이벤트 슬라이드인, 자산 피격 시 펄스, 점수 증가 카운트업. 과하지 않게 — 시그니처는 "자산 지도의 실시간 피격 애니메이션" 하나에 집중.
- **접근성**: 색만으로 팀 구분하지 말 것(아이콘/라벨 병행), reduced-motion 존중, 키보드 포커스.

---

## 2. 화면 구성 (제안서 11장 기반 + 확장)

### 2.1 Range Overview (상단 헤더 바)
- 전체 상태 배지(시나리오 진행중/대기/종료), 경과시간 타이머
- Red 총점 vs Blue 총점 (대형 대비 표시, 실시간 카운트업)
- 진행 중 시나리오명, 참가 팀 수

### 2.2 Asset Map (핵심 시그니처)
- 4개 구역: 위성 지상국 / 발전소·SCADA / 국방망 / DMZ
- 각 자산 노드 상태: `secure`(파랑) / `under_attack`(앰버 펄스) / `compromised`(빨강) / `recovered`(초록 플래시)
- 자산 간 연결선에 트래픽/공격 흐름 애니메이션
- 노드 클릭 → 해당 자산의 취약점/이벤트 상세 패널

### 2.3 Event Timeline (우측 스트림)
- WebSocket(`ws://event_collector:8010/ws`) 구독, 신규 이벤트 상단 슬라이드인
- 이벤트 타입별 색/아이콘: 공격(앰버), 탐지(시안), 패치(초록), 유출(마젠타), 복구(초록)
- 필터: 팀/자산/이벤트타입, 일시정지(스크롤백) 토글

### 2.4 Score Board
- 팀별 Red/Blue 점수 + 시간대별 점수 추이 라인차트(recharts)
- `GET /scores`, `GET /scores/history` 폴링(2~3초) 또는 score_updated 이벤트 구독
- 마일스톤 획득 로그(어떤 취약점으로 몇 점) 타임라인

### 2.5 Patch Status
- 취약점 카탈로그 × 팀 매트릭스: vulnerable / patched / checking
- Patch Verification(safe probe) 결과 실시간 반영
- 취약점별 MITRE ATT&CK 태그 표시

### 2.6 Flag Tracker
- 더미 기밀 플래그 목록과 상태: safe / accessed / exfiltrated / blocked
- 유출 발생 시 마젠타 경보 + Asset Map 해당 노드 하이라이트

### 2.7 Instructor Console (권한 분리)
- 시나리오 시작/종료, 이벤트 수동 주입, 점수 조정
- **모든 조작은 audit log에 기록**(누가/언제/무엇을) — 훈련 신뢰성 필수
- 별도 인증(교관 토큰), 관전자는 read-only

---

## 3. 에이전트 분업

### Agent 0 — Architect
- 리포 구조, API 클라이언트 타입 정의(`src/api/types.ts`, Event/Score 스키마를 백엔드와 일치), 라우팅/레이아웃 셸, 디자인 토큰(`tailwind.config` + CSS 변수)
- WebSocket 연결 관리 훅(`useEventStream`)과 재연결/백오프 로직

### Agent 1 — Realtime & State
- `useEventStream`(WS 구독, 자동 재연결), `useScores`(폴링), 전역 상태(zustand 권장)
- 이벤트 → 자산 상태 파생 로직(예: asset_compromised → 노드 red)
- **데모 모드**: 백엔드 없을 때 시뮬레이션 이벤트 생성기(개발/시연용, 플래그로 on/off)

### Agent 2 — Asset Map (시그니처 컴포넌트)
- SVG/Canvas 기반 자산 지도, 상태 전이 애니메이션, 연결선 트래픽 흐름
- reduced-motion 대응, 노드 상세 패널

### Agent 3 — Timeline & Score
- Event Timeline(가상 스크롤로 대량 이벤트 처리), 필터/일시정지
- Score Board 라인차트 + 마일스톤 로그

### Agent 4 — Patch/Flag/Instructor
- Patch Status 매트릭스, Flag Tracker, Instructor Console(+audit log 뷰)

---

## 4. 백엔드 계약 (이미 구현됨)

- `WS  /ws` (8010) — 정규화 이벤트 스트림(Event 스키마)
- `GET /events?limit=&target_asset=&team_id=` (8010)
- `GET /scores?scenario_id=` (8020) → `{teams: {team_id: {red, blue}}}`
- `GET /scores/history?scenario_id=&team_id=` (8020) → achievement 타임라인

**백엔드 보강 요청(추천, Instructor Console용)**: 현재 없는 아래 엔드포인트를 Scoring/Collector에 추가 필요.
- `POST /instructor/scenario/start|end` (audit log 기록)
- `POST /instructor/event/inject`
- `POST /instructor/score/adjust`
- `GET  /instructor/audit` (조작 이력)

---

## 5. Definition of Done

- 트윈에 curl 공격 → 3초 내 Timeline에 이벤트, Asset Map 노드 색 전환, Score 카운트업.
- safe probe로 패치 검증 → Patch Status가 patched로, Blue 점수 증가.
- 플래그 유출 curl → Flag Tracker 마젠타 경보.
- 모바일 반응형, reduced-motion, 키보드 포커스 통과.
