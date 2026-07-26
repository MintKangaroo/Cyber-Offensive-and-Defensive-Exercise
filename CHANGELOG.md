# 변경 이력 (Changelog)

형식: [Keep a Changelog](https://keepachangelog.com/), 버전: [SemVer](https://semver.org/).

## [Unreleased]
### Added
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
