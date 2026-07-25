# GAP_ANALYSIS — 코드 실측 기반 갭 분석 (Phase 0)

> 작성 원칙: README/문서 주장을 **코드 실측**으로 검증. 근거는 `파일:라인` 인용. 이번 분석에서 코드는 수정하지 않음.
> 실측 환경: 로컬 docker 스택 실행 중, 재시작 테스트는 실제 `docker compose restart` 수행.

## 판정 요약

| # | 항목 | 판정 | 근거(파일:라인) | 실전 영향 | 공수 |
|---|---|---|---|---|---|
| 1 | 인증/세션 | **부분구현** | `shared/rbac.py:61,98`(토큰 미설정 시 dev_mode로 전 검사 우회) · 로그인 UI 없음(대시보드에 login 컴포넌트 부재, `InstructorConsole.tsx:69` 토큰 텍스트 입력만) · 만료/회전/폐기 없음(정적 토큰, JWT 아님) · 감사로그는 있음(`config_service/main.py:91`, `edr/api/main.py:344,372`, `instructor_api/audit_store.py:47`) | 로그인 화면 없어 URL/포트만 알면 접근. 토큰은 정적(폐기·만료 불가) → 부정행위자 즉시 차단 수단 없음. 단 `.env` 토큰 설정 시 조작 계열은 RBAC 게이트됨 | **L** |
| 2 | 영속성 | **부분구현** | event/scoring/config/siem = sqlite(`event_collector/main.py:25` `scoring_engine/main.py:23` `siem/storage/sqlite_backend.py`), **볼륨 없음**(`docker inspect event_collector` → NO VOLUME) · challenge_portal = **메모리**(`challenge_portal/main.py:46` `_SOLVES`) | **실측**: `restart event_collector` 후 이벤트 1→1 생존 ✓, `restart challenge_portal` 후 solve **소실**(빈 스코어보드) ✓. sqlite가 컨테이너-fs라 `restart`엔 생존하나 **recreate/crash-replace 시 소실**. 8h 훈련 중 컨테이너 죽으면 점수·이벤트 유실 위험 | **L** |
| 3 | 실시간 전송 | **부분구현(하이브리드)** | 이벤트=WebSocket(`livefire/src/api/client.ts:103` `ws://…/ws`), 나머지=폴링(scores 3s `ScoreBoard.tsx:82`, patches/alerts/safety 4~5s, coverage 15s) | 관전자 100명 시 폴링 부하 ≈ scores 33/s + history 20/s + patches 20/s + delayed 33/s ≈ **~106 req/s**(캐시 없음). SSE/토픽 구독·Last-Event-ID 리플레이 없음 | **M** |
| 4 | SIEM 검색 | **구현(FTS5)** / 대규모 실측 **확인불가** | `siem/storage/sqlite_backend.py:56`(CREATE VIRTUAL TABLE events_fts USING fts5), `:171`(MATCH). 선형 스캔 아님 | 소규모는 인덱스 검색. 단 sqlite **단일 노드**라 100만건 p50/p95는 미측정(측정 하네스 부재). 대규모 동시검색 한계 가능 | **M** |
| 5 | 대시보드 배포 | **미구현** | 대시보드 5종에 **Dockerfile 없음**(`ls dashboards/*/Dockerfile` → 없음), compose에 정적서빙/landing/gateway 서비스 없음(트윈 gateway만 존재) | 실전 운영 시 교관이 **vite dev 서버 5개를 수동 기동**해야 함. 단일 진입점·프로덕션 배포 경로 없음 | **L** |
| 6 | 트윈 프로토콜 실체 | **미구현(HTTP 모사)** | 전 트윈 uvicorn HTTP 80xx(`refinery_plant/main.py:82` 등), `pymodbus/asyncua/StartTcpServer` 임포트 **전무**. 502/4840/20000/102/2404 리스너 없음 | Red가 **pymodbus·plcscan·opcua-client·Metasploit ICS 모듈 등 실툴 사용 불가**. Suricata ICS 룰은 프로토콜이 아닌 HTTP 트래픽 기반. ICS 트래픽분석 챌린지도 **합성 로그**(실캡처 아님). 훈련 리얼리즘의 가장 큰 갭 | **L** |
| 7 | defense_network AD | **미구현(HTTP 모사)** | `defense_network/main.py:33` `/api/smb/shares`·`/api/ad/service-accounts`·`/api/directory/search` HTTP. impacket/samba 없음 | GetUserSPNs.py·smbclient·ldapsearch 실습 불가. Zeek SMB/Kerberos 로그도 실제 프로토콜 산물 아님 | **M** |
| 8 | 관측성(컨트롤플레인) | **미구현** | `prometheus_client`/`/metrics`/`opentelemetry` 임포트 전무(node_modules 제외). NOC Monitor는 트윈 헬스만 폴링 | 이벤트 파이프라인 지연·드롭·서비스 장애를 정량 관측 불가. 훈련 중 장애 원인 추적 어려움 | **M** |
| 9 | 테스트/보안CI | **부분구현** | 백엔드 유닛 **81**(pytest) + 프론트 **1개**(`livefire/…/ProcessImpact.test.ts`). CI 잡=unit/challenges/dashboard(vitest·build)/integration. **trivy/semgrep/bandit/pip-audit/npm audit/syft/커버리지/Playwright E2E 전무**(`.github/workflows/*.yml`) | 이미지 취약점·SAST·의존성·SBOM 게이트 없음(취약 서비스 다수 포함 저장소라 특히 필요). 프론트 커버리지 사실상 0 | **M** |
| 10 | 공정성/안티치트 | **미구현** | challenge_portal에 rate limit/lockout/제출 감사로그 **없음**(grep 무결과). 크로스매치/컨트롤플레인 공격 탐지 없음(range_control `/safety`는 네트워크 격리만) | 플래그 브루트포스·정답 공유·스코어링 엔진 공격 방어·이상탐지 부재. 대회 공정성 리스크 | **M** |
| 11 | 저장소 위생 | **미구현(대부분)** | **없음**: LICENSE, SECURITY.md, CONTRIBUTING.md, .env.example, CHANGELOG.md, README.en.md, git 태그. repo description **빈값**, topics **없음**. **있음**: `.dockerignore`. `.env`는 **미커밋**(`.gitignore:1`)이라 시크릿 노출은 없음 | 의도적 취약 서비스를 담은 저장소인데 **SECURITY.md 경고 없음**(인터넷 노출 위험 미고지). 라이선스 부재로 사용/기여 불명확. 공개 완성도 낮음 | **S** |

---

## 세부 근거

### 1. 인증/세션
- **dev-mode 우회**: `rbac.py:55-61` `authenticate()` — 역할 토큰이 하나도 설정 안 되면 `Identity(role="instructor", dev_mode=True)` 반환. `rbac.py:93-98` `require_role()`는 `dev_mode`면 모든 검사 통과. → **프로덕션에서 토큰을 안 넣으면 무인증 instructor**가 된다(프로파일 분리 없음, `.env`에 넣어야만 enforce).
- **로그인 UI 없음**: 대시보드에 login/password 컴포넌트 없음. 교관 콘솔은 토큰을 텍스트로 입력(`InstructorConsole.tsx:69-75`), Red/Blue 포털은 팀 드롭다운만(인증 아님).
- **토큰 수명주기 없음**: 정적 문자열 토큰(`RBAC_TOKENS`/개별 env). JWT·만료·refresh·revoke **없음**.
- **감사로그 있음**(방어/조작 계열): config 패치·격리·킬스위치(`config_service/main.py:91`), EDR isolate/kill(`edr/api/main.py:344,372,389`), instructor 조작(`instructor_api/audit_store.py`). → 단 **AAR 자동 첨부 여부는 별도 확인 필요**.

### 2. 영속성 (실측)
```
이벤트 주입 → restart event_collector → 1건 생존 (sqlite, event_collector/main.py:25)
restart challenge_portal → solve 소실 (메모리, challenge_portal/main.py:46,268)
docker inspect event_collector → NO VOLUME  ⇒ sqlite는 컨테이너-fs
```
- **결론**: `restart`(동일 컨테이너 재기동)엔 event/scoring/config/siem 생존. 그러나 **볼륨이 없어** `up --force-recreate`·`docker kill`+재기동·이미지 교체 시 **소실**. challenge_portal solve/blue_solve·range_control 매치·safety 상태는 **메모리라 어떤 재시작에도 소실**.

### 3. 실시간
- WS: `client.ts:15` `WS_URL = …/ws`, `:103` `new WebSocket`. 이벤트만 푸시.
- 폴링: scores 3s·history 5s·patches 5s·alerts 5s·source health 5s·safety 4s·matches 6s·coverage 15s·edr hosts 5s. **SSE/토픽 구독·JWT 필터·Last-Event-ID 리플레이 없음**.

### 6·7. 프로토콜 리얼리즘
- 트윈은 전부 FastAPI HTTP. `requirements.txt`에 `pymodbus/asyncua/impacket/pyshark` 없음. → OT/AD **실제 프로토콜 리스너 부재**. ICS-002~012 트래픽분석 챌린지는 `generate_artifact.py`가 만드는 **합성 로그**.

### 9. 테스트/CI
- `.github/workflows/ci.yml`: unit(81), challenges(schema+solve), dashboard(vitest 1개+build), integration(docker smoke). **보안 스캔 계열 전무**. dependabot 파일 없음.

---

## 내가 README를 보고 틀리게 짐작했던 것

1. **"영속성이 전부 메모리일 것"** → 실제로는 event/scoring/config/**siem**이 **sqlite**였다(`sqlite_backend.py` FTS5 포함). 다만 볼륨이 없어 recreate엔 약하고, challenge_portal·range_control만 순수 메모리. "메모리다"는 절반만 맞음.
2. **"SIEM 검색이 선형 스캔일 것"** → **FTS5 가상테이블**로 전문검색 인덱스가 있었다(`sqlite_backend.py:56`). 대규모 성능은 별개지만 선형 스캔은 아님.
3. **"감사로그가 없을 것"** → EDR isolate/kill·config 패치·instructor 조작에 **감사로그가 이미 있었다**(3곳). 없는 건 "플래그 제출 감사로그"와 "로그인·인증 이력".
4. **".env가 커밋돼 시크릿 노출됐을 수도"** → `.gitignore:1`로 **미커밋**. 시크릿 유출은 없음(단 `.env.example`이 없어 재현성은 나쁨).
5. **"트윈이 진짜 Modbus/OPC UA일 수도"** → 전부 **HTTP 모사** 확정. 이건 짐작대로였지만, HTTP 위에 access-log→SIEM→탐지 파이프라인은 실제로 동작하므로 "탐지 훈련" 가치는 유효(공격 툴 리얼리즘만 부재).

---

## 우선순위 제언 (실전 영향 × 공수)
1. **P0-1 단일 진입점/프로덕션 배포**(항목 5) — 공수 L이지만 "훈련을 못 돌리는" 최상위 갭.
2. **P0-3 영속성 강화**(항목 2) — 볼륨 마운트만으로도 recreate 생존 확보(공수 S~M), 완전 강화는 PostgreSQL(L).
3. **P0-2 인증/세션**(항목 1) — 프로덕션 dev-mode 차단 + 로그인 게이트.
4. **P1-1 프로토콜 리얼리즘**(항목 6/7) — 훈련 질의 핵심이나 공수 L, 단계적.
5. **P3 저장소 위생**(항목 11) — 공수 S, 효과 큼(SECURITY.md는 필수).
