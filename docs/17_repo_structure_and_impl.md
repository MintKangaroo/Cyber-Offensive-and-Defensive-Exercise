# 저장소 구조 & 구현 가이드 — Cyber Range 모노레포

> 전체 프로젝트의 디렉토리 구조와 각 부분을 어떻게 구현할지에 대한 지도.
> Claude Code 에이전트가 파일을 어디에 놓을지, 각 모듈을 어떤 방식으로 지을지의 기준.

---

## 1. 최상위 구조

```
cyber-range/
├─ contracts/              # B0 소유. 공통 스키마/인터페이스(단일 진실원)
├─ platform/               # 공방 플랫폼 백엔드(트윈+코어 서비스)
├─ siem/                   # 자체 SIEM(수집/정규화/탐지/API)
├─ dashboards/             # 대시보드 2종(Live Fire, SIEM)
├─ scenarios/              # 시나리오 as-code(YAML)
├─ challenges/             # 분야별 문제(카테고리별 디렉토리)
├─ infra/                  # 배포/격리/CI(안전장치)
├─ docs/                   # 기획·프롬프트 문서(00~16)
└─ docker-compose.yml      # 전체 오케스트레이션(개발용)
```

각 최상위 디렉토리는 담당 에이전트(09번 역할)와 1:1로 대응한다.

---

## 2. contracts/ — B0 계약 (이미 코드화됨)

```
contracts/
├─ shared/
│  ├─ event_schema.py       # Live Fire 이벤트 + 점수표
│  ├─ siem_schema.py        # SIEM 정규화 이벤트(ECS-lite)
│  ├─ storage_interface.py  # 저장소 추상클래스
│  ├─ api_contract.py       # 포트/엔드포인트/요청모델
│  └─ challenge_schema.py   # 문제/시나리오 검증 모델
├─ tests/test_contracts.py
└─ README.md
```
**구현 방식**: 순수 Pydantic 모델 + ABC. 로직 없음(계약만). 다른 모듈이 `from contracts.shared... import`. 파이썬 패키지로 설치(`pip install -e contracts/`)하거나 PYTHONPATH 공유.

---

## 3. platform/ — 공방 플랫폼 백엔드 (B1, B2, B3)

```
platform/
├─ twins/                          # B1: 취약한 디지털 트윈
│  ├─ ground_station/  (main.py, Dockerfile, files/, secret/)
│  ├─ power_plant/
│  └─ defense_network/
├─ core/                           # B2: 코어 서비스
│  ├─ event_collector/  (수신/dedup/저장/WS/리플레이)
│  ├─ scoring_engine/   (멱등 채점/복구/dwell/reconcile)
│  ├─ config_service/   (패치 무중단 토글/킬스위치)
│  └─ instructor_api/   (교관 콘솔 + audit)
├─ scenario_engine/                # B3: 시나리오 러너
│  ├─ loader.py         (YAML → 검증 → Config 주입)
│  ├─ runner.py         (이벤트 구독 → stage 판정 → chain_bonus)
│  └─ recovery_watcher.py (복구 판정)
└─ shared_clients/       (event_client, config_client)
```

**구현 방식**
- **트윈**: 각각 독립 FastAPI 앱. `patched()`를 config_client 폴링으로 구현(환경변수 폐기). 취약 엔드포인트는 patched 분기로 취약/안전 동작 전환. 공격 성공 시 `emit_event(trace_id=...)`.
- **event_collector**: FastAPI + SQLite(append-only). `POST /events`에서 event_id dedup → 저장 → WS 브로드캐스트 → scoring으로 비동기 전달. `/replay/events`는 저장 이벤트를 시간순 반환.
- **scoring_engine**: achievement_key 멱등 채점. dwell time 계산(matched_event_id로 공격↔탐지 연결). `/scores/reconcile`로 점수↔이벤트 역추적 감사.
- **config_service**: Redis 또는 SQLite에 패치 상태 보관. 트윈이 3~5초 폴링(로컬 캐시). 교관 토글 시 즉시 반영. 킬스위치 플래그.
- **scenario_engine**: loader가 YAML을 challenge_schema.Scenario로 검증 후 initial_vuln_state를 config_service에 주입. runner가 이벤트 스트림 구독하며 stage match 평가(requires_stage로 순서 강제). recovery_watcher는 compromised→patched→health 3회 확인 시 asset_recovered 발행.

---

## 4. siem/ — 자체 SIEM (B4)

```
siem/
├─ ingestion/    (syslog_server.py UDP/TCP/TLS, file_tailer.py)
├─ parsers/      (suricata.py, zeek.py, pfsense.py, twin.py, base.py 레지스트리)
├─ enrich/       (geoip.py, asset.py)
├─ storage/      (sqlite_backend.py MVP, opensearch_backend.py 운영) # storage_interface 구현
├─ detection/    (engine.py, rules/*.yaml, sigma_loader.py)
├─ api/          (main.py: /search /alerts /stats /sources/health /ws)
└─ Dockerfile
```

**구현 방식**
- **ingestion**: `asyncio.DatagramProtocol`로 UDP 514, `asyncio.start_server`로 TCP. 수신 raw를 asyncio.Queue로. file_tailer는 eve.json/zeek 로그를 tail -f. backpressure 시 드롭 카운터.
- **parsers**: source_type별 파서를 레지스트리에 등록. raw → NormalizedEvent(siem_schema). 실패해도 raw 보존 + parse_error 태그.
- **storage**: StorageBackend 구현. MVP는 SQLite FTS5, 운영은 OpenSearch. API/detection은 인터페이스에만 의존.
- **detection**: 정규화 이벤트 스트림 구독 → 규칙 평가(단순/임계/시퀀스). 알림 시 Live Fire로 blue_detection_success 전달(옵션). sigma_loader로 Sigma YAML 임포트.

---

## 5. dashboards/ — 대시보드 2종 (B5)

```
dashboards/
├─ livefire/    (React: AssetMap, Timeline, Score, Patch, Flag, Instructor, Replay)
│  ├─ src/api/       (types.ts, useEventStream.ts, useScores.ts)
│  ├─ src/components/
│  └─ src/views/     (역할별: red/blue/observer/instructor)
└─ siem/        (React: Discover, Alerts, SourceHealth, Analytics)
```

**구현 방식**
- **공통**: React + TS + Tailwind. WS 훅으로 실시간, 폴링으로 점수/통계. 디자인 토큰은 02번(전술 HUD).
- **livefire**: AssetMap은 SVG/Canvas 상태전이 애니메이션. 이벤트→자산상태 파생. 역할별 뷰는 API 응답 필터링(백엔드 스코프, 프론트만 숨기면 치팅 가능). Replay는 라이브 WS↔리플레이 스트림 스왑.
- **siem**: Discover는 가상스크롤 로그 테이블 + 검색. Alerts는 상태관리(open/ack/closed). Analytics는 ATT&CK 히트맵.

---

## 6. scenarios/ — 시나리오 as-code (콘텐츠, B3가 실행)

```
scenarios/
├─ single/       (SAT-KILLCHAIN-01.yaml, SCADA-SABOTAGE-01.yaml, DEFENSE-EXFIL-01.yaml)
├─ crossover/    (분야 연계 시나리오)
└─ README.md
```
**구현 방식**: 순수 YAML(challenge_schema.Scenario 준수). scenario_engine이 로드. 재현성을 위해 초기상태/노이즈를 YAML에 명시.

---

## 7. challenges/ — 분야별 문제 (콘텐츠 C1~C6)

```
challenges/
├─ web/<ID>/        (challenge.yaml, deploy/, solution/, grader/, tests/, writeup.md)
├─ forensics/<ID>/
├─ detection/<ID>/
├─ ai/<ID>/
├─ reversing/<ID>/
└─ network/<ID>/
```
**구현 방식**: 11번 출제표준 구조. 각 문제는 독립 배포 가능(deploy/docker-compose 조각). grader는 GradeResult 반환. C-QA CI가 9단계 검수.

---

## 8. infra/ — 배포/격리/CI (B6)

```
infra/
├─ compose/        (network 격리: internal, range_control 분리)
├─ hardening/      (트윈별 리소스제한, cap_drop, read-only 프로파일)
├─ ci/             (시크릿 스캔, 격리 회귀 테스트, C-QA 파이프라인)
└─ deploy/         (배포 스크립트, 체크리스트 자동화)
```
**구현 방식**: docker-compose override로 격리 프로파일. CI는 08번 체크리스트를 자동화(외부 egress 실패 확인, 시크릿 스캔 등).

---

## 9. 의존성 & 빌드 순서

```
contracts/ (B0)  ─▶ 모든 모듈이 의존
platform/core + twins (B1,B2) ─┬─▶ scenario_engine(B3)
                               ├─▶ siem(B4)
                               └─▶ dashboards(B5)
infra(B6) ─── 전체 횡단
challenges + scenarios (C*) ─── platform/scenario_engine 위에 탑재
```

**로컬 개발**: 루트 docker-compose.yml로 contracts 공유 + core + twins + siem + dashboards 기동. 문제는 필요한 것만 개별 up.

**운영/대회**: infra/deploy로 팀별 격리 배포. SIEM 저장소는 OpenSearch로 승격.
