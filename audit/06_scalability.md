# F축 감사 — 확장성·성능

감사 범위: `cyber-range-platform` (읽기 전용 정적 분석). 도커/부하도구 미실행.
모든 수치는 저장소 내 **코드 상수**에서 뽑아 계산한 이론값이다. 실측이 필요한 항목은 §6에 분리했다.

---

## 0. 전제 정정

팀 브리핑의 "docker-compose.yml:12-20 공통 앵커에 mem_limit 256m ... 서비스 정의 120개"는 절반만 맞다.

- 서비스 정의 수: **121개** (`docker-compose.yml`, 최상위 2-space 키 기준).
- `x-ad-service-security` 앵커(`docker-compose.yml:11-20`, mem_limit 256m/cpus 0.50/pids_limit 128)를 **실제로 상속받는 서비스는 7개뿐**이다(`<<: *ad-service-security` 출현 7회, 전부 `ad_team_*` 취약 데모 서비스).
- `mem_limit`이 명시된 곳은 전체에서 5줄뿐: `:18`(앵커 256m), `:231`(512m), `:300`(ad_postgres 1g), `:326`(attack_defense_ha 512m), `:393`(ad_ha_gateway 128m).
- 즉 **event_collector·scoring_engine·siem_api·config_service·트윈 11종·suricata 11·zeek 11 은 메모리/CPU 상한이 전혀 없다**(기본 compose 기준). 근거: 위 grep 결과 및 `docker-compose.yml:23-33`(event_collector 정의에 mem_limit 없음), `docker-compose.yml:85-108`(siem_api 정의에 mem_limit 없음), `docker-compose.yml:773-795`(gs_suricata/gs_zeek 정의에 mem_limit 없음).
- 상한이 붙는 유일한 경로는 하드닝 오버레이 `infra/hardening/docker-compose.hardening.yml:54-60` (event_collector·scoring_engine → `cpus: "0.5"`, `mem_limit: "512m"`). **siem_api는 이 오버레이에도 없다.**

따라서 "256m이 SQLite FTS5/Postgres/uvicorn에 충분한가"는 잘못된 질문이다. 실제 문제는 **상한이 없어서 OOM이 호스트 전체를 때린다**는 쪽이다(§4 D-06).

---

## 1. 요약 판정 테이블

| # | 항목 | 판정 | 근거 (path:line) | 실전 영향 |
|---|---|---|---|---|
| F1 | 동시 참가 팀/사용자 수 실측 근거 | **없음** | `loadtest/` 하위에 결과·리포트 파일 0건(`find` 결과 공백). `docs/28_load_testing_plan.md:125-133`은 임계치 표만 있고 실측치 없음 | 수용 인원을 아무도 모른다. 대회 당일이 첫 부하 시험 |
| F2 | 부하 시나리오 코드 존재 | 있음(미실행) | `loadtest/k6/attack_defense.js:6-25`, `event_collector_ingest.js:3-16`, `twin_attack_load.js:4-18`, `loadtest/sse_loadtest.py:88-95`, `syslog_flood.py:25-29` | 목표 수치는 코드에 있음(§3.1). 실행 증거만 없음 |
| F3 | 로드테스트 CI 통합 | **없음** | `.github/workflows/ci.yml` 전체에 `k6`/`loadtest` 문자열 0건. 잡은 unit·challenge QA·npm·docker smoke 4종뿐(`ci.yml:14-24, 44, 62-65, 77-128`) | 성능 회귀가 머지될 때까지 아무도 모름 |
| F4 | `tests/attack_defense/test_load_profile.py` | **부하 검증이 아님** | `test_load_profile.py:8-19` — 12팀 3라운드 부트스트랩 후 `scoreboard()` **순차 100회 호출**, 검증은 `len(board)==teams`뿐. 동시성 0, 지연 임계치 0, HTTP 0 | "부하 프로파일"이라는 이름이 CI 녹색등으로 오독됨 |
| F5 | 이벤트 수집 경로 | **동기 HTTP, 큐 없음, 예외 삼킴** | `shared/event_client.py:52-55` — `requests.post(timeout=1.5)` 후 `except RequestException: pass` | 백프레셔 없음 = **조용한 이벤트 유실 = 조용한 점수 유실** |
| F6 | 채점 이벤트 큐/백프레셔 | **없음** | `services/event_collector/main.py:162` `asyncio.create_task(_forward_to_scoring_engine(...))` fire-and-forget, `:200-201` `except httpx.HTTPError: pass`. 재시도·DLQ·in-flight 상한 전부 없음 | scoring_engine 2초 이상 느려지면 그 구간 점수 전부 소실 |
| F7 | SSE 팬아웃 구조 | 큐 격리는 있음 / **직렬화가 O(N)** | `shared/sse_bus.py:51-55` publish는 `put_nowait` O(N) 논블로킹(양호). 그러나 프레임 직렬화 `event_collector/main.py:290-291 _sse_frame`이 **구독자 스트림마다 별도로 `json.dumps` 실행**(`:334`) | 구독자 N × EPS 만큼 CPU. §3.2에서 포화점 계산 |
| F8 | SSE 드롭 관측성 | **없음** | `sse_bus.py:54-55` `except QueueFull: pass` — 카운터·로그·메트릭 전무 | 관전자 화면이 조용히 누락된 채 "정상"으로 보임 |
| F9 | SSE 리플레이 윈도 | **부족** | 링버퍼 2000(`event_collector/main.py:36`), 재연결 간격 3000ms(`:311`) | 200 EPS면 리플레이 창 = **10초**. 15초 끊김 시 Last-Event-ID 있어도 영구 유실 |
| F10 | 대시보드 폴링 잔존 | **잔존(SSE로 대체 안 됨)** | AD 셸 5s(`AttackDefenseApp.tsx:88`), redportal 5s(`redportal/src/App.tsx:65`), blueportal 4s(`blueportal/src/App.tsx:264`), 관전자 delayed 3s(`LegacyExerciseApp.tsx:72`), `usePolling` 9곳(§3.1) | 관전자 100명에서 **163 RPS**가 컨트롤플레인에 상시 인가됨 |
| F11 | 컨트롤플레인 SQLite 동시쓰기 | **WAL 없음** | `event_collector/main.py:76`, `scoring_engine/main.py:52`, `config_service/main.py:43`, `siem/storage/sqlite_backend.py:27`, `siem/storage/alert_store.py:21` — 전부 `sqlite3.connect(path)` 맨몸. journal_mode=DELETE, synchronous=FULL | 쓰기 완전 직렬화 + 커밋마다 fsync. §2 병목 1·2위 |
| F12 | A/D DB 설정 | 양호하나 **풀 없음** | `services/attack_defense/db.py:146-153` WAL·synchronous=NORMAL·busy_timeout=10000 (유일하게 제대로 됨). 그러나 `:143` `connect()`와 `:156-167` `transaction()`이 **호출마다 새 연결 생성/종료**, psycopg 풀 0건(`grep pool` 무응답) | Postgres 모드에서 초당 수백 회 신규 접속 + scram-sha-256 인증 |
| F13 | SIEM 인덱싱 경로 | **이벤트루프 블로킹** | `siem/api/main.py:130` `await backend.index(event)` → `sqlite_backend.py:68-72`는 **동기** `connect→INSERT×2→commit→close`. `async` 함수 안에서 blocking I/O | fsync 동안 SSE·WS·UDP syslog 수신이 전부 정지 |
| F14 | SIEM 보존/롤오버/인덱스 정리 | **전무** | `grep -i "retention|rollover|vacuum|purge"` → services/·scripts/·infra/·compose 전체 **0건**. `sqlite_backend.py`에 DELETE 경로 없음, `alert_store.py`에도 없음 | 8시간 훈련 후 단일 sqlite 파일이 무한 성장(§3.3) |
| F15 | 로그 볼륨 상한 | **없음** | `siem_logs` named volume(`docker-compose.yml:106`)에 suricata/zeek 22개가 write(`:781, :791`), logrotate 설정 0건, suricata memcap 튜닝 0건(`infra/suricata/suricata.yaml` 전체 37줄, `threads: 1`만 있음) | 호스트 디스크 고갈 |
| F16 | UDP syslog 드롭 계측 | **거짓 안심** | 큐 5000(`siem/api/main.py:75`), 초과 시 `drop_counters`(`syslog_server.py:44-47`). 그러나 F13으로 루프가 멈추면 **커널 소켓 버퍼에서 드롭**되고 이건 카운터에 안 잡힘. `/sources/health:324`가 `dropped_total: 0`을 보고함 | 유실이 일어나도 대시보드는 0을 표시 |
| F17 | `rate_limit.py`가 제한하는 것 | **게임 액션만** | `services/attack_defense/rate_limit.py:26-49`. 정책값: 플래그 120/분, 스텔스 30/분, 패치 10/시간(`docker-compose.yml:360-362`) | **이벤트 수집(`/events`)·대시보드 폴링·SSE 구독에는 레이트리밋이 전혀 없다** |
| F18 | A/D 수평확장(상태공유) | **실제로 됨** | Postgres advisory lock 매치 리스(`test_postgres_ha.py:100`), DB 공유 레이트리밋(`rate_limit.py:31-40`, `test_ha_coordination.py:26-38`), `SKIP LOCKED` 잡 클레임 + 펜싱(`test_postgres_ha.py:176`), KOTH 직렬화(`:213`). haproxy `server-template replica 1-4` + `option httpchk GET /ready`(`infra/attack_defense/haproxy-ha.cfg:24-28`), `deploy.replicas: 2`(`docker-compose.yml:380`) | A/D API는 수평확장 가능. 단 §2 병목 4위(커넥션 풀 부재)가 상한을 결정 |
| F19 | HA 테스트의 CI 실행 | **항상 스킵** | `tests/attack_defense/test_postgres_ha.py:41-42` — `ATTACK_DEFENSE_TEST_POSTGRES_URL` 미설정 시 skip. `ci.yml`에 해당 env 0건 | HA 코드 6개 테스트 전부 CI에서 실행되지 않음. 회귀 방지 없음 |
| F20 | 컨트롤플레인 수평확장 | **불가(구조적)** | SSE 버스가 프로세스 내 객체(`event_collector/main.py:36 bus = SSEBus(...)`), WS 클라이언트도 프로세스 내 set(`:73 _ws_clients`). 게다가 `container_name: event_collector`(`docker-compose.yml:25`) 고정이라 `--scale` 자체가 불가. Dockerfile에 `--workers` 없음(`services/event_collector/Dockerfile:9`, `scoring_engine/Dockerfile:9`, `siem/Dockerfile:10`) | event_collector·scoring_engine·siem은 **영구히 단일 프로세스 단일 코어**. 전체 플랫폼의 하드 상한 |

---

## 2. 병목 후보 순위표

| 순위 | 컴포넌트 | 병목 원인 | 코드 근거 | 추정 한계치 | 계산 근거 |
|---|---|---|---|---|---|
| **1** | `siem_api` 인덱싱 | 이벤트마다 **새 sqlite 연결 + WAL 없음 + synchronous=FULL 커밋**, 그것도 asyncio 이벤트루프 위에서 동기 실행 | `sqlite_backend.py:26-29`(`_conn`, PRAGMA 없음), `:68-72`(`index`: connect→\_insert→commit→close), `:84-110`(SELECT+INSERT+SELECT rowid+INSERT fts = 문장 4개), `siem/api/main.py:130` | **~200-330 EPS** (NVMe), **~120-250 EPS** (GCP pd-balanced) | rollback journal 커밋 = 저널생성·fsync·본문쓰기·저널삭제·디렉터리 fsync ≈ fsync 3-4회. NVMe fsync ~100µs → 0.3-0.4 ms + 문장 4개 + 파일 open/close 2회 ≈ 3-5 ms/건 → 1/0.003~1/0.005. pd-balanced fsync ~1 ms → 4 ms만으로도 250 EPS. 문서 임계치 200 EPS(`docs/28_load_testing_plan.md:130`)와 **거의 같은 자리** = 여유 0 |
| **2** | `event_collector` `/events` 쓰기 | 동일 문제 + `async def` 안에서 blocking sqlite → **이벤트루프 전체 정지** | `main.py:129`(`async def ingest_event`), `:76`(`sqlite3.connect`, PRAGMA 없음), `:131`(SELECT dedup), `:136-150`(INSERT+commit) | **~200-330 건/s**, 그리고 그 동안 SSE/WS 팬아웃 **동시 정지** | 위와 동일. 추가로 `sqlite3.connect`의 기본 `timeout=5.0` → 관전자 조회(`:243` `/events/delayed`, 200행 SELECT)가 shared lock을 쥐면 쓰기가 **최대 5초 블로킹**되고, 그 5초간 이벤트루프가 통째로 멈춘다. 초과 시 `OperationalError` → HTTP 500 → `event_client.py:53-55`가 삼킴 → **유실** |
| **3** | `event_collector` SSE 팬아웃 CPU | 프레임 직렬화가 **구독자마다 반복** | `main.py:290-291`(`_sse_frame`에 `json.dumps`), `:334`(구독자별 제너레이터 안에서 호출), `sse_bus.py:51-55` | 구독자 132명 기준 **~151 EPS**(하드닝 적용 시) / **~303 EPS**(무제한, 단일 코어) | ~1 KB 페이로드 `json.dumps` ≈ 25 µs. 예산 = 하드닝 `cpus: "0.5"`(`hardening:55`) → 0.5 CPU-s/s → 0.5/25µs = 20,000 frame/s. `EPS × 구독자 ≤ 20,000` → 구독자 132에서 EPS ≤ 151. 상한 해제 시 단일 코어 1.0 → 40,000 → EPS ≤ 303. **여기에 병목 2의 blocking write가 같은 코어를 나눠 쓴다** |
| **4** | `attack_defense` DB 접속 | **커넥션 풀 없음** — API 호출마다 신규 연결 | `db.py:143-155`(`connect()`), `:156-167`(`transaction()`이 `_postgres_connect` 후 `raw.close()`), 저장소 전체 `pool` 0건 | Postgres 모드에서 **~100 동시연결**(postgres:17 기본 `max_connections`)이 상한, 초당 신규접속 ~163회 | §3.1의 163 RPS × 요청당 최소 1 연결. scram-sha-256 인증 왕복이 매번 발생. `ad_postgres` `mem_limit: 1g`(`docker-compose.yml:300`) → work_mem×100연결 여유 없음 |
| **5** | `scoring_engine` `/score/ingest` | sync `def` 엔드포인트가 anyio 스레드풀(기본 40)로 흩어져 **비-WAL sqlite에 40 스레드가 동시 쓰기 시도** | `scoring_engine/main.py:143`(`def score_ingest`, async 아님), `:52`(PRAGMA 없는 connect), `:104-124`(`_award`: SELECT+INSERT+UPSERT), `:221` commit | **~330 EPS**, 그 이상에서 스레드가 5초 busy-wait 후 500 | 단일 writer 직렬화 3 ms/건. 40 스레드는 동시성이 아니라 **락 대기열 40개**일 뿐. 초과 시 `sqlite3.OperationalError`가 잡히지 않고 500 → `event_collector/main.py:200-201`이 삼킴 |
| **6** | 호스트 메모리 | 121 서비스 중 **116개가 mem_limit 없음** | `docker-compose.yml`의 `mem_limit` 총 5줄(`:18, :231, :300, :326, :393`), 앵커 상속 7회 | 기저 상태에서 이미 **>20 GB**, 권장 사양 32 GB(`docs/21_build_environment_guide.md:15`)를 부하 전에 소진 | suricata 11개 × 기본 memcap(flow 64M+stream 64M+ht) 실측 RSS 300-600 MB = 3.3-6.6 GB (`infra/suricata/suricata.yaml` 37줄에 memcap 튜닝 0건) + zeek 11개 × ~300 MB = 3.3 GB + Python/uvicorn 컨테이너 ~60개 × 100-150 MB = 6-9 GB + nginx 게이트웨이 11 + Postgres 1 GB |
| **7** | `siem_logs` 볼륨 | 22개 센서가 한 볼륨에 무한 write, 로테이션 없음 | `docker-compose.yml:781, :791`(`siem_logs:/var/log/siem`), `:106`(siem은 `:ro`), logrotate 설정 0건 | 8시간 후 **수 GB~수십 GB**, 상한 없음 | zeek conn.log만 해도 자산당 수백 MB/시간 가능. 디스크 100 GB(`docs/21:15`)를 SIEM DB(§3.3)와 나눠 씀 |

---

## 3. 부하 계산

### 3.1 대시보드 폴링 → 총 RPS

코드에서 추출한 폴링 상수 전량:

| 위치 | 주기 | 사이클당 요청 수 | 클라이언트당 RPS |
|---|---|---|---|
| `dashboards/livefire/src/attackDefense/AttackDefenseApp.tsx:88` | 5,000 ms (숨김 시 15,000) | `refresh()`가 state, scoreboard, services, attackSurface, patches, captures, koth, stealth, tournament = 최대 9, 관전자는 7 (`:47-68`) | competitor **1.8** / observer **1.4** |
| `dashboards/redportal/src/App.tsx:65` | 5,000 ms | getState, getAttackSurface, getScoreboard = 3 (`:41-45`) | **0.60** |
| `dashboards/blueportal/src/App.tsx:264` | 4,000 ms | loadEvents, loadPatches = 2 | **0.50** |
| `dashboards/livefire/src/LegacyExerciseApp.tsx:72` | 3,000 ms | `/events/delayed?delay=30&limit=200` = 1 (**200행 반환**) | **0.33** |
| `components/Instructor/RangeControlPanel.tsx:13-14` | 4,000 / 6,000 ms | safety, matches | 0.417 |
| `components/Instructor/InstructorConsole.tsx:14` | 5,000 ms | audit | 0.20 |
| `components/PatchStatus/PatchMatrix.tsx:18` | 5,000 ms | patches | 0.20 |
| `components/Score/ScoreBoard.tsx:83-84` | 15,000 ms ×2 | scores, history | 0.133 |
| `dashboards/siem/.../AlertsView.tsx:74` | 5,000 ms | alerts | 0.20 |
| `dashboards/siem/.../SourceHealth.tsx:11` | 5,000 ms | source health | 0.20 |
| `dashboards/siem/.../AttackCoverageView.tsx:4` | 15,000 ms | coverage | 0.067 |
| 1초 타이머 2곳 (`components.tsx:36`, `BroadcastOverlay.tsx:28`) | 1,000 ms | 0 (로컬 시계 tick) | 0 |

**시나리오 A — 16팀 / 관전자 100명 / 교관 3명 / SIEM 분석가 16명**

```
팀 클라이언트   : 16팀 × (redportal 0.60 + blueportal 0.50 + AD셸 1.80) = 16 × 2.90 =  46.4 RPS
관전자          : 100 × AD셸 observer 1.40                                            = 140.0 RPS
교관 콘솔       : 3  × (0.417 + 0.20 + 0.20 + 0.133)                                  =   2.9 RPS
SIEM 분석가     : 16 × 0.467                                                          =   7.5 RPS
─────────────────────────────────────────────────────────────────────────────────────────────
합계                                                                                  ≈ 196.8 RPS
그중 attack_defense API(8100) 몫: 46.4 + 140.0 = 186.4 RPS
```

- 이 186 RPS 전부가 **단일 uvicorn 워커 1프로세스**로 간다(`services/attack_defense/Dockerfile:12`에 `--workers` 없음). HA 프로필(`docker-compose.yml:380` replicas 2)을 켜야 2개.
- Postgres 모드에서는 요청당 최소 1회 신규 접속(`db.py:156-167`) → **초당 186 신규 커넥션**, `postgres:17-alpine` 기본 `max_connections=100`.
- 관전자가 legacy 셸(`LegacyExerciseApp.tsx:72`)을 쓰면 여기에 100 × 0.33 = 33 RPS가 event_collector에 추가되고, **매 요청이 200행 SELECT**(`event_collector/main.py:243-252`) → 초당 6,600행 스캔이 §2 병목 2의 쓰기 락과 정면 충돌한다.

**시나리오 B — 어디서 먼저 깨지는가(관전자 수를 올릴 때)**

§2-3위 식 `EPS × 구독자 ≤ 20,000`(하드닝 0.5 CPU)에 문서 임계 200 EPS를 넣으면 **구독자 상한 100명**. 여기에 폴링 RPS의 CPU까지 같은 프로세스가 부담하므로 실제 안전선은 그보다 낮다.

### 3.2 SSE 팬아웃 상한 (재계산 명시)

```
프레임 1개 비용   = json.dumps(약 1 KB dict) ≈ 25 µs (CPython 3.11 기준 보수적)
초당 프레임 수     = EPS × 구독자 수          (sse_bus.py:51 + main.py:334, 구독자마다 재직렬화)
CPU 예산           = 0.5 core (hardening:55) → 500,000 µs/s
                   = 1.0 core (제한 없음)    → 1,000,000 µs/s

포화식: EPS × 구독자 ≤ 20,000 (0.5 core)  /  ≤ 40,000 (1.0 core)

  구독자 132 →  EPS 151 (0.5 core) / 303 (1.0 core)
  구독자 200 →  EPS 100 (0.5 core) / 200 (1.0 core)
  EPS 200 고정 → 구독자 100 (0.5 core) / 200 (1.0 core)
```

메모리 측면: 구독자 큐 maxsize=1000(`main.py:319`) × 1 KB × 200 구독자 = **최대 200 MB** + 링버퍼 2000 × 1 KB = 2 MB. 하드닝 `mem_limit: "512m"`(`hardening:56`) 아래서 팬아웃 지연이 누적되면 OOM 사거리에 들어간다.

### 3.3 SIEM 수집량 × 8시간

**로그 소스 수(코드 기준)**

- 트윈 자산 12개: `siem/api/main.py:42-48` (`ground_station, power_plant, defense_network, refinery_plant, smart_factory, water_utility, lng_terminal, railway_signaling, airport_ot, datacenter_bms, hospital_ot, cloud_native`)
- 자산당 tail 스트림 = access 1(`:234`) + suricata eve.json 1(`:258`) + zeek 5종(`:259` `conn, dns, http, ssl, notice`) = **7**
- 총 tail 태스크 = 12 × 7 = **84** (전부 단일 이벤트루프의 코루틴, `file_tailer.py:14-17` poll_interval 0.5 s)
- 실제 배치된 센서 컨테이너 = suricata 11 + zeek 11 = **22** (`docker-compose.yml:773-1026`)
- + pfsense UDP syslog 1채널(`docker-compose.yml:89` `1514:1514/udp`)
- + noise_generator: `base_eps` 기본 **2.0** (`siem/api/main.py:59`), 그리고 **기본 비활성**(`main.py:58` `SIEM_NOISE_ENABLED` 기본 false, `docker-compose.yml:99` `false`)

**EPS 추정 (코드 상수 기준)**

| 출처 | 상수 | 8시간(28,800 s) 총건수 |
|---|---|---|
| noise_generator (활성 시) | 2.0 EPS × 업무시간 가중(`noise_generator.py:38, 66`) | 57,600 (무시 가능) |
| 문서 SIEM 임계치 | 200 EPS (`docs/28_load_testing_plan.md:130`) | **5,760,000** |
| `syslog_flood.py` 기본 | 500 EPS (`syslog_flood.py:29`) | **14,400,000** |
| k6 ingest 시나리오 | 200/s (`event_collector_ingest.js:8`) | 5,760,000 |
| suricata/zeek 22 센서 | **코드에 상수 없음 → UNVERIFIED**. 다만 zeek conn.log만으로도 자산당 수십 EPS는 일상적이므로 11자산 합산이 200 EPS를 넘길 개연성이 높다 | — |

**저장 용량**

`sqlite_backend.py:90-109` — 행당 `raw`(원본 JSON 전체) + `message` + `tags` + `mitre` JSON 저장. 보수적으로 행당 1.5 KB, FTS5는 `content='events'` 외부콘텐츠(`:56`)라 본문 중복은 없고 토큰 인덱스만 ≈ 원문의 40%.

```
200 EPS × 28,800 s = 5,760,000 행
5,760,000 × 1.5 KB × 1.4 (FTS 인덱스 포함) ≈ 12.1 GB   ← 단일 sqlite 파일 (si_data 볼륨)
500 EPS 가정 시                            ≈ 30.2 GB
```

디스크 100 GB(`docs/21_build_environment_guide.md:15`)를 `siem_logs` 원본 로그(§2-7위, 상한 없음)와 나눠 쓴다. **보존·롤오버·VACUUM 코드는 저장소 전체에 0건**이므로 훈련을 반복하면 파일은 단조 증가한다. 검색 임계치는 "1만 건 기준 500 ms"(`docs/28:131`)로 명시되어 있는데, 실제 8시간 후 데이터는 **576배**다. 이 임계치는 운영 규모에 대해 아무것도 보증하지 않는다.

**큐 포화 시간**

```
syslog 큐 5000슬롯 (siem/api/main.py:75)
소비자 정지 시 포화까지: 5000 / 200 EPS = 25초, 5000 / 500 EPS = 10초
포화 후 → drop_counters (syslog_server.py:44-47)
그러나 §F16: 이벤트루프가 index() fsync로 멈추면 커널 UDP 버퍼에서 먼저 드롭되고
이건 카운터에 안 잡힌다 → /sources/health(main.py:324)는 0을 보고한다.
```

---

## 4. 결함 목록 (심각도 순)

### D-01 (Critical) — 채점 이벤트에 백프레셔가 없고 실패가 조용히 삼켜진다

경로 전체가 무보증이다.

1. 트윈 → collector: `shared/event_client.py:52-55` — 동기 POST, 1.5초 타임아웃, `except RequestException: pass`.
2. collector 저장 실패: `event_collector/main.py:136-150`의 `OperationalError`가 잡히지 않음 → 500 → 위 1의 `pass`가 삼킴.
3. collector → scoring: `main.py:162` fire-and-forget 태스크, `:186` 2초 타임아웃, `:200-201` `except httpx.HTTPError: pass`. 재시도·DLQ·in-flight 상한 전부 없음.
4. 게다가 `main.py:185`가 **이벤트마다 새 `httpx.AsyncClient`(=새 커넥션풀)를 만든다** → 200 EPS면 초당 200 TCP 신규 연결, keep-alive 재사용 0.

**발생 시나리오:** 16팀이 동시에 익스플로잇을 터뜨려 순간 EPS가 300을 넘기면(§2-1,2,5의 상한) scoring_engine이 5초 busy-wait에 들어간다 → 2초 타임아웃 초과 → 그 구간 **모든 득점 이벤트가 흔적 없이 사라진다**. 로그도, 카운터도, 알림도 없다. 대회 후 "점수가 안 들어갔다"는 이의제기를 검증할 데이터 자체가 없다.

### D-02 (Critical) — SIEM 인덱싱이 이벤트루프를 막고, 그 손실이 계측되지 않는다

`siem/api/main.py:130`은 `await backend.index(event)`지만 `sqlite_backend.py:68-72`는 순수 동기 blocking I/O다. fsync 3-4회 동안 동일 루프의 84개 tail 코루틴, UDP `datagram_received`(`syslog_server.py:38-47`), WS 브로드캐스트(`main.py:117-122`)가 전부 정지한다.

**발생 시나리오:** 관전자·팀이 붙은 상태에서 Red가 스캔을 돌려 suricata/zeek EPS가 250을 넘기면 SIEM 인덱싱이 밀린다 → 루프 정지 구간에 UDP 데이터그램이 커널 버퍼에서 드롭 → `/sources/health`는 `dropped_total: 0`을 보고 → **Blue 팀은 자기가 보고 있는 SIEM이 눈먼 상태라는 걸 모른다.** Live-fire에서 탐지 채점의 신뢰성이 통째로 무너진다.

### D-03 (High) — 컨트롤플레인이 구조적으로 단일 프로세스에 고정

`event_collector/main.py:36`의 `bus`와 `:73`의 `_ws_clients`는 프로세스 로컬 객체다. 인스턴스를 늘리면 구독자는 자기가 붙은 인스턴스가 받은 이벤트만 본다. 게다가 `docker-compose.yml:25`가 `container_name: event_collector`로 고정이라 `--scale`이 실행조차 안 되고, Dockerfile에 `--workers`도 없다(`services/event_collector/Dockerfile:9`, `scoring_engine/Dockerfile:9`, `siem/Dockerfile:10`).

**발생 시나리오:** 팀 24개·관전자 200명 규모로 키우려는 순간, A/D API는 `deploy.replicas`로 늘릴 수 있지만(F18) event_collector·scoring_engine·siem은 **코드를 고치지 않는 한 한 대 이상 못 늘린다.** 확장 경로가 문서에도 코드에도 없다. Redis/NATS 등 외부 pub/sub 도입이 전제 조건인데 그 흔적이 없다.

### D-04 (High) — 동시 수용 인원의 실측 근거가 0

`loadtest/`에 스크립트 5종이 있으나 **실행 결과·리포트 파일이 저장소에 단 하나도 없다**. `.github/workflows/ci.yml`에 `k6`/`loadtest` 문자열이 없어 CI에서도 절대 돌지 않는다. 유일하게 "load"라는 이름을 단 `tests/attack_defense/test_load_profile.py:8-19`는 **동시성이 전혀 없는 순차 100회 호출**이고 검증문은 `len(board) == teams` 하나뿐이다 — 지연도, 처리량도, 실패율도 보지 않는다.

**발생 시나리오:** "우리는 부하 테스트도 하고 CI에 load profile 테스트도 녹색"이라는 근거로 국가 기반시설 훈련 일정을 잡는다. 실제로 검증된 것은 아무것도 없다. Locked Shields 급 행사에서 이 상태는 **드라이런 없이 본선 진행**과 동등하다.

### D-05 (High) — 관전자 수가 늘면 관전자가 먼저 죽는 게 아니라 채점이 먼저 죽는다

§3.2: `EPS × 구독자 ≤ 20,000`(하드닝 0.5 core). SSE 팬아웃과 `/events` 쓰기가 **동일한 단일 이벤트루프**를 공유하므로, 관전자가 늘어 팬아웃 CPU가 예산을 먹으면 쓰기 경로가 굶는다. `sse_bus.py:54-55`의 드롭은 관전자만 격리하지만 — 그건 **큐가 찼을 때** 얘기고, **직렬화 CPU는 격리되지 않는다.**

**발생 시나리오:** 팀 16개·관전자 150명, EPS 180. 필요 프레임 = 180 × 182 = 32,760/s > 20,000 예산. 이벤트루프 포화 → `/events` POST 응답이 1.5초를 넘김 → `event_client.py:15`의 타임아웃 → `:53-55`가 삼킴 → **관전자를 늘렸더니 팀 점수가 사라진다.** 링버퍼 2000(`main.py:36`)은 EPS 180에서 11초 창이므로 재연결 복구도 안 된다.

### D-06 (Medium) — 121개 서비스 중 116개에 메모리/CPU 상한이 없다

§0. suricata 11개는 `infra/suricata/suricata.yaml`(전체 37줄)에 memcap 튜닝이 전혀 없어 기본값으로 뜨고, zeek 11개도 무제한이다. 게다가 둘 다 `image: ...:latest`(`docker-compose.yml:774, 786`) — 버전 고정 없음.

**발생 시나리오:** 트래픽이 몰려 suricata 11개가 동시에 flow 테이블을 채우면 호스트 32 GB(`docs/21:15`)가 소진되고, 커널 OOM killer가 **어느 컨테이너를 죽일지 예측할 수 없다.** 하필 event_collector가 죽으면 그 사이 모든 이벤트가 D-01 경로로 조용히 소실된다. 상한이 없다 = 격리 실패가 전역 장애가 된다.

### D-07 (Medium) — `/events`에 레이트리밋이 없다

`rate_limit.py`(`services/attack_defense/rate_limit.py:26-49`)는 **A/D 게임 액션 전용**이다(플래그 120/분, 스텔스 30/분, 패치 10/시간 — `docker-compose.yml:360-362`). `event_collector`의 `/events`, `/events/delayed`, `/stream`, `siem_api`의 syslog 수신에는 레이트리밋도 인증 게이트도 없다(`event_collector/main.py:128`, `:236`, `:295`). event_collector는 트윈 격리망 11개 전부에 연결되어 있다(`docker-compose.yml:32`).

**발생 시나리오:** 트윈 하나를 장악한 Red 팀이 `/events`에 초당 수천 건을 밀어 넣으면 컨트롤플레인 전체가 정지한다. 이건 공격 시나리오의 일부가 아니라 **레인지 자체를 다운시키는 경로**다.

### D-08 (Medium) — HA 코드가 CI에서 한 번도 실행되지 않는다

`tests/attack_defense/test_postgres_ha.py:41-42`가 `ATTACK_DEFENSE_TEST_POSTGRES_URL` 미설정 시 skip하고, `ci.yml`에 그 env가 없다. Postgres advisory lock·SKIP LOCKED 펜싱·KOTH 직렬화 등 **HA의 핵심 6개 테스트가 전부 스킵**된다. `test_ha_coordination.py`는 SQLite로만 돌아 실제 다중 인스턴스 상황을 재현하지 않는다.

### D-09 (Medium) — A/D DB에 커넥션 풀이 없다

`db.py:156-167` `transaction()`이 매번 `psycopg.connect` → `close`. 저장소 전체에 `pool`/`ConnectionPool` 0건. §3.1의 186 RPS면 초당 186회 신규 접속 + scram-sha-256 인증. `postgres:17-alpine` 기본 `max_connections=100`, `mem_limit: 1g`(`docker-compose.yml:300`).

**발생 시나리오:** 팀 16 + 관전자 100에서 A/D API가 커넥션 고갈로 `FATAL: sorry, too many clients already`를 뱉기 시작한다. haproxy 헬스체크(`haproxy-ha.cfg:26` `GET /ready`)도 같은 DB를 쓴다면 **양쪽 replica가 동시에 unhealthy로 빠져 전체 A/D가 내려간다.**

### D-10 (Low) — SSE 드롭·유실이 전혀 관측되지 않는다

`sse_bus.py:54-55` `except QueueFull: pass` — 카운터도 로그도 없다. `/stream` 응답의 `subscribers` 값은 `internal/publish`(`main.py:346`)에서만 노출되고 드롭 수는 어디에도 없다. 링버퍼 2000(`main.py:36`)을 넘긴 리플레이 실패도 마찬가지로 무음이다.

---

## 5. HA / 수평확장 판정 정리

| 컴포넌트 | 수평확장 | 상태공유 | 근거 |
|---|---|---|---|
| `attack_defense_ha` | **가능** (replicas 2, 템플릿 1-4) | **실제로 됨** — advisory lock 매치 리스, DB 공유 레이트리밋, SKIP LOCKED + 펜싱 토큰, KOTH per-hill 직렬화 | `docker-compose.yml:380`, `haproxy-ha.cfg:24-28`, `test_postgres_ha.py:100, 128, 176, 213, 260` |
| `ad_postgres` | 단일 (레플리카/스탠바이 없음) | — | `docker-compose.yml:290-311`. HA의 SPOF |
| `event_collector` | **불가** | 프로세스 로컬 SSE 버스 + WS set | `main.py:36, :73`, `docker-compose.yml:25` container_name |
| `scoring_engine` | **불가** | 로컬 sqlite 파일, PRAGMA 없음 | `main.py:52`, `docker-compose.yml:36` container_name |
| `siem_api` | **불가** | 로컬 sqlite + 로컬 tail 태스크 + UDP 포트 바인딩 | `sqlite_backend.py:22`, `main.py:234-260`, `docker-compose.yml:87` container_name |
| `config_service` | **불가** | 로컬 sqlite | `config_service/main.py:43`, `docker-compose.yml` container_name |

결론: **A/D 게임 플레인만 HA다. 컨트롤플레인은 전부 단일 인스턴스 고정이며, 이는 설정이 아니라 코드 구조에서 오는 제약이다.**

---

## 6. UNVERIFIED (실측 필요 항목과 측정 방법)

| # | 항목 | 왜 정적으로 확정 못 하나 | 측정 방법 |
|---|---|---|---|
| U-01 | 실제 SIEM 인덱싱 EPS 상한 | fsync 비용이 호스트 스토리지에 종속(NVMe vs pd-balanced에서 2배 이상 차이) | `python3 loadtest/syslog_flood.py --eps 100/200/400/800 --duration 120` 계단식. 각 단계 후 `GET :8040/sources/health`의 `pfsense:udp_drops`와 `total_events` 증가분을 비교 → **두 수가 어긋나는 지점이 커널 드롭 시작점**(D-02 검증) |
| U-02 | suricata/zeek 22 센서의 실제 EPS | 로그 생성률이 트래픽 종속이라 코드 상수가 없음 | 훈련 시나리오 1회 재생 후 `wc -l /var/log/siem/*/eve.json`과 `conn.log`를 60초 간격 2회 측정해 차분 |
| U-03 | SSE 팬아웃 실측 지연 | §3.2는 json.dumps 25 µs 가정치 | `python3 loadtest/sse_loadtest.py --observers 50/100/150/200 --teams 16 --rate 100/200/400 --duration 60` 격자. 스크립트가 p50/p95/p99와 PASS/FAIL을 출력함(`sse_loadtest.py:120-131`). **p95 1초 초과 지점이 §3.2 포화식의 실측 대응점** |
| U-04 | A/D API의 RPS 상한과 PG 커넥션 고갈점 | psycopg 접속 비용·PG 설정 종속 | `k6 run -e SCOREBOARD_VUS=50,100,200 -e SUBMISSIONS_PER_SECOND=20 loadtest/k6/attack_defense.js`. 동시에 `SELECT count(*) FROM pg_stat_activity`를 1초 간격 샘플링 → 100 근접 시점 기록 |
| U-05 | 컨테이너별 실제 RSS | mem_limit이 없어 상한 추정만 가능(§2-6위) | `docker stats --no-stream --format "{{.Name}} {{.MemUsage}}"`를 기동 직후 / 부하 30분 후 2회. 특히 `*_suricata`, `*_zeek`, `siem_api` |
| U-06 | 8시간 후 sqlite 검색 응답시간 | 문서 임계치는 1만 건 기준(`docs/28:131`), 실제는 576만 건 | 5.76M 행을 합성 주입 후 `GET :8040/search?text=...` p95 측정. `docs/28`의 500 ms 임계치를 **실 규모 기준으로 재작성해야 함** |
| U-07 | `siem_logs` 볼륨 증가율 | 로테이션 없음(§2-7위)이지만 증가율은 트래픽 종속 | 훈련 중 `docker system df -v`로 `siem_logs` 크기를 시간당 샘플링 → 8시간 외삽 |
| U-08 | 하드닝 오버레이 적용 시 event_collector 실제 포화점 | `cpus: "0.5"`(`hardening:55`)가 §3.2 예산의 근거이나 미실측 | U-03을 하드닝 오버레이 적용/미적용 두 조건으로 각각 실행해 비교 |

---

## 7. 최소 수정 우선순위 (참고)

1. 모든 컨트롤플레인 sqlite 연결에 `PRAGMA journal_mode=WAL; synchronous=NORMAL; busy_timeout` 적용 — `attack_defense/db.py:146-153`이 이미 올바른 참조 구현이다. 나머지 5곳(`event_collector/main.py:76`, `scoring_engine/main.py:52`, `config_service/main.py:43`, `siem/storage/sqlite_backend.py:27`, `siem/storage/alert_store.py:21`)이 이를 따르지 않는다.
2. `sqlite_backend.index()`를 `asyncio.to_thread`로 빼고 연결을 재사용 — D-02의 루프 정지 제거.
3. `event_client.py:53-55`와 `event_collector/main.py:200-201`의 `pass`에 최소한 **드롭 카운터**를 붙일 것 — 유실을 못 막더라도 유실을 보이게 해야 한다.
4. `_sse_frame` 결과를 구독자 루프 밖에서 1회 직렬화 후 재사용 — §3.2 포화점을 구독자 수와 무관하게 만든다.
5. `.github/workflows/ci.yml`에 야간 loadtest 잡과 `ATTACK_DEFENSE_TEST_POSTGRES_URL` 서비스 컨테이너 추가 — D-04, D-08 동시 해소.
