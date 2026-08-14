# J축 감사 — 코드 건전성 (Code Health)

감사 대상: `/home/mintkangaroo/Project/Cyber_offensive_Defense_Project/cyber-range-platform`
방식: 정적 분석 전용(AST 스캔 + grep + 파일 정독). 테스트 미실행, docker 미실행.
기준일: 2026-08-14

---

## 1. 요약 판정 테이블

| 항목 | 판정 | 근거 (path:line) | 실전 영향 |
|---|---|---|---|
| 커버리지 측정 설정 | **없다** | 저장소 루트에 `.coveragerc`·`pytest.ini`·`pyproject.toml`·`setup.cfg` 파일이 존재하지 않음. `requirements-dev.txt:1-4` 전체 내용은 `-r requirements.txt` + `pytest==8.3.3` 뿐 — `pytest-cov` 없음 | 어느 채점 분기가 실행된 적 없는지 아무도 모른다. 커버리지 회귀를 감지할 수단이 0 |
| 린트 설정 | **없다** | `.ruff_cache/0.16.0/` 는 존재하나(누군가 로컬에서 ruff 실행) 저장소에 `ruff.toml`·`.ruff.toml`·`[tool.ruff]` 섹션 없음. `.github/workflows/ci.yml` 128줄 전체에 `ruff`·`flake8`·`black` 문자열 0회 | 로컬에서만 임의 규칙으로 돌아간 흔적. CI 게이트 아님 → 스타일/버그 패턴 회귀 무방비 |
| 타입 체크 | **없다** | `mypy.ini` 없음, CI에 `mypy` 0회. 백엔드 전체에 타입힌트는 있으나 검증 주체 없음 | 시그니처 불일치가 런타임에만 드러남 |
| tsconfig strict | **있다** | `dashboards/{livefire,siem,redportal,blueportal}/tsconfig.json:14` `"strict": true` (4/4) | 프런트 타입 안정성은 유일하게 게이트가 있는 영역 |
| 채점 로직 테스트 — `services/scoring_engine` | **전무** | `tests/` 전체에서 `services.scoring_engine` import 0회 (`grep -rhoE 'from services[a-zA-Z0-9_.]*' tests/` 결과에 부재) | 10개 이벤트 타입 분기(`main.py:143-227`) 중 단 하나도 테스트 안 됨. Live Fire 본선 점수 계통 |
| 채점 로직 테스트 — `attack_defense/flag_service` | **있다(분기 깊음)** | `tests/attack_defense/test_security.py:214,222,248,275,303,312,331` 이 malformed·expired·future·cross_match·disabled·replay 를 모두 검증 | A/D 플래그 검증은 실제로 방어됨 |
| 채점 로직 테스트 — `attack_defense/scoring.ScoringService` | **껍데기만** | 테스트가 import 하는 것은 `ConfigurableScoringPolicy` 하나뿐(`test_core_unit.py:9,61`). `calculate_round` 호출은 `test_integration.py:70` 단 1회(해피패스). `recalculate_match`·`adjustment`·`scoreboard`·`_apply_target` 직접 테스트 0 | 라운드 채점 멱등성·재계산·수동조정이 미검증. 대회 중 재계산 시 점수 붕괴 감지 불가 |
| 채점 로직 테스트 — `attack_defense/checker` (실 HTTP) | **없다(전량 Fake로 대체)** | `tests/attack_defense/fakes.py:14-49` 가 `FakeInjector`/`FakeChecker` 로 전부 대체. `checker.py:95-268` 의 `HttpFlagInjector`·`HttpWorkflowChecker` 는 어느 테스트에서도 인스턴스화되지 않음. 테스트가 건드리는 것은 `derive_management_token`(`test_kubernetes_runtime.py:14`)과 dataclass뿐 | SLA 판정의 실제 경로(타임아웃→`"timeout"`, 연결실패→`"connection"`, 체커 버그→`"checker_system_error"`)가 미검증. 체커 오작동 = 전 팀 가용성 0점 |
| 채점 로직 테스트 — `challenges/*/grader/*.py` (77개) | **없다** | 77개 grader 중 단위 테스트 대상 0. CI 잡 2(`ci.yml:33-47`)의 `scripts/validate_challenges.sh:22-29` 는 아티팩트형/탐지형만 실채점하고 **서비스형은 스키마만**(`validate_challenges.sh:28` `svc=$((svc+1))   # 서비스형/특수: 스키마만`) | WEB/ICS 계열 실채점기가 한 번도 실행 검증되지 않은 채 본선 투입 |
| 격리 로직 테스트 — `attack_defense/network_policy` | **있다** | `tests/attack_defense/test_security.py:11` 이 `ContainerPolicySpec`·`validate_container_policy` import. 모듈 43 LOC 전체가 순수 함수 1개 | 유일하게 커버된 격리 로직 |
| 격리 로직 테스트 — `infra/ci/isolation_test.py` (162 LOC) | **없다** | `grep -rn 'infra' tests/` 결과는 `test_artifact_solve.py:13` 한 줄뿐(challenge_qa 경로). CI에 `isolation_test` 문자열 0회 | 격리 회귀 테스트 자체가 CI에서 실행되지 않는다. "격리 검증됨"의 근거가 수동 실행 |
| 격리 로직 테스트 — `shared/rbac.py` | **있다** | `tests/unit/test_rbac.py`(135 LOC), `tests/unit/test_rbac_jwt.py`(109 LOC) | dev_mode 우회 자체는 코드 설계 결함(§4 참조)이나 테스트는 존재 |
| 계약 테스트 실효성 | **모델 검증만** | `tests/test_contracts.py` 9개 함수 전부 pydantic 생성/필드 assert. `api_contract.Ports`·`EventCollectorAPI`·`ScoringAPI`·`SiemAPI`·`InstructorAPI`(=`shared/api_contract.py:17-76`)의 **포트·경로 상수를 검증하는 테스트가 0개** | 계약 상수가 현실과 어긋나도 CI 통과(§5에 실제 어긋난 사례) |
| 보안 스캐너 | **전무** | `ci.yml` 128줄에 `trivy`·`semgrep`·`bandit`·`pip-audit`·`npm audit`·`syft`/SBOM 0회 | 국가 기반시설 레인지에 공급망 게이트 없음 |
| `infra/ci/secret_scan.py` CI 연동 | **없다** | CONTRACTS.md:98 이 존재를 명시하나 `.github/workflows/` 에 `secret_scan` 0회 | 시크릿 유입 방지 스캐너가 자동 실행되지 않음 |
| 구조화 로깅 | **없다** | `import logging` 을 쓰는 파일은 `services/attack_defense/game_engine.py`·`services/attack_defense/api.py`·`shared/siem_access_log.py` **3개뿐**. 나머지 전 서비스는 `print()` 41회 | AAR·사후조사에서 서비스 로그를 기계적으로 파싱할 수 없다 |
| prometheus_client / OpenTelemetry | **없다** | `grep -rn 'prometheus_client\|opentelemetry' services/ shared/` 결과 0. `services/observability/metrics.py:1-8` 이 명시: "서비스마다 계측 라이브러리를 심는 대신… `/health` 를 스크레이프" | 지연·에러율·큐길이 등 내부 지표 없음. `/health` 도달성만 관측 |
| 상관 ID (request/trace id) | **부분** | `Event.trace_id`(이벤트 도메인)·`correlation_id`(A/D 감사, `scoring.py:231`, `flag_service.py:109`)는 있으나 HTTP 계층 `X-Request-Id` 미들웨어는 `grep -rn 'X-Request-Id' services/ shared/` 결과 0 | 서비스 경계를 넘는 요청 추적 불가 |
| 순환 의존 | **없다** | `grep -rn '^\(from\|import\) services' shared/` 결과 0(shared→services 역방향 없음). 서비스 간 import 는 `services/noc_monitor/api/main.py:21 → services.core.recovery_watcher` 하나뿐, 나머지는 전부 패키지 내부 | 계층 규율은 지켜짐 |

---

## 2. 테스트 커버리지 갭표

| 모듈 | LOC | 전용 테스트 | 핵심 분기 커버 여부 |
|---|---|---|---|
| `services/scoring_engine/main.py` | 357 | **없음** | `score_ingest` 10개 이벤트 타입 분기(143-227) 전부 미커버. `_award` 멱등성(105-124), `_dwell_bonus`(126-136), `reconcile`(298), `adjust_score`(265) 전부 미커버 |
| `services/attack_defense/scoring.py` | 349 | 간접만 | `ConfigurableScoringPolicy`(24-40, 17 LOC)만 직접 테스트. `_apply_target`(66-119) 델타/멱등 분기 미커버, `recalculate_match`(239-247) 미커버, `adjustment`(249) 미커버, `scoreboard`(277) 미커버 |
| `services/attack_defense/flag_service.py` | 321 | **있음(깊음)** | `validate_submission`(150-306) 6개 이상 거부 분기 커버. `expire_flags`(307) 미확인 — UNVERIFIED |
| `services/attack_defense/checker.py` | 269 | 이름만 | `derive_management_token`(18-33)만. `HttpFlagInjector`(95-150)·`HttpWorkflowChecker`(152-268) **0%** — 전량 `fakes.py` 로 우회 |
| `challenges/*/grader/*.py` | 77 파일 | **없음** | 서비스형(WEB/ICS 계열)은 CI에서 스키마만(`validate_challenges.sh:28`). `grade_red`/`grade_blue` 본체 미실행 |
| `services/attack_defense/network_policy.py` | 43 | 있음 | 유일한 함수 `validate_container_policy` 커버 |
| `infra/ci/isolation_test.py` | 162 | **없음** | 5개 체크 함수(44,57,69,81,94) 전부 미커버. CI 미연동 |
| `shared/rbac.py` | 142 | 있음(244 LOC) | dev_mode·JWT·정적토큰 경로 커버 |
| `services/event_collector/main.py` | 367 | **없음** | 이벤트 dedup·SSE 발행·scoring 전달 전부 미커버 |
| `services/config_service/main.py` | 275 | **없음** | 패치 토글/킬스위치 — Blue 훈련의 핵심 |
| `services/range_control/main.py` | 372 | **없음** | baseline 검증·긴급정지 오케스트레이션 |
| `services/instructor_api/main.py` | 172 | **없음** | 교관 콘솔 |
| `services/ground_station/main.py` | 400 | **없음** | 트윈 |
| `services/defense_network/main.py` | 329 | **없음** | 트윈 |
| `services/patch_console/api/main.py` | 184 | **없음** | 게다가 배포조차 안 됨(§5) |
| `services/noc_monitor/api/main.py` + `health_poller.py` | 121 + 163 | **없음** | 가용성 판정 = 복구 채점의 입력 |
| `services/core/recovery_watcher.py` | 91 | **없음** | `asset_recovered` 최종 판정 = Blue 50점 |
| `shared/safe_probe.py` | 394 | 있음(139 LOC) | 레지스트리/분류/emit 억제 커버. 네트워크 계층은 모킹 |

**총평**: 채점 계통 두 개 중 Live Fire 쪽(`scoring_engine` 357 LOC)은 커버리지 0, A/D 쪽은 플래그 검증만 깊고 라운드 채점은 해피패스 1회. 격리 계통은 43 LOC짜리 순수함수 하나만 커버되고 실측 도구(162 LOC)는 CI 밖.

---

## 3. 크래시 위험 지점 (훈련 중단 유발 가능)

AST 스캔 결과 요약: `except …: pass` **83건**, timeout 없는 HTTP 호출 **24건**, 예외 핸들러 없는 `asyncio.create_task` **13건**(전 저장소에 `add_done_callback`·`TaskGroup`·`set_exception_handler` **0회**).

| # | 파일:라인 | 유형 | 훈련 중 무엇이 멈추는가 |
|---|---|---|---|
| 1 | `services/incident/main.py:288` + `:296` + `:297` | SQLite 커넥션 누수 + 예외 삼킴 | `c = _db()`(288) → `c.close()`(296)가 **try 블록 안**, `except Exception: pass`(297). 288~296 사이 어떤 예외(SQLite lock, `next()` StopIteration)든 커넥션이 닫히지 않는다. `_correlate_loop` 는 10초 주기(`:278`) → 하루 8,640회 누수 → `Too many open files` 로 인시던트 서비스 사망. 그 시점부터 SIEM 알림→인시던트 승격이 조용히 중단되고 Blue 팀은 인시던트가 안 오는 이유를 알 수 없다 |
| 2 | `services/incident/main.py:304` | 백그라운드 태스크 예외 미처리 | `asyncio.create_task(_correlate_loop())` — 위 루프가 `while True` 밖에서 죽으면(예: `_db()` 자체가 OSError) 태스크가 조용히 종료. `/health` 는 200을 계속 반환 → 컨테이너는 "정상"인데 상관 기능만 죽어있다. 교관이 알 방법 없음 |
| 3 | `services/noc_monitor/api/main.py:72-73` | 백그라운드 태스크 예외 미처리 | `poll_forever()`, `_subscribe_compromise_events()` 둘 다 fire-and-forget. 후자는 `:64 except Exception: await asyncio.sleep(5)` 로 자기복구하지만 `poll_forever` 는 UNVERIFIED. poller가 죽으면 uptime/health 샘플이 멈추고 → `recovery_watcher` 의 "health 3연속" 조건이 영구 미충족 → **Blue의 asset_recovered 50점이 영구히 나오지 않는다** |
| 4 | `services/siem/api/main.py:235,239,258,260,264,142,144` | 백그라운드 태스크 예외 미처리 (7건) | startup 에서 트윈 tail·syslog consumer·자산별 Suricata/Zeek tail(자산 N개 × 6 태스크)을 전부 fire-and-forget. 어느 하나가 죽으면 **그 자산의 로그 수집만 조용히 멈춘다**. SIEM `/health`(`:268`)는 `rules_loaded` 만 보고하므로 200 유지. Blue는 해당 자산 공격을 영원히 탐지 못 하고, 탐지 점수(20점/건)와 dwell 보너스가 사라진다 |
| 5 | `services/event_collector/main.py:162` | 백그라운드 태스크 + 예외 삼킴 | `asyncio.create_task(_forward_to_scoring_engine(event))` → `:199 except httpx.HTTPError: pass`. scoring_engine 이 다운/지연이면 **그 이벤트의 점수는 영구 소실**된다(재시도·큐·DLQ 없음). 이벤트는 저장되므로 사후 `reconcile` 로만 복구 가능하나 자동 아님. 라운드 중 scoring 재시작 = 그 구간 점수 증발 |
| 6 | `services/scoring_engine/main.py:222` | 입력 검증 없는 형변환 | `points = int(event.metadata.get("points", 0))` — `metadata.points` 가 `"abc"` 이면 `ValueError` → FastAPI 500. `stage_completed` 이벤트를 발행하는 `scenario_engine/runner.py` 나 교관 수동 주입이 문자열을 넣으면 **채점 엔진이 500을 뱉고 해당 이벤트 점수 소실**. `:236 red_stealth_bonus` 의 `int(...bonus_points...)` 도 동일 |
| 7 | `services/scoring_engine/main.py:144-226` | 커넥션 누수 (try/finally 부재) | `conn = get_db()`(144) … `conn.commit(); conn.close()`(224-225)가 **보호되지 않음**. #6의 ValueError 나 SQLite lock 발생 시 커넥션이 닫히지 않고 트랜잭션도 롤백되지 않는다. 반복되면 scoring_engine 이 파일디스크립터 고갈 → **전 종목 채점 정지** |
| 8 | `services/scoring_engine/main.py:52` (및 동일 패턴 17개 파일) | SQLite 동시쓰기 락 미대비 | `sqlite3.connect(DB_PATH)` — `PRAGMA journal_mode=WAL`·`busy_timeout` 미설정(기본 DELETE 저널). 대조군: `services/attack_defense/db.py:151-153` 만 WAL+`busy_timeout=10000` 설정. 동일 결함이 `event_collector/main.py:76`, `config_service/main.py:43`, `noc_monitor/health_poller.py:52,80,130,142,154`, `edr/api/main.py:56`, `auth/main.py:46`, `incident/main.py:49`, `injects/main.py:79`, `challenge_portal/main.py:50`, `instructor_api/audit_store.py:18`, `siem/storage/alert_store.py:21`, `siem/storage/sqlite_backend.py:27`, `patch_console/api/main.py:36`, `ground_station/main.py:98` 에 존재. 다팀 동시 제출 부하에서 `database is locked` → 500. `event_collector` 는 이벤트 유실, `scoring_engine` 은 채점 유실 |
| 9 | `shared/safe_probe.py:64,70,76,82,88,94,101,107,113,119,127,133,139,147,153,159,165,171,180,186` (20건) | HTTP timeout 전무 | 20개 프로브 전부 `requests.get/post(...)` 에 `timeout` 인자 없음 = **무한 대기**. 이 모듈은 `services/range_control/main.py:31` 이 import 하여 `:263 probe = safe_probe.run(emit=False)` 로 **HTTP 핸들러 안에서 동기 호출**한다. 트윈 하나가 TCP 연결을 수락하고 응답하지 않으면 `/ranges/{id}/verify-baseline` 요청이 영구 블록되고, uvicorn 기본 워커 풀이 소진되면 **range_control 전체(리셋·긴급정지 포함)가 응답 불능**. 교관이 훈련을 리셋할 수 없는 상태 |
| 10 | `services/attack_defense/scoring.py:126-128` | KeyError → 500 | `calculate_round` 가 라운드 미존재 시 `raise KeyError(round_id)`. `api.py:436,458,487,…` 이 KeyError 를 404로 매핑하는 경로들은 있으나, `game_engine` 이 이 함수를 백그라운드에서 호출하는 경로는 UNVERIFIED. 매핑 밖에서 터지면 라운드 채점 중단 |
| 11 | `services/attack_defense/scoring.py:129,131` | 검증 없는 키 접근 | `match = self.repo.get_match(match_id, conn)` 직후 `json_load(match["config"])` — `get_match` 가 None 반환 시 `TypeError`. 같은 함수 `:231 round_row["correlation_id"]` 도 무방비. 매치 레코드가 정리된 뒤 지연 채점이 돌면 라운드 채점 트랜잭션이 통째로 롤백 |
| 12 | `services/attack_defense/scoring.py:240-244` | 커넥션 누수 | `recalculate_match`: `conn = self.db.connect()`(240) → `conn.close()`(244)가 try/finally 없이. 중간 쿼리 실패 시 누수. 운영자가 재계산을 반복 시도하면 누적 |
| 13 | `services/siem/api/main.py:161,180` | 예외 삼킴 | `_promote_to_incident`·`_push_detection_to_livefire` 의 `except httpx.HTTPError: pass`. 후자가 실패하면 **Blue 탐지 성공이 Event Collector 에 도달하지 못해 탐지 점수 20점 + dwell 보너스가 영구 소실**된다. 재시도 없음. SIEM 화면에는 알림이 떠 있으니 Blue 는 점수가 왜 안 오르는지 알 수 없다 |
| 14 | `services/event_collector/main.py:88` / `services/edr/api/main.py:99` | 스키마 마이그레이션 실패 은폐 | `except sqlite3.OperationalError: pass` — `ALTER TABLE … ADD COLUMN` 실패를 "이미 존재"로만 간주. 파일 손상·권한 문제로 실패해도 통과하고, 이후 INSERT 가 컬럼 개수 불일치로 매 이벤트마다 500 |
| 15 | `services/power_plant/main.py:159,172,213,228,245,262` / `services/water_utility/main.py:128,136,150,208,219,237` (12건) | 광범위 예외 삼킴 | 물리 시뮬 루프·Modbus 핸들러의 `except Exception: pass`. 시뮬 계산이 깨져도 트윈은 계속 "정상" 응답 → **물리 상태가 얼어붙은 채로 훈련 진행**. Red 의 ICS 공격 효과가 반영되지 않고 Blue 는 이상을 볼 수 없다 |
| 16 | `shared/ics/twin_modbus.py:87,95,108,120,140,153` (6건) + `:166` create_task | Modbus 프로토콜 계층 예외 삼킴 + 태스크 미감시 | 7개 섹터 트윈이 공유하는 Modbus 헬퍼. 레지스터 읽기/쓰기 예외를 전부 삼킴 → 실 프로토콜 공방에서 공격 성공/실패가 무음 처리 |
| 17 | `services/auth/main.py:133` (startup 시점 `_seed()` at `:134`) | startup 실패 시 부분 사망 | `_seed()` 가 모듈 임포트 시점에 실행되며 예외 보호 없음. DB 볼륨 권한 문제 시 컨테이너가 아예 안 뜨는 것은 오히려 낫지만, `_init()`(`:122`) 이후 부분 성공하면 사용자 테이블 없이 기동 |
| 18 | `services/event_collector/main.py:116-118` | 무의미한 startup 훅 | `@app.on_event("startup") async def startup(): pass` — 초기화가 전부 모듈 임포트 시점(`:113 init_db()`)에 발생. `init_db()` 가 실패하면 임포트 실패로 컨테이너가 죽으므로 이 케이스는 탐지되나, 헬스체크 기반 진단이 불가 |
| 19 | `shared/sse_bus.py:54` | 큐 오버플로 무음 폐기 | `except asyncio.QueueFull: pass` — 관전 대시보드 구독자가 느리면 이벤트가 조용히 버려진다. 상황판이 실제 경기와 어긋난 채 표시되고 아무 경고가 없다 |
| 20 | `challenges/web/WEB-002/grader/blue_grader.py:26-28` (동형 다수) | 네트워크 실패 = 0점 | `except requests.exceptions.RequestException: return GradeResult(False, 0, …)` — 대상 미도달과 "패치 안 됨"이 **동일하게 0점**. 일시적 네트워크 문제로 Blue 가 정당한 100점을 잃고, 결과에는 `could not reach deploy` 만 남는다(재시도·재채점 없음) |

---

## 4. 시크릿 · 로깅 위생

### 4.1 코드 내 시크릿 기본값
| 위치 | 내용 |
|---|---|
| `services/attack_defense/cli.py:115,202,254` | `os.environ.get("INSTRUCTOR_TOKEN", "dev-instructor-token")` — **코드 하드코딩 폴백 3곳** |

### 4.2 compose 기본값으로 주입되는 시크릿
`docker-compose.yml` 이 `${VAR:-기본값}` 형태로 **운영 가능한 값이 채워진 채** 기동된다:

| 라인 | 변수 | 기본값 |
|---|---|---|
| 42,58,74,118,132,177,243,342,507 (9곳) | `INSTRUCTOR_TOKEN` | `dev-instructor-token` |
| 188,242,341 | `AUTH_JWT_SECRET` | `demo-jwt-secret-change-before-production-32bytes` |
| 189 | `AUTH_ADMIN_PASSWORD` | `demo-operator-change-me` |
| 239,338 | `ATTACK_DEFENSE_FLAG_SECRET` | `attack-defense-dev-flag-secret-change-me` |
| 240,339 | `ATTACK_DEFENSE_FLAG_HASH_SECRET` | `attack-defense-dev-hash-secret-change-me` |
| 241,340,423 | `ATTACK_DEFENSE_MANAGEMENT_TOKEN` | `attack-defense-dev-management-token` |
| 274,368 | `PCAP_ANONYMIZATION_SECRET` / `PCAP_WATERMARK_SECRET` | `…-change-me` |
| 304,334 | `AD_POSTGRES_PASSWORD` | `ad-ha-dev-password-change-me` |

`.env` 미설정 시 이 값들이 그대로 유효 시크릿이 된다. **`ATTACK_DEFENSE_FLAG_SECRET` 이 기본값이면 플래그 토큰을 누구나 재생성할 수 있다**(`flag_service.py:62 _token()` 이 이 시크릿으로 파생). "실패해서 뜨지 않는" 안전장치가 없다 — 조용히 dev 시크릿으로 기동한다.

### 4.3 dev_mode 인증 전면 우회
`shared/rbac.py:93-95`:
```
if not mapping and not has_jwt:
    return Identity(actor="unauthenticated", role="instructor", dev_mode=True)
```
그리고 `rbac.py:134-135` `if ident.dev_mode: return ident` — **모든 역할 검사를 무조건 통과**시킨다. 즉 `INSTRUCTOR_TOKEN`/`RED_TOKEN`/…/`AUTH_JWT_SECRET` 이 전부 비어 있으면 미인증 요청이 교관 권한을 얻는다. 이것이 실전에서 발동할 조건은 "환경변수 누락" 하나뿐이며, 발동해도 경고 로그·헬스 표시가 없다.
추가로 `rbac.py:106-115 read_enforced()` 의 기본값은 **off** — `OBSERVER_READ_ENFORCE` 미설정 시 `/scores`·`/events` 등 읽기 엔드포인트는 완전 공개. 경기 중 Red 가 Blue 점수·이벤트를 무인증 조회할 수 있다.

### 4.4 로그에 찍히는 비밀
| 위치 | 내용 |
|---|---|
| `services/auth/main.py:130` | `print(f"[auth] 시드 교관 계정 생성: instructor / {pw} …")` — **생성된 교관 비밀번호를 평문으로 stdout 출력** → `docker compose logs` / CI 로그 / 로그 수집기에 영구 기록. `ci.yml:120` 의 `docker compose logs --tail=80` 이 실패 시 GitHub Actions 로그에 이를 노출할 수 있다 |

플래그·토큰이 로그에 찍히는 다른 지점은 grep 상 발견되지 않았다(`(print|logger.*)\(.*(flag\|token\|password\|secret)` 스캔 결과 위 1건).

### 4.5 관측성
- `prometheus_client`·`opentelemetry` 의존성 **0**. `requirements.txt` 12개 패키지에 없음.
- `services/observability/metrics.py:1-8` 이 설계 의도를 명시: 계측 라이브러리를 심지 않고 각 서비스 `/health` 를 스크레이프해 Prometheus 텍스트 형식으로 **재구성**. 따라서 관측 가능한 것은 **도달성(up/down)과 `/health` 가 자발적으로 노출하는 카운터**뿐이다. 요청 지연 분포, 에러율, 큐 깊이, 태스크 생존 여부는 관측 불가 — §3의 결함 2·3·4(태스크 무음 사망)가 **탐지 불가능한 이유가 바로 이것이다**.
- 구조화 로깅 없음: `logging` 사용 3파일 vs `print()` 41회.
- HTTP 상관 ID 없음: `X-Request-Id`/`correlation_id` 미들웨어 grep 결과 0. 도메인 레벨 `trace_id`(이벤트)와 `correlation_id`(A/D 감사)는 존재하나 서비스 경계 HTTP 호출에 전파되지 않는다.

---

## 5. 의존성 그래프 괴리 (문서 vs 실제)

### 5.1 문서에 있으나 실재하지 않는 의존
| 문서 주장 | 실제 |
|---|---|
| `CONTRACTS.md:118` — "콘텐츠 C0~C6 → `challenge_schema`(Challenge), **`api_contract`(GradeResult)**" | **77개 grader 중 `from shared.api_contract` 를 import 하는 파일 0개.** 77개 전부가 자기 파일 안에 `class GradeResult` 를 재정의한다(예: `challenges/web/WEB-002/grader/blue_grader.py:11-15`). 채점 계약이 78벌 존재하며 어느 것도 서로 검증되지 않는다 |
| `docs/17_repo_structure_and_impl.md:11-19` — 최상위 `contracts/`, `platform/`, `siem/` | 실재: `shared/`, `services/`, `services/siem/`. `platform/→services/` 는 `CONTRACTS.md:104-106` 이 사후 정정했으나 `contracts/`·`siem/` 는 미정정. `docs/17:38` 의 `from contracts.shared... import` 는 실제 `from shared...` |
| `docs/17:14` — "`docs/` 기획·프롬프트 문서(00~16)" | 실제 `docs/00~31` + 부속 문서 다수 |
| `INTEGRATION.md:5` — "`cyber-range-contracts/` — 계약, scenario_engine, patch_console, noc_monitor, config_service, edr" | 그런 최상위 디렉토리 없음. 전부 `services/` 하위로 병합됨 |
| `CONTRACTS.md:68` — `uvicorn services.patch_console.api.main:app --port 8060` | **8060은 `challenge_portal` 이 점유**(`docker-compose.yml:503 ports: ["8060:8060"]`). `README.md:780` 도 "Challenge Portal 8060" 이라 적어 CONTRACTS.md 와 직접 충돌 |

### 5.2 `shared/api_contract.py` 계약 vs 실제
`api_contract.Ports`(`:17-30`)가 선언하는 13개 포트 중:
- `PATCH_CONSOLE = 8060`(`:29`) — **틀렸다**. 8060은 challenge_portal. 그리고 `patch_console` 은 `docker-compose.yml`·`docker-compose.prod.yml`·`docker-compose.override.yml`·`Makefile` 어디에도 **서비스 정의가 없다**(`grep -n 'patch_console' docker-compose*.yml Makefile` → 0건). 즉 184 LOC + `whitelist.py` 가 배포되지 않는 코드다. 그런데 `docs/30_master_flow_overview.md:98` 은 "Blue가 patch_console에서 GS-001 패치 클릭" 을 훈련 시나리오 8단계로 기술한다 — **문서가 규정한 훈련 흐름의 한 단계가 배포 대상이 아니다**.
- `Ports` 에 **누락된** 실제 게시 포트: `auth 8051`, `range_control 8055`, `challenge_portal 8060`, `incident 8095`, `injects 8096`, `observability 8097`, `attack_defense 8088/8090/8100`, 섹터 트윈 `8201-8209`. 즉 "단일 진실원"(`api_contract.py:16` 주석)이 실제 토폴로지의 절반 이하만 담고 있다.
- `tests/test_contracts.py` 는 `Ports`·`EventCollectorAPI`·`ScoringAPI`·`ConfigAPI`·`SiemAPI`·`InstructorAPI` 를 **한 번도 import하지 않는다**(import 목록: `event_schema`, `siem_schema`, `challenge_schema`, `api_contract` 에서 `ScoreAdjustRequest`·`GradeResult` 만). 위 포트 오류가 CI를 통과하는 이유.

### 5.3 문서에 없는 실제 의존
- `services/noc_monitor/api/main.py:21 → services.core.recovery_watcher` — 서비스 간 유일한 직접 import. `CONTRACTS.md:93-94` 가 두 모듈을 개별 나열하나 이 결합은 "누가 무엇을 import 하나"(`CONTRACTS.md:110-118`) 절에 없다.
- `services/range_control/main.py:31 → shared.safe_probe` — range_control 이 트윈 프로브 라이브러리를 HTTP 핸들러에서 동기 실행한다(§3 #9). 어느 문서에도 없다.
- `shared/ics_twin.py:28-32` → `event_client`·`event_schema`·`config_client`·`edr_agent`·`siem_access_log` 5중 결합. `shared/` 내부 결합도가 문서화되지 않음.

### 5.4 순환 의존
**없다.** `shared/` → `services/` 역방향 import 0건, 서비스 간 상호 import 0건(§5.3의 단방향 1건 제외). 계층 방향성은 유지되고 있다.

---

## 6. 중복 / 잔존 코드

| 항목 | 근거 | 판정 |
|---|---|---|
| **두 개의 채점 계통** | `services/scoring_engine/main.py`(357 LOC, SQLite `achievements`/`team_scores`, 이벤트 타입별 고정 점수표 `:36-48`) vs `services/attack_defense/scoring.py`(349 LOC, `score_snapshots`/ledger 기반 결정론적 라운드 재계산). 점수 모델·저장소·멱등 키가 전부 다르고 상호 참조 없음 | **중복 아닌 이중 시스템**. 문제는 어느 문서도 "어느 훈련 모드에서 어느 계통이 권위인지" 명시하지 않는다는 점. `docs/30_master_flow_overview.md` 는 Live Fire 흐름만 기술 |
| **두 개의 ICS 트윈 헬퍼** | `shared/ics_twin.py`(119 LOC) — 9개 서비스가 import. `shared/ics/twin_modbus.py`(177 LOC) — 7개 서비스가 import. **`airport_ot`·`datacenter_bms`·`hospital_ot`·`lng_terminal`·`railway_signaling`·`refinery_plant`·`smart_factory` 7개 서비스가 둘 다 import 한다** | **실질 중복**. 두 헬퍼 모두 `event_client.emit_event`·`event_schema`·`siem_access_log` 를 각자 배선(`ics_twin.py:28-32` vs `twin_modbus.py:23-25`). 같은 트윈 안에 이벤트 발행 경로가 2개 → 이벤트 중복/누락 진단이 어려움 |
| `dashboards/livefire/src/LegacyExerciseApp.tsx` | `App.tsx:2` 에서 import, `App.tsx:43` 에서 렌더 | **죽은 코드 아님 — 현역**. 이름만 "Legacy" 이고 실제로는 A/D 모드가 아닐 때의 기본 화면. 명명이 잘못됨 |
| `services/patch_console/` (184 + whitelist LOC) | compose 정의 0건(§5.2) | **배포되지 않는 코드**. 테스트도 없음. `docs/19` 전체와 `docs/30:98` 이 이를 전제로 서술 |
| `services/event_collector/main.py:116-118` | `@app.on_event("startup") async def startup(): pass` | 빈 훅 잔존 |
| grader `GradeResult` 77벌 | §5.1 | 계약 중복 |

---

## 7. 결함 목록 (심각도 순)

**S1 — 훈련 중단/점수 붕괴 직결**

1. **채점 엔진 `scoring_engine` 커버리지 0 + 커버리지 측정 수단 없음.** 357 LOC, 10개 이벤트 분기, 테스트 0. `.coveragerc`·`pytest-cov` 부재로 이 사실이 CI에서 드러나지 않는다. 근거: `requirements-dev.txt` 전체 4줄, `tests/` 내 `services.scoring_engine` import 0회.
2. **백그라운드 태스크 13개 전부 예외 미감시 + 관측 수단 없음.** `add_done_callback`·`TaskGroup` 전 저장소 0회, `prometheus_client`/OTel 0회. 태스크가 죽어도 `/health` 는 200. SIEM tail 태스크(`siem/api/main.py:235-264`) 사망 = 해당 자산 탐지 영구 중단. NOC poller(`noc_monitor/api/main.py:72`) 사망 = Blue 복구 점수 영구 미지급.
3. **`shared/safe_probe.py` 20개 HTTP 호출에 timeout 없음 + range_control 핸들러에서 동기 호출.** 트윈 하나가 응답을 지연시키면 `range_control` 이 응답 불능이 되어 **교관이 리셋·긴급정지를 할 수 없다**. 근거: `safe_probe.py:64-186`, `range_control/main.py:31,263`.
4. **A/D 실 체커(`checker.py:95-268`) 테스트 0%.** 전 테스트가 `fakes.py:14-49` 로 대체. 가용성 채점의 실제 판정 경로(타임아웃/연결실패/체커버그 3분기)가 한 번도 실행 검증되지 않았다. 체커 오작동 = 전 팀 가용성 0점.
5. **SQLite 17개 파일이 WAL·busy_timeout 미설정.** 다팀 동시 부하에서 `database is locked` → `event_collector` 이벤트 유실, `scoring_engine` 채점 유실. 대조군 `attack_defense/db.py:151-153` 만 올바르게 설정.

**S2 — 조용한 점수 소실 / 감사 불능**

6. `event_collector/main.py:199` + `siem/api/main.py:180` 의 `except httpx.HTTPError: pass` — 재시도·DLQ 없이 점수 이벤트 소실. 특히 SIEM→Event Collector 경로 실패는 Blue 탐지 20점 + dwell 보너스 전액 증발이며 화면상 알림은 정상 표시되어 아무도 모른다.
7. `scoring_engine/main.py:144-226` 커넥션 try/finally 부재 + `:222 int(metadata["points"])` 무검증 → 500 시 커넥션 누수 누적.
8. **구조화 로깅·상관 ID 부재.** `logging` 3파일 vs `print()` 41회, `X-Request-Id` 0회. 사고 발생 시 서비스 경계를 넘는 추적이 불가능하고 AAR 근거를 기계적으로 만들 수 없다.
9. 77개 grader가 네트워크 실패를 0점으로 채점(`WEB-002/grader/blue_grader.py:26-28` 외). 재시도 없음.
10. `incident/main.py:288-297` 커넥션 누수 루프(10초 주기).

**S3 — 공급망 / 시크릿 / 계약**

11. **CI에 보안 게이트 전무.** `ci.yml` 128줄에 trivy·semgrep·bandit·pip-audit·npm audit·SBOM·커버리지 임계 0회. `infra/ci/secret_scan.py`·`infra/ci/isolation_test.py` 는 존재하나 **CI에서 실행되지 않는다**(grep 0건).
12. **compose 기본값 시크릿 20+ 곳.** `.env` 미설정 시 `ATTACK_DEFENSE_FLAG_SECRET`·`AUTH_JWT_SECRET` 등이 공개된 dev 값으로 조용히 기동. 플래그 토큰 위조 가능.
13. **`rbac.py:93-95` dev_mode 전면 우회 + `:106-115` read 게이트 기본 off.** 환경변수 누락 하나로 미인증 교관 권한. 경고 없음.
14. `auth/main.py:130` 이 생성된 교관 비밀번호를 평문 stdout 출력.
15. **`api_contract.Ports` 가 실제와 불일치**(`PATCH_CONSOLE=8060` ↔ challenge_portal 점유; 9개 이상 실제 포트 누락)이며 `tests/test_contracts.py` 가 이를 전혀 검증하지 않는다.
16. **`patch_console` 이 배포되지 않는다**(compose 정의 0건). 그런데 `docs/30:98` 이 이를 훈련 흐름 8단계로 규정. 문서-구현 괴리 중 가장 실전 영향이 큰 항목.
17. 77개 grader 가 `api_contract.GradeResult` 대신 자체 `GradeResult` 재정의 — `CONTRACTS.md:118` 의 문서화된 의존이 실재하지 않음.

**S4 — 유지보수**

18. 린트/타입 게이트 부재(`.ruff_cache` 만 존재, 설정·CI 없음, mypy 없음).
19. `shared/ics_twin.py`와 `shared/ics/twin_modbus.py` 이중 배선 — 7개 트윈이 양쪽 다 import.
20. `docs/17`·`INTEGRATION.md` 의 디렉토리 구조가 현실과 다름(`contracts/`·`siem/` 미정정).

---

## 8. UNVERIFIED

| 항목 | 확인 방법 |
|---|---|
| `services/noc_monitor/health_poller.py` 의 `poll_forever()` 내부에 자체 예외 복구 루프가 있는지 | `sed -n '1,60p' services/noc_monitor/health_poller.py` 로 `while True` + `try` 배치 확인 |
| `flag_service.expire_flags`(`:307-320`)를 커버하는 테스트 존재 여부 | `grep -rn 'expire_flags' tests/` |
| `attack_defense/game_engine.py` 가 `ScoringService.calculate_round` 를 호출하는 경로에서 `KeyError`/`TypeError` 를 잡는지 | `grep -n 'calculate_round' -A5 -B5 services/attack_defense/game_engine.py` |
| 각 서비스 Dockerfile 이 `.env` 없는 상태로 기동 시 시크릿 기본값 경고를 내는지 | 각 `services/*/Dockerfile` 및 엔트리포인트 스크립트 정독 |
| `dashboards/control-tower` 483 LOC 단일 index.html 의 XSS/입력처리 — 빌드·타입체크·테스트 대상 밖 | 파일 정독(본 감사 범위 밖으로 남김) |
| SQLite 락 결함(#8)이 실제 다팀 부하에서 재현되는 임계 동시성 | `loadtest/` 의 프로파일로 부하 시험 필요(본 감사는 정적 분석 전용) |
| CI 잡 4(integration)가 실제로 통과 중인지 / 최근 실패 이력 | `gh run list --workflow=ci.yml` |
