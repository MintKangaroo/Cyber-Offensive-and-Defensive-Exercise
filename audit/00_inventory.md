# PHASE 1 — 인벤토리

감사 기준일: 2026-08-14. 저장소 루트: `cyber-range-platform/` (git repo). 상위 디렉터리
`Cyber_offensive_Defense_Project/`는 git 저장소가 아니다 — `git status` 실행 시
`fatal: not a git repository`. `files/`는 버전관리 밖의 원본 기획 문서 사본이다.

전 항목 정적 분석으로만 확인했다. 컨테이너는 기동하지 않았다(사용자 지시). 런타임 동작을
전제로 한 주장은 전부 `UNVERIFIED`로 분류했다.

---

## 0. 전제 정정 — 감사 의뢰서의 규모 수치

| 의뢰서 기술 | 실측 | 근거 |
|---|---|---|
| 기획 문서 33개 | git 추적 `.md` **171개** (그중 `docs/01~31` 33개가 원본 기획 세트) | `git ls-files \| grep -c '\.md$'` = 171 |
| 구현 파일 240개 이상 | git 추적 파일 **999개**, `.py` **410개** | `git ls-files \| wc -l` = 999 |
| Splunk 기준 SIEM | **Splunk는 저장소 어디에도 없다.** 자체 SIEM(FastAPI+SQLite FTS5) | `git grep -il splunk` = 0건. 실제: `services/siem/storage/sqlite_backend.py:56` |

G축(관제) 감사는 Splunk가 아니라 자체 SIEM 기준으로 수행해야 한다.

---

## 1. 컴포넌트 경계 맵

### 1.1 최상위 경계

| 경계 | 경로 | 성격 |
|---|---|---|
| 컨트롤 플레인 | `services/{event_collector,scoring_engine,config_service,siem,edr,scenario_engine,instructor_api,aar_report,range_control,auth,incident,injects,observability}` | 훈련 운영·채점·관제 |
| A/D 게임 엔진 | `services/attack_defense/` (10,224 LOC) | 별도 서브시스템. Postgres 사용, 자체 CLI·마이그레이션·HA·K8s 어댑터 |
| 디지털 트윈 | `services/{ground_station,power_plant,defense_network,refinery_plant,smart_factory,water_utility,lng_terminal,railway_signaling,airport_ot,datacenter_bms,hospital_ot,cloud_native}` | 공격 대상 |
| 공유 라이브러리 | `shared/` (2,987 LOC) | 이벤트 스키마·RBAC·Modbus·물리 시뮬·SSE |
| 챌린지(Jeopardy) | `challenges/{web,forensics,ai,detection,network,reversing,ics}` 69문제 | A/D와 별개 트랙 |
| 시나리오 | `scenarios/{single,crossover}` 15개 YAML | |
| 프런트엔드 | `dashboards/{livefire,redportal,blueportal,siem,control-tower,start-here}` | |
| 인프라 | `infra/{gateway,twin_gateway,suricata,zeek,match,hardening,attack_defense,ci,challenge_qa,deploy}` | |

### 1.2 컴포넌트 실측표

`PYLOC` = git 추적 `.py` 총 라인. `LASTCOMMIT` = 해당 경로 최종 커밋일.

| 컴포넌트 | .py | PYLOC | 전용 테스트 | 최종 커밋 |
|---|---|---|---|---|
| services/attack_defense | 42 | 10,224 | **있음** (tests/attack_defense, 15파일 2,959 LOC) | 2026-08-12 |
| services/siem | 18 | 1,782 | 부분 (`tests/unit/test_siem_engine.py:52`, 52 LOC) | 2026-07-30 |
| services/challenge_portal | 2 | 766 | 간접 1건 | 2026-07-26 |
| services/aar_report | 6 | 629 | 있음 (4파일) | 2026-07-29 |
| services/power_plant | 1 | 514 | 간접(`test_process_sim`, `test_modbus`) | 2026-07-28 |
| services/edr | 3 | 516 | 있음 (`test_edr_rules.py`, 67 LOC) | 2026-07-26 |
| services/ground_station | 1 | 400 | **없음** | 2026-07-24 |
| services/incident | 3 | 394 | 있음 (2파일) | 2026-07-30 |
| services/range_control | 1 | 372 | **없음** | 2026-07-26 |
| services/event_collector | 1 | 367 | **없음** | 2026-07-26 |
| services/scoring_engine | 1 | 357 | **없음** | 2026-07-26 |
| services/defense_network | 1 | 329 | **없음** | 2026-07-26 |
| services/injects | 3 | 345 | 있음 (`test_injects_model.py`, 59 LOC) | 2026-07-26 |
| services/scenario_engine | 5 | 851 | 있음 (3파일) | 2026-07-26 |
| services/auth | 1 | 256 | 간접(`test_rbac_jwt.py`) | 2026-08-12 |
| services/config_service | 2 | 275 | **없음** | 2026-07-26 |
| services/instructor_api | 3 | 234 | **없음** | 2026-07-26 |
| services/patch_console | 4 | 235 | **없음** | 2026-07-24 |
| services/noc_monitor | 4 | 284 | **없음** | 2026-07-26 |
| services/observability | 3 | 187 | 있음 (`test_observability_metrics.py`) | 2026-07-30 |
| services/water_utility | 1 | 243 | 간접 | 2026-07-28 |
| services/cloud_native | 1 | 88 | 있음 (`test_cloud_native.py`) | 2026-07-30 |
| services/{airport_ot,hospital_ot,lng_terminal,smart_factory,railway_signaling,datacenter_bms,refinery_plant} | 각 1 | 92~104 | **없음(개별)** | 2026-07-28 |
| shared/ | 22 | 2,987 | 부분 (ics·rbac·sse·smtp·safe_probe) | 2026-07-28 |
| infra/challenge_qa | 12 | 1,025 | 1건(`test_artifact_solve.py`) | 2026-07-24 |
| infra/ci | 3 | 278 | **없음** | 2026-07-27 |
| scripts/ | 4 | 887 | 부분(`test_beginner_defense.py`, `test_training_environment.py`) | 2026-08-14 |
| challenges/ (7 도메인) | 204 | 9,756 | `scripts/validate_challenges.sh` 게이트 | 2026-07-24~25 |

프런트엔드:

| 대시보드 | 파일 | LOC | 최종 커밋 | 비고 |
|---|---|---|---|---|
| livefire | 35 | 5,342 | 2026-08-14 | 유일하게 테스트 있음(vitest 4개 + Playwright `e2e/live-fire.spec.ts`) |
| redportal | 12 | 980 | 2026-08-14 | 테스트 없음 |
| siem | 14 | 645 | 2026-07-26 | 테스트 없음 |
| blueportal | 9 | 516 | 2026-07-26 | 테스트 없음 |
| control-tower | 1 | 483 | 2026-07-30 | 단일 `index.html`, 빌드 파이프라인 없음 |
| start-here | 1 | 333 | 2026-08-14 | 단일 `index.html` |

### 1.3 시간 축

- 최초 커밋 2026-07-24, 최종 커밋 2026-08-14 — 실작업 3주.
- **`docs/01~31` 기획 문서 31개 전부 최종 커밋일이 2026-07-24**(최초 커밋)에 고정. 이후
  3주간의 구현 변화가 한 건도 반영되지 않았다. 근거: `git log -1 --format=%ad -- docs/NN_*.md`
  → 전부 `2026-07-24`.
- 갱신되는 문서군은 `docs/attack-defense-*.md`(2026-08-09~12)와 `README.md`(08-14)뿐이다.

### 1.4 배포 표면

`docker-compose.yml`은 1,000줄 이상, 서비스 정의 다수:
- A/D 스택: `attack_defense`, `ad_postgres`, `attack_defense_ha`, `ad_ha_gateway`, `ad_registry`,
  팀별 취약 서비스 6개(`ad_team_01~03_{notes,vault}`), `ad_patch_sandbox`
  (`docker-compose.yml:223-484`)
- 트윈 11종 + 트윈별 nginx 게이트웨이 11종 (`docker-compose.yml:531-772`)
- 센서 사이드카: 섹터별 `*_suricata` / `*_zeek` 쌍 (`docker-compose.yml:773-1014+`)
- 공통 하드닝 앵커: `read_only: true`, `cap_drop: ["ALL"]`, `no-new-privileges`,
  `pids_limit: 128`, `mem_limit: 256m`, `cpus: 0.50` (`docker-compose.yml:12-20`)

---

## 2. 설계 문서에 있으나 구현 파일이 없는 기능

| # | 문서 주장 | 구현 실측 | 근거 |
|---|---|---|---|
| D1 | Wazuh 연동 (`docs/26_wazuh_suricata_zeek_integration_plan.md`) | **구현 0**. 코드/컴포즈에 `wazuh` 문자열 전무 | `git grep -il wazuh -- ':!*.md'` = 0건. 문서 3건에만 존재. 단 문서 자체가 0절에서 "우선순위 낮춤"을 명시(`docs/26_...:11-19`) → 의도적 미구현 |
| D2 | pfSense 로그소스 (`docs/01`, `docs/26`) | 파서만 존재(`services/siem/parsers/pfsense.py`, 84 LOC). pfSense 인스턴스·컴포즈 서비스 없음 | `docker-compose.yml`에 pfsense 서비스 정의 없음 |
| D3 | DNP3 (`challenges/ics/ICS-003`) | **프로토콜 스택 없음**. `deploy/generate_artifact.py`가 만드는 합성 JSONL 로그만 | `challenges/ics/ICS-003/deploy/generate_artifact.py:51` → `dnp3_log.jsonl` |
| D4 | IEC 61850 GOOSE (`challenges/ics/ICS-006`) | **동일 — 합성 JSONL** | `challenges/ics/ICS-006/deploy/generate_artifact.py:23` |
| D5 | 위성 TT&C / CCSDS 프레이밍 | **CCSDS 문자열이 저장소 전체에 0건**. `ground_station`은 FastAPI HTTP API로, 취약점은 pickle 역직렬화·SSRF·XXE·경로순회 등 **웹 취약점**이다 | `git grep -i ccsds` = 0건. `services/ground_station/main.py:23`(pickle), `:274`(download_file), `:346`(tle_import), `:377`(xml_import) |
| D6 | Ansible 패치 콘솔 (`docs/19`) | 플레이북 **2개뿐**(`patch_GS-001.yml`, `patch_GS-002.yml`). 트윈은 11종 | `ls services/patch_console/playbooks/` |
| D7 | 대시보드 프로덕션 배포 | **대시보드용 Dockerfile 0개**. `ls dashboards/*/Dockerfile` → `No such file`. `infra/gateway/`가 nginx로 대체하는지 여부 미검증 | `infra/gateway/nginx.conf` (내용 미확인 — UNVERIFIED) |
| D8 | `docs/GAP_ANALYSIS.md` 자체가 **구식** | 6번 항목 "트윈 프로토콜 실체 미구현(HTTP 모사), pymodbus 임포트 전무"라고 단정하지만, 이후 커밋 `1d7dc07`(2026-07-28)이 9개 트윈에 실 Modbus 502를 붙였다. 11번 항목 "LICENSE·SECURITY.md·CHANGELOG 없음"도 현재 전부 존재 | `docs/GAP_ANALYSIS.md:19`(6번 행) vs `shared/ics/modbus.py:1-14`, `shared/ics/twin_modbus.py:1-16`. `git ls-files`에 LICENSE·SECURITY.md·CHANGELOG.md 존재 |

**D8이 이 저장소 문서 문제의 대표 사례다** — 갭 분석 문서가 스스로 갭이 되었다.

---

## 3. 구현되어 있으나 어떤 문서에도 없는 기능

`git grep -il <name> -- '*.md'` = 0건인 것만 올린다.

| # | 구현 | 위치 | 문서 |
|---|---|---|---|
| U1 | 초보자 방어 러너 | `scripts/beginner_defense.py`, `tests/unit/test_beginner_defense.py:51` | **0건** (Makefile `beginner-defense` 타깃만 존재, `Makefile:15`) |
| U2 | 훈련환경 오케스트레이터 | `scripts/training_environment.py`, `tests/attack_defense/test_training_environment.py` | **0건** |
| U3 | START HERE 랜딩 | `dashboards/start-here/index.html` (333 LOC) | **0건** |
| U4 | 단일 진입 CLI | `./training` (루트 bash 스크립트) | README 외 전용 문서 0건 |

부분 문서화(코드는 있으나 설명이 1건 이하):
- `services/siem/detection/noise_generator.py` — 배경 트래픽 생성기. **`docker-compose.yml:99`에서
  `SIEM_NOISE_ENABLED=false`로 기본 비활성**. 탐지 훈련의 전제가 기본값에서 꺼져 있다(B축 이관).
- `services/attack_defense/{network_policy.py,rate_limit.py,evidence.py}` — 각 문서 1건 이하.

---

## 4. 즉시 확인된 구조적 사실 (PHASE 2 입력)

칭찬은 한 줄로 끝낸다: **Modbus/TCP는 진짜다** — `shared/ics/modbus.py`가 FC1/3/4/5/6/16과
MBAP 프레이밍·예외응답 01/02/03을 직접 구현했고(`shared/ics/modbus.py:6-9`),
`shared/ics/process_sim.py`가 slew-rate 기반 연속 물리를 돌린다. 외부 라이브러리 없이
자체 구현이다(`requirements.txt`에 `pymodbus` 없음 — 12개 패키지 전부 확인).

나머지는 결함 후보다:

1. **프로토콜 리얼리즘이 Modbus 한 종에 집중.** DNP3·IEC 61850·OPC-UA·S7·IEC 104는 전부
   합성 로그이거나 부재. 위성(`ground_station`)은 웹 취약점 세트다. → B축
2. **테스트 편중.** 백엔드 테스트 5,288 LOC 중 2,959(56%)가 `services/attack_defense` 전용.
   `event_collector`·`scoring_engine`·`config_service`·`range_control`·`instructor_api`·
   `ground_station`·`defense_network`·`patch_console`·`noc_monitor`에 **전용 테스트 파일이 없다**.
   채점 파이프라인 본체(`services/scoring_engine/main.py`, 357 LOC)가 무테스트다. → C·J축
3. **프런트 테스트는 livefire에만.** redportal·blueportal·siem·control-tower 테스트 0.
   `dashboards/control-tower/index.html`은 483줄 단일 HTML로 빌드·타입체크 대상 밖. → J축
4. **문서 동결.** 기획 문서 31개가 2026-07-24 이후 무갱신. 구현은 08-14까지 진행. → 문서 신뢰 불가
5. **점수 조정 경로 존재.** `services/scoring_engine/main.py:265` `adjust_score`,
   `:298` `reconcile`, `:340` `admin_reset`. 감사 로그·권한 실효성은 미검증. → C축
6. **CI에 보안 스캔 없음.** `.github/workflows/ci.yml` 128줄에 unit/challenges/dashboard/
   integration 4잡만. trivy·semgrep·bandit·pip-audit·SBOM 전무(`ci.yml:22-128`). 의도적
   취약 서비스를 다수 포함한 저장소에서 특히 문제. → D·J축
7. **CI 통합 잡이 실제 docker 스택을 기동**(`ci.yml:77-128`) — 격리 검증이 여기 있는지가
   D축의 핵심. `infra/ci/isolation_test.py`(존재 확인) 내용 미독. → D축

---

## 5. UNVERIFIED (PHASE 1 시점)

컨테이너 미기동 지시에 따라 아래는 정적으로만 판정 가능하거나 판정 불가다.

| 항목 | 확인에 필요한 것 |
|---|---|
| egress 차단 실효성 | `infra/hardening/docker-compose.hardening.yml`·compose 네트워크 정의 정독(정적으로 가능, PHASE 2 D축에서 수행) |
| Modbus 502 실제 응답 | 스택 기동 필요 → **기동 금지이므로 영구 UNVERIFIED**. 대안: `infra/ci/modbus_probe.py`와 CI 로그가 증거가 되는지 확인 |
| 공격→로그→대시보드 E2E 지연 | 런타임 측정 필요 → 영구 UNVERIFIED. 대안: 폴링 주기 상수를 코드에서 추출해 이론 상한 산출 |
| 동시 팀 수 한계 | 실측 부재. `loadtest/k6/*.js` 3종·`loadtest/sse_loadtest.py` 존재하나 **결과 기록 파일 없음** |
| 대시보드 프로덕션 서빙 경로 | `infra/gateway/nginx.conf`·`entrypoint.sh` 정독 필요 |
| 채점 서버의 참가자망 도달성 | compose 네트워크 attach 관계 전수 추적 필요 |

---

## PHASE 1 종료

PHASE 2(10축 심층 감사) 진행 승인을 요청한다. 진행 시 아래를 전제로 한다:

- 컨테이너 기동 없음 → B축(폐루프 물리)·G축(E2E 지연)·F축(동시성)은 코드 상수·CI 로그
  기반 정적 추론으로 대체하고, 측정이 필요한 항목은 `UNVERIFIED`로 명시 분류한다.
- 감사 브리핑의 "Splunk 기준"은 자체 SIEM(`services/siem/`) 기준으로 치환해 수행한다.
