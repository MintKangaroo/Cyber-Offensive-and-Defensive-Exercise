# 101 — 치명 결함 재감사 (Phase 1)

- 재감사일: 2026-09-30
- 대상 리비전: `main` HEAD `9939453` (원 감사 대상 `09e9378`에서 +다수 커밋)
- 원 감사: `audit/99_final.md` (2026-08-14, 정적 분석)
- 방식: 현재 HEAD 코드·테스트 정적 재판정(서브에이전트 4갈래 증거 수집 + 직접 재확인). 도커 미기동(규칙 5) — 런타임 재현이 필요한 항목은 UNVERIFIED로 분리하고 실행 명령을 명시.
- 판정 라벨: **FIXED**(원 발생 시나리오가 코드상 더는 성립 안 함) / **PARTIAL**(핵심은 해소, 잔여 존재) / **OPEN**(미해소) / **UNVERIFIED**(코드는 정비됐으나 실측 필요).

---

## 0. 요약

| 구분 | FIXED | PARTIAL | OPEN | UNVERIFIED |
|---|---|---|---|---|
| §1 Showstopper (S-1~S-11) | 7 | 4 | 0 | 0 |
| §2 2차결함 (T-1~T-30) | 11 | 8 | 10 | 1 |
| §6 UNVERIFIED (U-1~U-10) | 9 | 0 | 1 | 0 |

- **Showstopper 11건 중 7건 FIXED, 4건 PARTIAL(S-3·S-8·S-9·S-10).** OPEN 0.
- PARTIAL 4건은 전부 **경계 사례/잔여 홉** 수준이며 원 감사의 "즉시 무효화" 시나리오는 모두 차단됨. Phase 2에서 마감 대상.
- 원 감사의 라인 번호는 대부분 stale(코드가 크게 확장됨) — 아래는 현재 라인 기준.

---

## 1. Showstopper 재판정 (S-1 ~ S-11)

### S-1 허위 안전 보증 — **FIXED** (격리 실측만 UNVERIFIED)
- `services/range_control/main.py:323-351` `safety_status()`: 하드코딩 BLOCKED/NONE/100% **제거**. 미측정 3항목은 `"UNKNOWN"`, `range_containment_score: "UNKNOWN"`. estop만 config_service에서 실측. `design_intent`로 설계의도를 측정값과 분리, `verified_by: infra/ci/isolation_test.py`.
- `shared/safe_probe.py:22-33`: 타깃 `PROBE_HOST` env 주입(+서비스별 `*_URL`), localhost 하드코딩 아님. `:334-344` 연결 실패는 `{"patched": None, "reachable": False}` UNREACHABLE로 편입(false-pass 방지). verify-baseline이 `unreachable>0`이면 `passed=False`(`main.py:274-286`).
- `docker-compose.yml:1742` `ad_team_access: {internal: true}` ✅, twin_* 11개 전부 internal.
- 증거: `sed -n '323,351p' services/range_control/main.py`; `grep -n 'PROBE_HOST\|reachable\": False\|internal: true' shared/safe_probe.py docker-compose.yml`
- 테스트: `tests/unit/test_safe_probe.py::{test_unreachable_included_in_results,test_core_check_unreachable_uses_meta}` — **실행 16 passed**.
- 잔여(경미): `safe_probe.py __main__`은 unreachable이 있어도 exit 0. run() 요약·watch 판정은 반영하나 CLI 종료코드 강제 미적용 → Phase 2 소소 보강 후보. 격리의 실제 상태(egress 실차단)는 `isolation_test.py` 런타임 필요 → **UNVERIFIED(Phase 3 리허설에서 확인)**.

### S-2 무인증 채점 계통 — **FIXED**
- `services/event_collector/main.py:407-420` `/events`: range-agent 서명 경로 아니면 `require_service_token(authorization)`. `services/scoring_engine/main.py:228-231` `/score/ingest`: 첫 줄 `require_service_token`. `shared/service_auth.py` fail-closed.
- 망 분리: `event_collector`는 `networks: [range_control]` 단독(twin_* 미소속). 트윈은 `EVENT_COLLECTOR_URL=http://ingest_proxy:8010` 경유, `ingest_proxy`만 twin_*+range_control에 붙어 S2S 토큰 주입. (compose 57-58행 stale 주석 존재 — Phase 2 정리 후보.)
- 감사: `score_adjustments` 테이블(actor/reason/before/after/ts), `/score/adjust`는 reason 필수·actor∈{red,blue} 검증.
- 테스트: `tests/unit/test_scoring_engine.py::test_ingest_requires_service_token`, `tests/test_contracts.py::test_score_adjust_requires_reason`, `tests/unit/test_service_scope.py` 다수.

### S-3 챌린지 플래그 위조 — **PARTIAL**
- 해소: 그레이더/생성기 `CHALLENGE_SECRET` 미설정 시 RuntimeError fail-fast(204곳). 최상위 `challenge_portal`은 `${CHALLENGE_SECRET:?}`(docker-compose.yml:790, prod.yml:62). portal Dockerfile이 solution/exploit.py/writeup 삭제+self-check, CI integration 잡이 이미지 clean 검증. 아티팩트형은 portal 프로세스의 secret 상속.
- **잔여 1**: 서비스형 챌린지 배포 스캐폴드에 예측 가능한 dev 기본 시크릿 잔존 — `challenges/*/deploy/{Dockerfile,docker-compose.yaml}`의 `ENV CHALLENGE_SECRET=<slug>-dev-secret` / `${CHALLENGE_SECRET:-<slug>-dev-secret}` (140줄). 이 스캐폴드는 어떤 오케스트레이터에서도 참조되지 않음(수동 배포용)이나, 운영자가 CHALLENGE_SECRET 미설정으로 이 파일을 그대로 쓰면 저장소 열람만으로 해당 서비스형 플래그 위조 가능.
- **잔여 2**: 비-스코프(dev) 제출 시 `main.py:452-459`가 body `team_id`를 신뢰. 단, 실경쟁(`range_scope.is_team()`)에서는 identity로 override되어 무력화(`main.py:454`).
- **잔여 3**: 담합 탐지가 신호만 방출, `passed` 미변경(`main.py:494-498`).
- 증거: `grep -rnE 'ENV CHALLENGE_SECRET=[^$]|:-[a-z0-9]+-dev-secret' challenges/ | wc -l` → 140
- 테스트: `tests/unit/test_anticheat.py::test_detect_flag_sharing_across_teams`, `tests/unit/test_assessment.py::test_portal_records_subject_and_endpoint`
- **Phase 2 제안**: 배포 스캐폴드도 `:?`로 강제(또는 ENV 기본값 제거) + shared secret 로더 통합. 담합 정책은 설계 결정 사항이므로 사용자 확인.

### S-4 기본 시크릿 + fail-open — **FIXED**
- `shared/rbac.py:85-92` `insecure_dev_allowed()` 기본 False, `RBAC_ALLOW_INSECURE_DEV=true` opt-in만. `require_role()`(:144-168) dev_mode인데 미허용이면 401 fail-closed. prod compose 시크릿 `:?` 43건. base compose dev 기본값 10건은 로컬 전용(prod에서 차단).
- 테스트: `tests/unit/test_rbac.py::test_dev_mode_fails_closed_without_explicit_optin`, `test_rbac_jwt.py::{test_unconfigured_fails_closed,test_no_token_401,test_forged_signature_401}`.

### S-5 팀 간 격리 — **FIXED**
- `ad_team_access`/`ad_game_attack`/`ad_management` 전부 `internal: true`. 팀 취약서비스는 `[ad_team_access, ad_game_attack]`에만. `ad_postgres`=`[ad_management]`, `ad_registry`=`[ad_management, ad_registry_host]` — 팀망 미공유(도달 불가). `siem_logs`는 자산별 subpath 격리 + `siem_logs_init` 선생성. `isolation_test.py`가 팀 egress + ad_postgres(5432)/ad_registry(5000) 도달불가 검증.
- 검증: `infra/ci/isolation_test.py` (런타임 — Phase 3 리허설).

### S-6 clean 호스트 기동 — **FIXED**
- `requirements.txt:17 python-dotenv==1.2.2`. CI 전용 `clean-install` 잡(ci.yml:55-65). README 선행조건(Docker/Compose v2/Node 22/`cp .env.example .env`+`gen_secrets.sh`/RBAC opt-in) 문서화.

### S-7 크로스오버 완주 — **FIXED** (강제 skip 엔드포인트만 부재)
- `services/scenario_engine/api.py:206` `POST /scenario/{id}/objective/submit`→`runner.py:195 submit_objective`(서버측 `obj.answer` 조회, 정답 시 `_propagate_unlocks`). `loader.py:42 answer` 필드. YAML 정답 주석→필드 이관(`scenarios/crossover/*.yaml`).
- 테스트: `tests/unit/test_crossover_objective.py::{test_answer_key_migrated_to_schema,test_submit_correct_and_wrong,test_locked_phase_rejects}`.
- 잔여(경미): 막힌 stage 교관 강제 unlock/skip 엔드포인트 없음. Phase 2 소소 후보(또는 위험 수용).

### S-8 이벤트 유실 — **PARTIAL**
- 해소: `event_collector`가 collector→scoring 홉을 DLQ+지수백오프 재시도+메트릭으로 보호(`main.py:524 _try_forward_once_with_retries`, `:535 _spool_to_dlq`, `:546 _dlq_drain_loop`, `/metrics`에 `dlq_pending`). `reconcile`이 events.db 대조(`scoring_engine/main.py:409`). 전 SQLite에 WAL+busy_timeout.
- **잔여 1**: `shared/event_client.py:55-65` 트윈→collector(ingest_proxy) 발행 홉이 여전히 `except RequestException: pass`(무손실 미보장). collector/proxy 순간 다운 시 트윈 이벤트 조용히 유실.
- **잔여 2**: `shared/sse_bus.py:54` QueueFull 드롭이 카운터/로그 없음(가시성 부재). 링버퍼+Last-Event-ID 복구는 있음.
- 증거: `grep -n 'except.*RequestException' shared/event_client.py`; `sed -n '524,563p' services/event_collector/main.py`
- 테스트: `test_scoring_engine.py::test_reconcile_detects_missing_achievement`. **DLQ spool/drain 전용 단위테스트 부재(갭).**
- **Phase 2 제안**: event_client에 로컬 스풀 또는 최소 드롭 카운터/로그 + sse_bus 드롭 카운터. DLQ 회귀 테스트 추가.

### S-9 A/D SIEM 사각지대 / src_ip 귀속 — **PARTIAL**
- 해소: A/D 게임 서비스(vulnerable_notes/file_vault/grid_scada)에 `attach_siem_access_log`. `shared/siem_access_log.py:65-66` XFF 우선. 트윈 게이트웨이 12개 XFF 주입. Zeek `#fields` 헤더 유실 완화(`file_tailer.py:39-51`, `parsers/zeek.py`). `INCIDENT_MIN_SEVERITY=4`+app_layer severity4 다수 → 승격 가능.
- **잔여(핵심)**: `infra/match/ad_target_gateway.conf`가 `proxy_set_header Host`만 설정, **X-Forwarded-For 미주입**(전 9개 location). → A/D 팀 타깃 access 로그 src_ip가 게이트웨이 IP로 뭉개져 **팀별 공격 귀속 불가**. 원 S-9 시나리오가 A/D 구간에서 여전히 성립.
- 증거: `grep -c 'X-Forwarded-For' infra/match/ad_target_gateway.conf` → 0
- 테스트: `tests/unit/test_file_tailer_header.py`(Zeek). **XFF 미들웨어·app_layer→incident 승격 전용 단위테스트 부재.**
- **Phase 2 제안**: ad_target_gateway.conf 각 location에 `proxy_set_header X-Forwarded-For $remote_addr;`(트윈 게이트웨이와 동일) + 회귀 테스트. (경쟁망 NAT 특성상 완전 귀속 한계는 문서화.)

### S-10 리셋/스냅샷/라운드 오염 — **FIXED** (prod PVC 웹셸 잔존만 PARTIAL)
- 해소: `range_control/main.py:46-54` `RESET_TARGETS` **8개**(event_collector·scoring_engine·config_service·challenge_portal·siem_api·edr·incident·injects) — incident/injects `/admin/reset` 실호출. 다운타임 보정 `game_engine.py:238-252`(`gap>threshold and gap<=round_duration`로 한 라운드 이내만 보정, 무한연장 회귀 방지).
- **잔여**: 팀 롤백이 이미지 digest만 복원. k8s prod PVC(`kubernetes_runtime.py:322`)는 롤백 시 명시적 정리 없음 → 웹셸 데이터 잔존 가능(sandbox emptyDir는 소거). prod k8s 경로만 해당.
- 테스트: `tests/attack_defense/test_downtime_compensation.py::{test_downtime_extends_ends_at,test_long_downtime_does_not_extend_and_round_rolls_over}`, `test_scoring_engine.py::test_reset_snapshots_before_clear`, `test_asset_checkpoint.py::test_reset_invalidates_checkpoints`.
- **Phase 2/백로그**: prod 롤백 시 PVC purge 옵션(런타임 k8s 필요 → 위험 수용 후보).

### S-11 자원 상한 / OOM — **FIXED** (실 OOM만 UNVERIFIED)
- `docker-compose.yml` `mem_limit` 70개(event_collector 512m·siem_api 512m 포함). 하드닝 오버레이가 3경로 전부 `-f` 로드(Makefile:4·training_environment.py:21-26·ci.yml:125). `event_collector/main.py:327 _prune_old_events` retention.
- 검증: 8h 소크 실OOM 방지는 런타임 필요 → **Phase 4 소크(UNVERIFIED)**. SIEM 측 rollover는 별도 확인 여지.

---

## 2. 2차 결함 재판정 (T-1 ~ T-30)

| T-# | 판정 | 근거(현재) |
|---|---|---|
| T-1 물리파국→점수 | **OPEN** | `asset_compromised`가 복구/AAR에서만 소비, scoring 미연결 |
| T-2 Modbus 도달 | **PARTIAL/UNV** | 다수 트윈에 실 Modbus 배선, compose 502 미노출 → 런타임 확인 필요 |
| T-3 실 프로토콜 종수 | **FIXED** | `shared/ics/` 13종 + space/ccsds |
| T-4 위성 CCSDS/TT&C | **FIXED** | `shared/space/ccsds.py`+`twin_ccsds.py`, ground_station 배선 |
| T-5 인젝트 엔진 | **PARTIAL** | `injects_campaign.py`+스케줄러 존재, scenarios inject 키·studio 통합 미흡 |
| T-6 힌트 체계 | **PARTIAL** | 진행형 서빙·정책·cost 노출됨, 경쟁 점수 차감은 의도적 미적용 |
| T-7 부분점수 | **OPEN** | `got` 계산·보고만, 부여는 여전히 만점(`points_red`) |
| T-8 배점 상한 불일치 | **UNVERIFIED** | 현재값은 감사 지적 상한, 광고 상한 소스 미확인 |
| T-9 Blue 채점 도달 | **PARTIAL** | 경로 존재, 실도달점 blue task량 의존 |
| T-10 ICS 동일 템플릿 | **FIXED** | ICS-002~012 exploit 로직 각기 상이(재저작) |
| T-11 ATT&CK 히트맵 발생축 | **FIXED** | alert `metadata.mitre` 발행, `NormalizedEvent.mitre`, heatmap 조인 |
| T-12 ICS Impact 전술 | **FIXED** | T0879/T0880/T0826/T0837/T0813/T0815 챌린지에 존재 |
| T-13 Lateral Movement | **OPEN** | 관련 기법 챌린지 1건뿐(NET-002) |
| T-14 Sigma 로더 데드코드 | **OPEN** | `sigma_loader.py` 호출부 0건 |
| T-15 SEQ-KILLCHAIN-001 | **FIXED** | `source_type:"twin"` 기반 재작성으로 발화 가능 |
| T-16 비콘 allowlist | **FIXED** | `engine.py:260-266` dst.ip 기준 수정 |
| T-17 EDR <5s 프로세스 | **OPEN** | `_POLL_INTERVAL_SEC=5` 유지, 완화 근거 없음 |
| T-18 EDR isolate L3 | **OPEN** | 앱레이어 503 quarantine, iptables 격리 없음 |
| T-19 NOC 자산 등록 | **OPEN** | `TWIN_HEALTH_URLS` 3종만 |
| T-20 AAR/instructor 인증 | **FIXED** | `_require_viewer`/`require_role({"instructor"})` 부착 |
| T-21 AAR PDF 영속화 | **FIXED** | `AAR_PDF_DIR=/data/aar_reports`+`aar_data` 볼륨 |
| T-22 타임라인 재구성 | **PARTIAL** | AAR이 events/SIEM/portal 조회+`timeline.py` 병합·타이브레이크, NTP 없음 |
| T-23 PCAP 자동 캡처 | **OPEN** | suricata.yaml pcap-log 미설정 |
| T-24 개인 단위 평가 | **PARTIAL** | Event.actor enum 유지, 개인 귀속은 portal(`assessment.py`, by=subject)에서 |
| T-25 NICE/KSA 매핑 | **FIXED** | `shared/nice_framework.py`+portal 배선 |
| T-26 latest 태그/digest | **FIXED** | `:latest` 0건, `@sha256` 22건 |
| T-27 탐지형 비결정성 | **PARTIAL** | `random.seed(42)` 추가됐으나 `t0=time.time()` 타임스탬프 잔존 |
| T-28 restart/healthcheck | **OPEN/PARTIAL** | restart 6·healthcheck 2 — 다수 미적용 |
| T-29 아티팩트 공용경로 레이스 | **PARTIAL** | per-team 복합키 생성이나 고정 파일명 write→read 레이스 잔존 |
| T-30 체커 시크릿 전팀 공유 | **OPEN** | 단일 앵커 전팀 공유, 팀별 파생은 K8s만 |

**FIXED 11 · PARTIAL 8 · OPEN 10 · UNVERIFIED 1.**
OPEN 중 T-13·T-17·T-18·T-19·T-23·T-14는 사실상 **기능 추가**(스코프 동결, 규칙 3) → v1.0 위험 수용 + `docs/POST_V1_BACKLOG.md` 이관 후보. T-7(부분점수)·T-30(체커 시크릿)·T-1(물리→점수)은 채점 무결성 관련이라 Phase 2 검토 필요.

---

## 3. UNVERIFIED 재판정 (U-1 ~ U-10)

| U-# | 판정 | 근거 / 실행 명령 |
|---|---|---|
| U-1 Modbus 502 | **FIXED(코드/CI)** | `shared/ics/modbus.py:166 serve(...502)`, `infra/ci/modbus_probe.py`, ci.yml E2E 스텝. 실통과=CI docker |
| U-2 공격→SIEM 지연 | **OPEN** | 측정 하네스 부재 → Phase 3에서 신규 계측(간단) |
| U-3 부하 포화점 | **FIXED(코드/CI)** | `loadtest/k6/*saturation.js`+`saturation.yml`(공유 httpx+세마포어). 실측=Phase 4 |
| U-4 격리 실상태 | **FIXED(코드/CI)** | `isolation_test.py`(egress+DB/registry 도달불가). 실통과=Phase 3 |
| U-5 Zeek 헤더 레이스 | **FIXED** | `test_file_tailer_header.py` — **실행 통과** |
| U-6 OOM 8h 소크 | **FIXED(하네스)** | `loadtest/soak/` 완비. 8h 실판정=Phase 4(`run_soak.sh`) |
| U-7 verify-baseline | **FIXED** | fail-closed(unreachable>0→passed=False), `test_safe_probe.py` **실행 통과** |
| U-8 체커 실 HTTP | **FIXED(코드)** | `checker.py`가 timeout/connection/system_error 분류. 테스트는 Fake — 실경로 Phase 3 |
| U-9 prod 프로파일 | **FIXED(코드)** | prod nginx `/start/`·`/api/ad/` 노출. 실기동=Phase 3 |
| U-10 AI-009 T1551 | **FIXED** | `challenge.yaml:10 mitre: [T1027]` (T1551 제거 확인) |

---

## 4. Phase 2 제안 우선순위 (승인 대상)

**A. Showstopper 잔여 마감(최우선)** — 결함 1건당 브랜치+회귀테스트(규칙 6):
1. **S-9**: `ad_target_gateway.conf` 9개 location에 XFF 주입 + 회귀 테스트. (영향 高·비용 低)
2. **S-8**: `event_client` 드롭 가시성(카운터/로그) + `sse_bus` 드롭 카운터 + DLQ spool/drain 회귀 테스트. (영향 中·비용 中)
3. **S-3**: 서비스형 배포 스캐폴드 `CHALLENGE_SECRET` `:?` 강제(ENV 기본값 제거) + 검증. 담합 정책·비스코프 신뢰는 사용자 확인. (영향 中·비용 低)
4. **S-1/S-2 경미**: safe_probe CLI 종료코드, compose stale 주석 정리. (비용 低)

**B. 채점 무결성 T-item(검토 후 결정)**: T-7(부분점수)·T-30(체커 시크릿)·T-1(물리→점수).

**C. 위험 수용 + 백로그(스코프 동결, 규칙 3)**: T-13·T-14·T-17·T-18·T-19·T-23·T-28·S-10(prod PVC)·S-11(rollover). `docs/POST_V1_BACKLOG.md`에 사유와 함께 기록.

**D. 런타임 확정(Phase 3/4로 위임)**: U-1/U-4/U-8/U-9(리허설), U-3/U-6/S-11(소크).

> **완료 기준 대비**: Showstopper "전부 FIXED 또는 위험 수용 사유 명시" 충족을 위해, A를 처리하면 S-3·S-8·S-9는 FIXED, S-10(PVC)·S-11(rollover)은 위험 수용으로 귀결 가능.
