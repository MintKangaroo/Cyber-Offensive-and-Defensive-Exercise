# B0 공통 계약 (Contracts) + 핵심 실행 코드

> Cyber Range 전체 시스템의 **단일 진실원(single source of truth)** + 실제 동작 코드 일부.
> B0(Architect)가 소유하며, 다른 모든 에이전트는 이 스키마/인터페이스에 의존한다.
> 변경은 B0만 승인. 필드 추가는 하위호환(옵셔널+기본값), 제거/의미변경은 major 버전업.

## 구성

| 경로 | 내용 |
|---|---|
| `shared/event_schema.py` | Live Fire 이벤트(트윈/수집/점수/시나리오 공용), 점수표 |
| `shared/sse_bus.py` | **SSE 상황판 허브(P0-4)**: 토픽 pub/sub, Last-Event-ID 리플레이, 역할·지연 가시성 |
| `services/challenge_portal/anticheat.py` | **공정성/안티치트(P1-5)**: 제출 rate-limit·lockout, 감사(sqlite), 플래그공유 탐지. 엔드포인트: /portal/anticheat/audit·/flagged |
| `services/incident/` | **Incident Case Management(P1)**: 알림→인시던트 승격·라이프사이클·타임라인·SLA·AAR. 포트 8095. 엔드포인트: /incidents/from-alert·/{id}/transition·/sla·/{id}/aar |
| `services/injects/` | **비기술 인젝트(P1-4)**: 미디어/경영/규제 인젝트 라이브러리·디스패치·인박스·마감·루브릭 채점. 포트 8096. 엔드포인트: /injects/library·/dispatch·/inbox·/{id}/respond·/{id}/score·/scoreboard |
| `services/observability/` | **플랫폼 관측성(P2-5)**: 전 서비스 /health 스크레이프 → Prometheus /metrics + JSON 요약. 포트 8097. 게이지: cr_service_up·scrape_ms·payload 카운터·cr_platform_services_up |
| `shared/siem_schema.py` | SIEM 정규화 이벤트(ECS-lite), severity 매핑 |
| `shared/storage_interface.py` | SIEM 저장소 추상클래스(SQLite/OpenSearch 교체) |
| `shared/api_contract.py` | 서비스 포트·엔드포인트·요청모델 명세 |
| `shared/challenge_schema.py` | 문제·시나리오 YAML 검증 모델 |
| `tests/test_contracts.py` | 계약 회귀 테스트 |
| `services/scenario_engine/loader.py` | 시나리오 YAML 로더(단일+크로스오버), Config Service 초기상태 주입 |
| `services/scenario_engine/runner.py` | stage 순서판정/chain_bonus, **크로스오버 phase 잠금해제+증거패키징** |
| `services/patch_console/` | **Ansible 패치 콘솔**: 화이트리스트 플레이북 실행, audit, Config Service 연동 |
| `services/noc_monitor/health_poller.py` | **Health Poller**: uptime/latency 계산, Recovery Watcher와 NOC이 공유 |
| `services/noc_monitor/api/main.py` | **NOC API**: /noc/status /noc/history /noc/ws |
| `services/core/recovery_watcher.py` | asset_recovered 최종 판정(compromise 이력 + patched + health 3연속) |
| `scenarios/single/*.yaml` | 단일 킬체인 시나리오 3종(위성/발전소/국방망) |
| `scenarios/crossover/*.yaml` | 크로스오버 시나리오 2종(웹→포렌식→탐지, 리버싱→Pwn→네트워크) |
| `infra/ci/secret_scan.py` | 실제 시크릿 유입 방지 스캐너(더미 허용리스트) |
| `infra/ci/isolation_test.py` | 트윈 네트워크 격리 회귀 테스트(egress차단/트윈간차단 검증) |
| `infra/hardening/docker-compose.hardening.yml` | cap_drop/read-only/리소스제한 오버레이 |
| `infra/deploy/checklist.py` | 배포 전 체크리스트 7항목 자동 실행 |

**주의**: 최상위 디렉토리명을 `platform/` → **`services/`** 로 변경했다(Python 표준 라이브러리의
`platform` 모듈과 이름이 충돌하는 문제를 뒤늦게 발견해 수정). 17번 문서(저장소 구조)에서
`platform/`으로 표기된 부분은 전부 `services/`로 읽는다.

## 누가 무엇을 import 하나

- **B1 트윈** → `event_schema`(emit_event)
- **B2 백엔드** → `event_schema`(점수표), `api_contract`
- **B3 시나리오** → `scenario_engine.loader`/`runner`, `challenge_schema`(Scenario)
- **B4 SIEM** → `siem_schema`, `storage_interface`, `api_contract`(SiemAPI)
- **B5 대시보드** → `api_contract`(포트/엔드포인트), 이벤트/점수 타입
- **B6 안전/인프라** → `infra/ci/*`, `infra/hardening/*`, `infra/deploy/checklist.py`
- **콘텐츠 C0~C6** → `challenge_schema`(Challenge), `api_contract`(GradeResult)

## 실행 (pydantic 필요)

```bash
pip install pydantic pyyaml
python tests/test_contracts.py                        # 계약 회귀 테스트
python infra/ci/secret_scan.py --path .                # 시크릿 스캔
python infra/ci/isolation_test.py --skip-if-no-docker  # 격리 테스트(Docker 필요, 없으면 skip)
python infra/deploy/checklist.py --repo-root .          # 배포 전 체크리스트 전체

# Ansible 패치 콘솔
pip install ansible fastapi uvicorn httpx
uvicorn services.patch_console.api.main:app --port 8060

# NOC 모니터링
pip install fastapi uvicorn httpx websockets
uvicorn services.noc_monitor.api.main:app --port 8070
```

**참고**: 개발 샌드박스에 pydantic이 없어 전체 테스트를 직접 돌리진 못했지만,
문법 검증(`py_compile`)과 pydantic-비의존 순수 로직(결정론적 ID/점수표/
challenge id 정규식/phase 잠금해제 알고리즘/stage 순서강제)은 별도 시뮬레이션으로
전부 검증 완료. `secret_scan.py`와 `isolation_test.py`, `checklist.py`는 실제 실행까지
확인함(트윈 코드 스캔 통과, 가짜 시크릿 주입 시 정확히 탐지, 체크리스트 7항목 통과).

## scenario_engine 핵심 로직 요약

- **단일 시나리오**: `requires_stage`로 순서 강제(순서 위반 이벤트는 조용히 무시) →
  모든 stage 완료 + 순서대로 + 시간 내 → `chain_bonus` 적립.
- **크로스오버 시나리오**: 각 phase는 `locked_until: "phase_N_x.completed"`로 잠김.
  선행 phase 완료 시 `_propagate_unlocks()`가 다음 phase를 잠금해제.
  `emits_evidence: true`인 phase(예: Web 공격)는 진행 중 이벤트를 `evidence_bundle`에
  축적해, 다음 phase(포렌식)의 조사형 채점(`submit_objective`)이 실제 발생 이벤트를
  근거로 삼을 수 있게 한다.

## Recovery Watcher 3-조건 판정 (신규)

`asset_recovered`(+50)는 다음 세 조건을 **모두** 만족할 때만 발행된다:
1. **다운 이력**: NOC API가 Event Collector WS를 구독해 `asset_compromised`를
   `recovery_watcher.record_compromise()`로 기록.
2. **패치 확인**: Config Service에서 해당 vuln_id가 patched.
3. **health 3연속 정상**: Health Poller가 감지.

Health Poller는 NOC API와 Recovery Watcher가 **같은 인스턴스를 공유**한다(콜백이
인메모리이기 때문에 프로세스를 분리하면 안 됨 — 둘 다 `noc_monitor` 서비스 안에서 뜬다).

## Ansible 패치 콘솔 안전장치 (신규)

`whitelist.py`는 vuln_id → playbook을 **명시적 dict**로만 매핑한다(`f"patch_{vuln_id}.yml"`
같은 문자열 조합 금지 — 그렇게 하면 vuln_id에 경로탈출 문자열을 넣는 순간 패치 콘솔
자체가 새 취약점이 된다). 실제로 화이트리스트 밖 값과 경로탈출 문자열 둘 다 거부되는 것을
테스트로 확인했다.

## 기존 코드와의 관계

이미 구현된 `cyber-range/shared/event_schema.py`는 이 계약의 v1.0에 해당한다.
이 패키지는 v1.1로, 다음 필드가 추가됨(전부 하위호환):
- Event: `trace_id`, `matched_event_id`, `challenge_id`, `schema_version`
- EventType: `stage_completed`, `red_stealth_bonus`, `unmatched_detection`

B1이 트윈을 갱신할 때 이 확장 스키마로 교체하되, 기존 필드는 그대로 유지한다.

## 버전

- Event schema: 1.1.0
- SIEM schema: 1.0.0

