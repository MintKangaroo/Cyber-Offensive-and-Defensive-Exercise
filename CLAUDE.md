# CLAUDE.md — Cyber Range Platform 작업 지침

이 파일은 Claude(및 기여자)가 이 저장소에서 작업할 때의 절대 규칙·구조·검증 명령을 담는다.
문서가 코드와 어긋나면 **코드와 실측이 우선**한다(설계 시점 문서 `docs/01~31` 은 참고용).

## 절대 규칙
1. **실행해서 확인한다.** "될 것 같다" 금지. 모든 판정에 실행 명령과 출력 근거를 남긴다.
2. **실패를 숨기지 않는다.** 원인 → 수정 → 재실행.
3. **정확도 우선.** 검증되지 않은 것은 PASS 가 아니라 UNVERIFIED 로 적는다(허위 보증 금지 — 감사 S-1).
4. **메모리 제약.** 전체 스택(75+ 컨테이너)을 한 번에 올리지 않는다. `free -h` 확인 후 필요한
   서비스 묶음만 기동하고, 검증이 끝나면 내린다. OOM 위험이 보이면 멈추고 보고한다.
5. **결함 1건 = 브랜치 1개 + 회귀 테스트 1개 이상.** main 직접 푸시·태그 생성·강제 푸시는 승인 후에만.
   워크플로: feature 브랜치 → 커밋 → push → `gh pr create` → CI green → `gh pr merge --squash`.
6. **python3** 사용. 시크릿 값은 출력하지 않는다. 의도적 취약 챌린지/훈련 더미 시크릿은
   `# training-only` 마커로 secret-scan allowlist 처리.
7. **시크릿은 fail-closed.** 운영(prod) 시크릿은 `docker-compose.prod.yml` 이 `:?` 로 강제.
   로컬은 `.env`(`./scripts/gen_secrets.sh`), dev 우회는 `RBAC_ALLOW_INSECURE_DEV=true` 명시 opt-in.

## 저장소 구조(요지)
- `services/` — 백엔드 서비스. 핵심: `attack_defense`(A/D 게임 엔진), `event_collector`(이벤트 원장),
  `scoring_engine`(채점), `siem/`(자체 SIEM·탐지엔진), `edr/`, `aar_report`(사후분석·PDF),
  `scenario_engine`, `range_control`(안전·리셋), `challenge_portal`, `incident`, `injects`,
  트윈들(`power_plant`·`ground_station`·`refinery_plant`·`smart_factory`·`water_utility` 등),
  `cloud_native`, `traffic_generator`.
- `shared/` — 공용 계약·로직: `event_schema.py`·`event_client.py`·`sse_bus.py`·`rbac.py`·
  `service_auth.py`·`safe_probe.py`·`siem_access_log.py`·`ics/`(실 프로토콜 인코더)·
  `space/ccsds.py`·`assessment.py`·`nice_framework.py`·`injects_campaign.py`.
- `challenges/<cat>/<ID>/` — CTF 챌린지(challenge.yaml·deploy/·grader/·solution/). 9개 카테고리.
- `dashboards/` — 프런트(React/정적): livefire·siem·edr·blueportal·redportal·control-tower·
  competition·start-here 등. 공유 디자인시스템 `dashboards/shared`.
- `infra/` — hardening 오버레이·게이트웨이 conf·CI 스크립트(isolation_test·secret_scan)·challenge_qa.
- `scripts/` — 운영/검증: `training_environment.py`·`bootstrap_attack_defense_demo.py`·
  `beginner_defense.py`·`smoke_test.sh`·`validate_challenges.sh`·`rehearsal/`(무인 리허설).
- `loadtest/` — k6 부하·`soak/`(장시간 소크). `audit/` — 감사·검증 산출물(00~103).
- `docker-compose.yml`(base) + `infra/hardening/docker-compose.hardening.yml`(리소스/rootfs 하드닝,
  모든 기동 경로가 함께 로드) + `docker-compose.prod.yml`(운영·시크릿 fail-fast).

## 검증 명령(실측 기준)
```bash
# 백엔드 유닛+계약 테스트(도커 불필요). 로컬 752 passed / 6 skipped(6=PostgreSQL HA, 별도 DB에서 통과).
python3 -m pytest tests/ -q

# 챌린지 전수 검증(스키마 + 아티팩트/탐지 게이트). 130/130 통과.
bash scripts/validate_challenges.sh

# 무인 리허설(Live Fire + A/D 2라운드). 서브셋 기동 → 완주 검증 → 결과 JSON.
#   깨끗한 플래그로 시작하려면 먼저 `make attack-defense-reset`.
make rehearsal          # 끝나면 `make rehearsal-down`

# 격리 회귀(팀 egress·DB/registry 도달불가) — 스택 기동 후.
python3 infra/ci/isolation_test.py

# 8h 정식 소크(장시간). 결과: loadtest/soak/results/soak_report.json
SOAK_DURATION_SEC=28800 bash loadtest/soak/run_soak.sh

# 시크릿 스캔.
python3 infra/ci/secret_scan.py
```

## CI (`.github/workflows/ci.yml`, 13 잡)
unit(+postgres)·service-scope-drill·clean-install·challenges·dashboard·integration(docker E2E)·
secret-scan·supply-chain(pip-audit/bandit/npm/trivy)·command-platform·specialist-dashboards(siem/
edr/blueportal/redportal). 스케줄: loadtest(nightly)·saturation(weekly).

## 도커 운영 주의(샌드박스)
- 서비스 정상상태 RSS ~50–80MiB(mem_limit 512m 은 여유). **다중 이미지 동시 `--build` 시 스파이크로
  일시 OOM** 가능 → 사전 빌드 후 `--no-build` 기동이 안전.
- 이벤트/채점/트윈 등은 `docker compose -f docker-compose.yml -f infra/hardening/docker-compose.hardening.yml`
  로 기동(Makefile `COMPOSE` 변수). `docker compose down` 로 정리(볼륨까지 `down -v`).
- 트윈 서비스키 ≠ container_name(예: `power_plant`→`pp_twin`). A/D 팀 서비스는 internal 망 격리 +
  `ad_target_gateway`(9101~9303) 로만 host 발행.
- 스테일 매치/대용량 볼륨은 검증을 오염시킨다 — A/D 는 `make attack-defense-reset`, event_collector
  events.db 가 크면(소크 잔여) `/replay/events` 무한 fetchall 이 OOM(→ audit/102 R-1, 백로그).

## 문서 신뢰도
- 권위: 코드·테스트·`audit/100~103`·이 파일·README(실측 반영본).
- 참고(설계 시점, 코드와 괴리 가능): `docs/01~31`, `HANDOFF.md`, `docs/NEXTGEN_*`.
