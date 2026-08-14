# E축 감사 — 프로비저닝·재현성

감사 방식: 정적 분석 전용(도커/make/스크립트 미실행). 모든 판정에 `경로:라인` 근거.
대상 커밋: 작업트리 HEAD(clean), 2026-08-14.

---

## 1. 요약 판정 테이블

| # | 항목 | 판정 | 근거 (path:line) | 실전 영향 |
|---|---|---|---|---|
| E1 | 0에서 전체 재구축 단일 명령 | **부분적으로만 존재** | `training:24-26` → `scripts/training_environment.py:215-243` | `./training up` 하나로 코어+A/D+대시보드까지 가지만, 호스트에 node/npm/python 의존성·`.env`·시크릿이 이미 갖춰져 있다는 전제. 신규 호스트에서는 실패한다(E3). |
| E2 | 호스트 파이썬 의존성 완결성 | **깨져 있다** | `scripts/bootstrap_attack_defense_demo.py:9`, `services/attack_defense/cli.py:11` 이 `dotenv` 임포트. `requirements.txt:1-12`·`requirements-dev.txt:1-4` 에 python-dotenv **없음** | `pip install -r requirements.txt` 만 한 clean 호스트에서 `./training up` 이 3단계(`bootstrap`)에서 `ModuleNotFoundError: dotenv` 로 죽고, 실패 핸들러가 스택 전체를 내린다(`training_environment.py:271-276`). `make beginner-defense`, `make attack-defense-runtime-work` 도 동일하게 죽는다. |
| E3 | 대시보드 프로덕션 서빙 경로 | **dev/prod 이원화, dev는 호스트 프로세스** | 대시보드 6종 Dockerfile 0개(`find . -name Dockerfile` 결과에 `dashboards/` 없음); dev는 `training_environment.py:165-169` 의 호스트 `python -m http.server`; prod만 `infra/gateway/Dockerfile:1-35` | dev 경로에서 대시보드는 컨테이너가 아니라 호스트 PID다. 호스트 재부팅/SSH 세션 종료 시 대시보드만 죽고 docker는 살아 있는 반쪽 상태가 된다. `restart:` 정책 적용 불가. |
| E4 | prod gateway의 커버리지 | **START HERE·A/D 누락** | `infra/gateway/Dockerfile:23-30` 이 ops/red/blue/siem/edr/control 만 복사. `dashboards/start-here` 미포함. `infra/gateway/nginx.conf:46-59` 에 attack_defense(8100) 프록시 **없음** | prod(`-f docker-compose.prod.yml`)로 띄우면 초보자 단일 진입점(5179)과 Attack/Defense 게임 API가 게이트웨이 뒤에서 사라진다. 문서가 안내하는 훈련 동선이 prod에서 성립하지 않는다. |
| E5 | 라운드 리셋 오케스트레이션 범위 | **4개 서비스만 리셋** | `services/range_control/main.py:43-48` (event_collector, scoring_engine, config_service, challenge_portal) | siem_api·edr_backend·incident·injects·attack_defense 는 리셋 대상이 아니다. `services/incident/main.py:261`, `services/injects/main.py:292` 에 `/admin/reset` 이 **구현돼 있는데도 호출되지 않는다**. 라운드 2 시작 시 라운드 1의 EDR/SIEM 알림·인시던트 티켓이 그대로 남아 Blue 채점이 오염된다. |
| E6 | 스냅샷/복원 | **복원 경로 없음** | `range_control/main.py:206-213` 스냅샷 = `{events, patched_vulns}` 카운터 2개(`:85-89`). restore 엔드포인트 부재(`grep "@app" main.py`에 restore 없음) | "스냅샷"은 드리프트 비교용 숫자일 뿐 상태 복원이 아니다. 라운드 중 환경이 망가지면 되돌릴 수단은 `docker compose down -v` 전면 초기화뿐 → 대회 중단. |
| E7 | 리셋 후 정상 복구 검증 | **존재한다(유일한 강점)** | `range_control/main.py:244-284` `verify-baseline`: 전 서비스 health + 이벤트 0 + safe_probe 전수 VULNERABLE | 다만 검증 대상이 E5의 4개 서비스 범위와 동일해, 리셋되지 않은 SIEM/EDR/A-D 상태는 "정상"으로 통과한다. |
| E8 | 팀 환경 개별 롤백 | **존재하나 데이터 볼륨은 롤백 안 됨 + 최초 패치 전에는 불가** | `services/attack_defense/api.py:822-836` → `patch_pipeline.py:590-596` (`previous_image_digest` 없으면 `no rollback target`), 실행부 `service_fabric.py:115-125` 는 `docker compose up -d --no-deps` | 이미지 교체만 하고 `ad_team_XX_notes_data` 볼륨은 유지된다. 공격자가 심은 웹셸/변조 데이터는 롤백 후에도 살아남는다. 아직 패치를 낸 적 없는 팀은 롤백 자체가 409로 거부된다. |
| E9 | 런타임 작업자(patch/rollback 실행 주체) | **데몬 없음 — 사람이 수동 실행** | `Makefile:25-26` `attack-defense-runtime-work` 는 1회성. 루프/데몬/크론 없음(`grep -rn "runtime-work"` 결과 Makefile·cli·beginner_defense 뿐) | 팀이 패치를 제출해도 교관이 호스트에서 명령을 치기 전까지 큐에 멈춰 있다. 라운드 롤백도 마찬가지. 3팀×2서비스 실전에서 교관 1명이 job마다 수동 개입해야 한다. |
| E10 | `latest` / 부동 태그 | **22곳 `:latest` + 전 이미지 digest 미고정** | `docker-compose.yml` 22개 `:latest`(3절 목록), `nginx:alpine`·`python:3.11-slim`·`node:20-alpine` 등 전부 태그만 | 같은 커밋을 한 달 뒤 배포하면 Suricata/Zeek 룰·엔진 버전이 달라져 탐지 결과가 바뀐다. 채점 재현성이 깨진다. |
| E11 | override 자동 병합 | **prod는 안전, dev는 오염됨** | `docker-compose.override.yml:1-9` 가 **git 추적됨**(`git ls-files` 확인) | prod는 명시적 `-f` 조합이라 override가 안 붙는다(prod.yml:2). 문제는 반대 방향: WSL 샌드박스 전용 포트 리맵(18090)이 모든 clean checkout에 딸려 간다. `ci.yml:69` 주석 "override 파일이 없어 edr는 8080에 뜨며"는 **사실이 아니다**(파일이 리포에 있으므로 CI 체크아웃에도 존재). |
| E12 | prod 시크릿 fail-fast | **2개만 강제, 나머지는 빈 값 통과** | `docker-compose.prod.yml:14`(INSTRUCTOR_TOKEN `:?`), `:36`(AUTH_JWT_SECRET `:?`). 반면 `:31,38,40,42,44,46,48,50,52` 는 `${AUTH_JWT_SECRET}` (기본값·검증 없음) | event_collector만 부팅 실패하고, scoring/edr/instructor 등은 빈 JWT 시크릿으로 조용히 뜬다. 서비스 간 토큰 검증이 서로 다른 시크릿을 보게 되는 반쪽 기동이 가능. |
| E13 | DB 마이그레이션 멱등성 | **정상** | `migrations/0001~0007` 전부 `CREATE TABLE/INDEX IF NOT EXISTS`, `ALTER` 0건. 러너가 `schema_migrations` 로 적용분 추적: `services/attack_defense/db.py:182-196`(SQLite), `:213-233`(PG) | 재실행 안전. E축에서 유일하게 견고한 부분. |
| E14 | 빌드 컨텍스트 위생 | **미흡** | `.dockerignore` 3줄(`*.db`, `**/events.db`)뿐. `node_modules/`·`.git/`·`.runtime/` 제외 없음. 서비스 ~30개가 `context: .`(`docker-compose.yml:24,35,52,…`) | `./training up` 이 호스트에 만든 `dashboards/*/node_modules` 가 매 빌드마다 데몬으로 전송되고, 캐시가 상시 무효화된다. `infra/gateway/Dockerfile:5,10,12,15,17` 은 그 디렉터리를 그대로 `COPY` 한다. |
| E15 | 프런트 의존성 고정 | **lock 있음(양호)** | `dashboards/{livefire,redportal,blueportal,siem}/package-lock.json`, `services/edr/console/package-lock.json` 존재. `training_environment.py:151` 이 lock 있으면 `npm ci` 선택. gateway는 항상 `npm ci` | package.json은 `^` 범위(`dashboards/livefire/package.json:14-31`)지만 lock이 있어 재현 가능. |
| E16 | 챌린지 아티팩트 결정성 | **아티팩트형 결정적 / 탐지형 비결정적** | 생성기 42개 중 HMAC 시드 방식: `challenges/ics/ICS-004/deploy/generate_artifact.py:22,30` 등. 반면 탐지형 13개는 `t0 = time.time()`(`challenges/detection/DET-000/deploy/generate_datasets.py:13,28`, `DET-002:15,29`, `DET-011:15,28`, `DET-012:15,28`) | 아티팩트형은 같은 team_id면 재생성해도 같은 플래그(재현 OK). 탐지형 데이터셋은 실행 시각이 섞여 바이트 단위 재현 불가 — 사후 이의제기 때 "그때 그 데이터셋"을 복원할 수 없다. |
| E17 | flag_determinism 게이트 미가동 | **CI에서 실행 안 됨** | `infra/challenge_qa/flag_determinism.py` 를 부르는 곳은 `infra/challenge_qa/run_all.py:136` 뿐. `scripts/validate_challenges.sh:21-32` 와 `.github/workflows/ci.yml:43-44` 는 schema/artifact/detection만 실행 | 재배포 후 플래그가 바뀌는 회귀를 CI가 잡지 못한다. |
| E18 | restart 정책 | **A/D 8개 서비스만** | `docker-compose.yml:20` 앵커 `x-ad-service-security` 를 쓰는 서비스 8곳 + `:315,381,400`. 서비스 75개 중 나머지 60여 개는 restart 정책 없음 | 호스트 재부팅/도커 데몬 재시작 후 레인지가 스스로 복귀하지 않는다. 대회 중 호스트 이슈 = 전면 수동 재기동. |
| E19 | healthcheck | **2개뿐** | `docker-compose.yml:309`, `:373` (둘 다 `ad-ha` 프로파일) | `docker compose up -d` 는 컨테이너 생성 직후 반환한다. 기본 프로파일에 `depends_on: condition: service_healthy` 를 쓸 근거가 없어 부팅 경합이 남는다. |

---

## 2. "0에서 재구축" 명령 체인 재구성

clean checkout(리포만 있고 `.env` 없음, 도커만 설치된 리눅스 호스트) 기준으로 실제 필요한 체인:

```
① git clone && cd cyber-range-platform
② cp .env.example .env                      ← 수동. 어떤 스크립트도 안 해준다
                                              (.env는 .gitignore:1, gen_secrets.sh:6이 없으면 exit 1)
③ ./scripts/gen_secrets.sh                  ← 수동. 12개 키를 채운다(gen_secrets.sh:20-31)
                                              AUTH_ADMIN_PASSWORD는 채우지 않는다(.env.example:21 vs gen_secrets.sh 목록)
④ (호스트에 node 20 + npm 설치)               ← 수동/문서화 없음. training_environment.py:151-158이 npm을 직접 호출,
                                              없으면 FileNotFoundError → 전체 롤백(:271-276)
⑤ pip install -r requirements.txt           ← 이것만으로는 부족. python-dotenv 누락(E2) → ⑥에서 실패
   pip install python-dotenv                ← 수동. 어떤 파일에도 적혀 있지 않다
⑥ ./training up
     ├ docker compose build attack_defense ad_team_01_notes ad_team_01_vault   (training_environment.py:216-218)
     ├ docker compose up -d                                                     (:220)  ← 75개 서비스 전부.
     │    Suricata/Zeek 사이드카 22개 포함(:774~1027) → Docker Hub에서 :latest pull 필요(인터넷 필수)
     ├ python -m scripts.bootstrap_attack_defense_demo                          (:222)
     │    ← dotenv 임포트(bootstrap:9). 매치/팀/서비스 생성은 409를 흡수해 멱등(bootstrap:51-53)
     │    ← 팀 계정 생성 실패는 조용히 warning만 반환(bootstrap:162-185) — up()은 이를 확인하지 않는다
     ├ start_dashboards()  npm ci → npm run build → python -m http.server ×7    (:147-193)
     └ wait_for_url ×7 (45초 타임아웃)                                            (:196-226)
⑦ (선택) bash scripts/smoke_test.sh          ← 수동
⑧ (선택) scripts/deploy_match.sh <id> <base> ← 매치별 트윈 셋. 수동, 교관 호스트 전용
```

프로덕션 경로는 별개다:

```
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d   (docker-compose.prod.yml:2)
```
- 이 경로에는 `./training up` 이 하는 **bootstrap이 없다**. 매치·팀·서비스·계정이 하나도 만들어지지 않는다 → 완전 수동.
- START HERE(5179)와 A/D API가 게이트웨이에 없다(E4).

### 수동 개입 지점 (총 7곳)
1. `.env` 생성 — 자동화 없음 (`gen_secrets.sh:6` 이 없으면 즉시 exit 1)
2. `gen_secrets.sh` 실행 — `./training` 이 호출하지 않음
3. node/npm 호스트 설치 — 사전 점검 코드 없음
4. `python-dotenv` 수동 설치 — 요구사항 파일에 누락(E2)
5. prod 경로의 매치/팀/계정 부트스트랩 전부
6. 패치·롤백 job마다 `make attack-defense-runtime-work` (E9)
7. 매치별 트윈 셋 `deploy_match.sh` / `teardown_match.sh`

---

## 3. `latest` / 부동 태그 전수 목록

**명시적 `:latest` — 22곳 (전부 `docker-compose.yml`)**

| 이미지 | 라인 |
|---|---|
| `jasonish/suricata:latest` | 774, 798, 821, 847, 871, 895, 919, 943, 967, 991, 1015 (11곳) |
| `zeek/zeek:latest` | 786, 810, 833, 859, 883, 907, 931, 955, 979, 1003, 1027 (11곳) |

**부동 태그(digest 미고정) — 전 이미지**

| 이미지 | 위치 |
|---|---|
| `nginx:alpine` | `docker-compose.yml:158, 532, 540, 548, 604, 612, 620, 628, 636, 644, 652, 660` / `infra/match/docker-compose.match.yml:52, 58, 64, 70, 76, 82, 88, 94, 100, 106, 112` / `infra/gateway/Dockerfile:21` |
| `postgres:17-alpine` | `docker-compose.yml:292` |
| `haproxy:3.1-alpine` | `docker-compose.yml:386` |
| `registry:2` | `docker-compose.yml:404` |
| `node:20-alpine` | `infra/gateway/Dockerfile:2` |
| `python:3.11-slim` | 서비스 Dockerfile 27개 + 챌린지 Dockerfile 13개 |
| `python:3.12-slim` | `services/attack_defense/Dockerfile:1`, `demo_services/file_vault/Dockerfile:1`, `demo_services/vulnerable_notes/Dockerfile:1` |

리포 전체에서 `@sha256:` 로 고정된 베이스 이미지는 **0건**.

**패키지 설치 고정 여부**

| 대상 | 판정 | 근거 |
|---|---|---|
| 서비스 python 의존성 | 고정 | `requirements.txt:2-12` 전부 `==` |
| 챌린지 python 의존성 | **미고정** | `challenges/web/WEB-000/deploy/Dockerfile:3` `pip install fastapi uvicorn`, `WEB-007:3`, `WEB-009:3`, `WEB-001:5`, `WEB-003:3`, `WEB-004:3`, `AI-000/deploy/Dockerfile:3`(`scikit-learn numpy`), `AI-007:3`, `ICS-001:3` — 전부 버전 없음 |
| apt | **미고정** | `services/power_plant/Dockerfile:5` `apt-get install -y iputils-ping`, `challenges/web/WEB-001/deploy/Dockerfile:3` |
| apk | **미고정** | `infra/gateway/Dockerfile:22` `apk add openssl` |
| npm | 고정(lock) | lock 5개 존재, `npm ci` 사용 |

즉, **파이썬 챌린지 이미지는 빌드 시점의 최신 FastAPI/scikit-learn을 받는다.** AI-000의 scikit-learn 버전이 바뀌면 모델 동작이 바뀌고 정답이 흔들린다.

---

## 4. 멱등성 위반 스크립트 목록

| 스크립트 | 재실행 시 무슨 일이 일어나는가 | 근거 |
|---|---|---|
| **`scripts/smoke_test.sh`** (가장 심각) | `set -u` 만 있고 `set -e` 없음(`:11`). 매 실행마다 config_service에 `SMOKE-VULN-<run_id>` 패치를 **영구히 켠다**(`:104-109`). 이 패치는 어디서도 지워지지 않는다. 결과: 스모크 1회 실행 후 `range_control` 의 `verify-baseline` 이 `all_vulnerable = probe["patched"] == 0` 조건에서 **영구 실패**(`services/range_control/main.py:264`). 훈련 전 스모크를 돌리면 훈련 시작 게이트가 막힌다. 또한 `smoke_team_$$` 팀 점수가 scoreboard에 계속 누적된다(`:128-145`). | `smoke_test.sh:11,104-115,128-145` |
| **`scripts/smoke_test.sh` (recovery 모드)** | `SMOKE_RECOVERY=1` 이면 `docker stop pp_twin` / `docker start pp_twin` 을 고정 sleep(8초/22초)으로 처리(`:189-190`). 느린 호스트에서는 start가 끝나기 전에 판정해 FAIL. 실패해도 컨테이너는 stop된 채 남을 수 있다(`set -e` 없음 → 스크립트는 계속 진행하고 종료). | `smoke_test.sh:180-205` |
| **`scripts/beginner_defense.py`** | 이미지 태그가 `beginner-<epoch>`(`:341` `tag = f"beginner-{int(time.time())}"`). 실행할 때마다 새 태그를 로컬 레지스트리에 push하고 삭제하지 않는다. `ad_registry`(`docker-compose.yml:404`)에 GC 설정 없음 → `ad_registry_data` 볼륨이 단조 증가. 또한 매 실행이 새 patch_submission 레코드를 만든다. | `beginner_defense.py:341`, `docker-compose.yml:404` |
| **`./training up` 재실행 (치명적 상호작용)** | `docker compose up -d`(`training_environment.py:220`)는 `ad_team_XX_*` 를 기본 이미지 `${AD_IMAGE_...:-cyber-range/ad-*:base}`(`docker-compose.yml:419,429,438,447,456,465`)로 재수렴시킨다. 반면 패치 배포는 `AD_IMAGE_*` 를 **그 명령 한 번에만 주입**한다(`service_fabric.py:115-119`). 즉 매치 도중 `./training up` 을 다시 치면 **모든 팀의 배포된 패치가 조용히 base로 되돌아간다.** DB의 patch status는 여전히 `deployed` 라 불일치가 감지되지 않는다. | `training_environment.py:220`, `service_fabric.py:115-125`, `docker-compose.yml:419-473` |
| **`./training up` 포트 점유 시** | `stop_dashboards()` 는 `cwd` 가 대시보드 디렉터리이고 cmdline에 vite/http.server가 있는 프로세스만 죽인다(`training_environment.py:88-100`). 무관한 프로세스가 5173~5180을 잡고 있으면 `http.server` 가 즉시 죽고 `wait_for_url` 이 45초 후 예외 → 예외 핸들러가 **docker 스택 전체를 down** 시킨다(`:271-276`). 대시보드 하나의 포트 충돌이 레인지 전체 종료로 번진다. | `training_environment.py:88-100, 196-212, 271-276` |
| `scripts/validate_challenges.sh` | `set -u` 만(`:12`). 개별 챌린지 실패를 `fail=1` 로 모아 계속 진행하는 의도된 설계라 재실행 자체는 안전하나, 생성 아티팩트를 `challenges/*/*/deploy/` 에 남긴다(.gitignore:16-28로 커밋은 막힘). | `validate_challenges.sh:12-33` |
| `scripts/deploy_match.sh` | `set -euo pipefail`(`:10`) + 네트워크 connect 실패를 `|| echo` 로 흡수(`:28,33`) → **멱등**. 단 `curl … /matches`(`:36-41`)가 기존 매치를 덮어쓴다(range_control `_save_matches`, `main.py:157`). | `deploy_match.sh:10,23,28,33` |
| `scripts/teardown_match.sh` | 전 구간 `|| true` → **멱등**. | `teardown_match.sh:12,15,18` |
| `scripts/gen_secrets.sh` | `^KEY=$` 인 빈 값만 채운다(`:10-13`) → **멱등**. 다만 키가 아예 없으면 "유지"로 조용히 넘어간다(`:15`) — .env를 손으로 편집해 키를 지우면 침묵 실패. | `gen_secrets.sh:8-18` |
| `infra/challenge_qa/flag_determinism.py` | `subprocess.run(["docker","compose","down","-v"])` 를 `check=` 없이 호출(`:51-52`) → down 실패해도 계속 진행해 이전 배포 위에 겹쳐 판정한다. | `flag_determinism.py:50-55` |

---

## 5. 결함 목록 (심각도 순)

### C1 (Critical) — clean 호스트에서 단일 명령이 실패한다: python-dotenv 미선언
`scripts/bootstrap_attack_defense_demo.py:9` 와 `services/attack_defense/cli.py:11` 이 `from dotenv import load_dotenv` 를 하는데, `requirements.txt:1-12` 와 `requirements-dev.txt:1-4` 어디에도 python-dotenv가 없다. `.github/workflows/ci.yml:39-44` 의 challenges 잡과 `:22-25` 의 unit 잡은 이 두 모듈을 임포트하지 않고, integration 잡(`:71-120`)은 `./training up` 대신 `docker compose up -d` 로 부분 스택만 띄우므로 **CI가 이 경로를 한 번도 통과하지 않는다.**
*시나리오*: 대회 전날 새 GCP VM에 배포. 문서대로 `pip install -r requirements.txt && ./training up`. docker 스택은 뜨고, 3단계에서 `ModuleNotFoundError: dotenv`. 예외 핸들러(`training_environment.py:271-276`)가 방금 띄운 스택을 전부 내린다. 원인이 로그 맨 끝에만 있어 추적에 시간이 걸린다.

### C2 (Critical) — 매치 도중 `./training up` 재실행이 전 팀 패치를 무음 롤백
근거는 4절 4행. 패치 배포는 `AD_IMAGE_<ID>` 환경변수를 단발 주입으로만 쓰고(`service_fabric.py:115-119`), compose 파일의 기본값은 `:base` 다(`docker-compose.yml:419-473`). DB의 patch status(`deployed`)와 실제 실행 이미지가 어긋나며, 이 불일치를 검출하는 코드가 없다.
*시나리오*: 라운드 3에서 대시보드가 먹통이 돼 교관이 "재시작"으로 `./training up` 을 다시 친다. 대시보드는 살아나고, 동시에 3팀 6개 서비스가 전부 취약 버전으로 되돌아간다. 스코어보드에는 여전히 "패치 완료"로 표시된다. Red 팀은 이미 막힌 줄 알았던 IDOR로 다시 플래그를 긁는다.

### C3 (High) — 라운드 리셋이 절반만 이루어진다
`range_control/main.py:43-48` 의 RESET_TARGETS는 4개뿐이다. SIEM·EDR·incident·injects·attack_defense는 빠져 있고, 그중 incident(`services/incident/main.py:261`)와 injects(`services/injects/main.py:292`)는 리셋 API가 **이미 구현돼 있는데 연결만 안 됐다**. A/D는 리셋/삭제 API 자체가 없다(`services/attack_defense/api.py` 의 `@app.post/@app.delete` 전수에 reset·delete 없음).
*시나리오*: 오전 매치 종료 후 오후 매치를 위해 `/ranges/range_1/reset` 실행. `verify-baseline` 이 ✅ 를 반환한다(검사 범위가 리셋 범위와 같으므로). 오후 매치 시작 5분 뒤 Blue 팀 SIEM에 오전 공격 알림 수백 건이 그대로 떠 있고, 오전 팀의 A/D 점수 원장이 살아 있다.

### C4 (High) — 스냅샷은 있지만 복원은 없다
`range_control/main.py:206-213` 이 저장하는 것은 `{"events": N, "patched_vulns": M}` 두 정수다(`:85-89`). `/restore` 류 엔드포인트는 존재하지 않는다. 팀 서비스 데이터 볼륨(`ad_team_XX_*_data`)의 스냅샷/복원도 없다. 롤백 경로는 이미지 교체뿐이며(`service_fabric.py:115-125`), 최초 패치 이전 팀은 `no rollback target` 으로 거부된다(`patch_pipeline.py:595-596`).
*시나리오*: Red가 team-02의 file_vault 데이터 볼륨에 백도어 파일을 심는다. 교관이 rollback_instance를 건다. 이미지는 base로 돌아가지만 볼륨은 그대로 마운트되고 백도어 파일이 남는다. 복원 수단은 `docker compose down -v`(전 팀 전 데이터 삭제)뿐이다.

### C5 (High) — 패치/롤백에 상주 워커가 없다
`Makefile:25-26` 의 `runtime-work` 는 job 하나를 claim하고 끝난다. 반복 실행하는 데몬·타이머·컨테이너가 리포 전체에 없다. `scripts/beginner_defense.py:224-256` 만이 자기 루프 안에서 이 명령을 반복 호출한다(최대 12회, `:370` `--max-iterations` 기본값).
*시나리오*: 라운드 2에서 3팀이 동시에 패치를 제출. 교관이 다른 사고를 처리하는 30분 동안 세 팀 모두 `uploaded` 상태로 대기. 팀들은 "제출은 됐는데 왜 안 뜨냐"고 항의하고, 방어 점수 구간이 통째로 날아간다.

### C6 (High) — 채점에 쓰이는 IDS 이미지가 `:latest` 22곳
3절 표. Suricata/Zeek는 SIEM 이벤트의 원천이며 Blue 탐지 채점 입력이다. 이미지가 pull 시점마다 달라지면 같은 공격이 다른 알림을 만든다.
*시나리오*: 예선(3월)과 본선(6월)을 같은 커밋으로 운영. 본선 호스트가 새 Zeek를 받아 로그 필드명이 바뀌고, SIEM 파서가 일부 필드를 놓쳐 Blue 탐지율이 예선 대비 급락. 코드도 룰도 그대로라 원인 규명에 며칠이 걸린다.

### C7 (Medium) — prod 게이트웨이에 START HERE와 A/D가 없다
`infra/gateway/Dockerfile:23-30`, `infra/gateway/nginx.conf:38-59`. dev(호스트 http.server)와 prod(nginx)의 서빙 대상이 다르고, prod가 더 좁다.
*시나리오*: 개발 내내 `./training up` 으로 5179를 통해 훈련 동선을 검증. 실제 대회는 prod 프로파일로 배포. 참가자에게 준 START HERE URL이 404이고, Attack/Defense 제출 API도 게이트웨이 뒤에서 라우팅되지 않는다.

### C8 (Medium) — 샌드박스 전용 override가 리포에 커밋돼 있고, CI 주석은 이를 부정한다
`docker-compose.override.yml` 은 git 추적 대상이며 내용은 WSL 로컬 사정(code-server 8080 점유) 전용이다(`:1-9`). `.github/workflows/ci.yml:69` 주석은 "override 파일이 없어 edr는 8080에 뜨며"라고 적었지만 체크아웃에 파일이 존재하므로 CI에서도 edr_backend는 18090으로 게시된다. `smoke_test.sh:30-36` 의 포트 자동탐지가 이 불일치를 가려 아무도 눈치채지 못한다. `services/range_control/main.py:40` 은 아예 기본값을 `http://localhost:18090` 으로 하드코딩해 샌드박스 사정이 서비스 코드까지 침투했다.

### C9 (Medium) — prod 시크릿 fail-fast가 2개 변수에만 걸려 있다
`docker-compose.prod.yml:14, 36` 만 `:?`. 나머지 9곳(`:31,38,40,42,44,46,48,50,52`)은 빈 값을 그대로 주입한다. 부분 기동(일부는 실패, 일부는 빈 시크릿으로 정상 부팅)이 성립한다.

### C10 (Medium) — 재부팅 복귀 불가
서비스 75개 중 restart 정책이 있는 것은 A/D 계열 11개뿐(`docker-compose.yml:20,315,381,400`). 대시보드는 아예 컨테이너가 아니라 호스트 프로세스라 정책 적용 대상도 아니다(`training_environment.py:165-193`).
*시나리오*: 대회 이틀차 아침, 호스트가 야간 커널 업데이트로 재부팅됐다. 코어 서비스 대부분이 죽어 있고 대시보드 7개도 사라져 있다. 복구 절차는 `./training up` 전체 재실행이며, 그것은 C2(패치 무음 롤백)를 유발한다.

### C11 (Medium) — 탐지형 챌린지 데이터셋이 시각 의존
`challenges/detection/DET-000/deploy/generate_datasets.py:13,28`, `DET-001:9,23`, `DET-002:15,29`, `DET-011:15,28`, `DET-012:15,28` 이 `time.time()` 을 기준 시각으로 쓴다. `random.seed(42)`(DET-000:27)로 내용은 고정돼도 타임스탬프는 매 생성마다 다르다. 산출물은 `.gitignore:16-28` 로 커밋 금지이므로 **채점에 쓰인 정확한 데이터셋을 사후에 재생성할 수 없다.**
*시나리오*: 참가자가 "우리 탐지 규칙이 왜 오탐 처리됐냐"고 이의 제기. 운영진이 데이터셋을 재생성하지만 타임스탬프가 달라 시간 윈도우 기반 규칙의 판정이 재현되지 않는다.

### C12 (Low) — 빌드 컨텍스트 위생
`.dockerignore` 가 3줄뿐이라 `node_modules/`·`.git/`·`.runtime/` 이 ~30개 서비스 빌드 컨텍스트에 매번 포함된다. `infra/gateway/Dockerfile:5,10,12,15,17` 은 `dashboards/*/` 를 통째로 COPY하므로 호스트 `npm install` 결과물이 이미지 레이어 캐시를 상시 무효화한다.

### C13 (Low) — flag_determinism 게이트가 CI에 없다
E17 참조. 42개 아티팩트 생성기의 결정성을 지키는 유일한 검사가 `run_all.py:136` 경유로만 존재하며 `validate_challenges.sh`·CI 어디서도 호출되지 않는다.

---

## 6. UNVERIFIED

| 항목 | 왜 미확인 | 확인 방법 |
|---|---|---|
| 리셋/teardown 실소요 시간 | 스크립트 실행 금지. 코드에 시간 예산·타임아웃 선언 없음(`teardown_match.sh` 전체, `range_control/main.py:216-226` 은 서비스당 timeout=6초만) | `time scripts/teardown_match.sh match_a` 및 `time curl -X POST /ranges/range_1/reset` 을 3회 측정 |
| `docker compose up -d` 실제 부팅 시간과 성공률 | 75개 서비스, healthcheck 2개뿐이라 정적으로 예측 불가 | clean 호스트에서 `time ./training up` 3회, 실패율 기록 |
| Suricata/Zeek `:latest` 가 현재 어떤 버전으로 해석되는가 | 이미지 pull 금지 | `docker image inspect jasonish/suricata:latest --format '{{.RepoDigests}}'` |
| `docker compose up -d` 가 22개 IDS 사이드카를 실제로 기동시키는지 (profiles 미지정이므로 기동될 것으로 판정했으나 `network_mode: service:*` 의존 순서 문제 가능) | 실행 금지 | `docker compose config --services | wc -l` 과 `docker compose ps` 비교 |
| `verify-baseline` 의 `safe_probe.run()` 이 컨테이너 내부에서 localhost 포트로 트윈에 도달하는지 (`range_control/main.py:14` 주석은 "호스트 사이드 실행 권장"이라 적혀 있으나 compose는 컨테이너로 띄운다) | 네트워크 실측 필요 | `docker exec range_control curl -s localhost:8001/health` |
| 대시보드 빌드가 node 20 이외 버전에서 성공하는지 (`vite ^7.3.6`, `dashboards/livefire/package.json:28`) | npm 실행 금지 | `node -v` 별로 `npm ci && npm run build` |
| `ad_registry` 의 이미지 GC 정책 | `docker-compose.yml:404` 에 `REGISTRY_STORAGE_DELETE_ENABLED` 등 환경변수 없음 → 기본값(삭제 비활성)으로 판정했으나 registry:2 기본 동작 미검증 | `docker exec ad_registry cat /etc/docker/registry/config.yml` |
