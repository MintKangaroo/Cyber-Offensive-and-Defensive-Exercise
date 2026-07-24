# 사용 가이드 (USAGE) — Cyber Range Platform

**최종 검증일**: 2026-07-13 (Docker 29.6.1 / Compose v5.3.1, WSL2)
**대상**: 이 리포를 로컬(WSL/Linux)에서 띄우고 검증하려는 사람.
전체 진행 맥락은 [`HANDOFF.md`](./HANDOFF.md) 참고.

---

## 0. 사전 준비 (한 번만)

```bash
cd /home/mintkangaroo/Project/Cyber_offensive_Defense_Project/cyber-range-platform

# 도커 확인
docker --version && docker compose version
docker ps                       # permission denied 나오면 아래 (a) 참고
```

### (a) `permission denied ... /var/run/docker.sock` 이 뜰 때
현재 유저가 `docker` 그룹에 없어서 소켓 접근이 막힌 경우다. 이 환경은 **passwordless sudo가 안 되므로**, 반드시 **본인 WSL 터미널(Claude 프롬프트 아님)** 에서 sudo 비밀번호를 직접 입력해 실행한다.

- **임시(세션 유지, 권장)**: `sudo chmod 666 /var/run/docker.sock`
  → 도커 데몬/WSL 재시작하면 원복됨(안전).
- **영구(재시작 필요)**: `sudo usermod -aG docker $USER` 후 `wsl --shutdown` → 재접속.

### (b) 파이썬 / 유틸 특이사항
- `python` 명령 없음 → **항상 `python3`**.
- `unzip` 없음 → `python3 -c "import zipfile; ..."` 로 대체.

---

## 1. 플랫폼 기동 (M1 코어 + 트윈)

> ⚠️ 이 샌드박스는 호스트 **8080/8081을 code-server가 점유**한다. 그래서
> `docker-compose.override.yml` 이 `edr_backend` 의 **호스트 포트만 18080** 으로 리맵한다
> (컨테이너 내부 포트 8080은 그대로 → 서비스간 통신 영향 없음).
> **정상/GCP 환경에서는 이 override 파일을 지우면** edr가 8080으로 뜬다.

> **RBAC(P3)**: 컨트롤플레인 인증은 역할별 토큰을 쓴다(`.env`의 `INSTRUCTOR_TOKEN`/`RED_TOKEN`/
> `BLUE_TOKEN`/`OBSERVER_TOKEN`). 교관 조작은 `instructor`, EDR 격리/kill 같은 방어 액션은
> `instructor` 또는 `blue`만 허용(무효 토큰 401 / 역할부족 403). 토큰을 하나도 설정하지 않으면
> 로컬 dev 모드로 관대 통과. 하위호환: `INSTRUCTOR_TOKEN`만 있으면 기존처럼 동작.

무거운 Suricata/Zeek 센서(외부 대용량 이미지, M5 SIEM용)를 빼고 **앱 서비스만** 기동:

```bash
docker compose up --build -d \
  event_collector scoring_engine config_service edr_backend siem_api \
  scenario_engine instructor_api aar_report noc_monitor \
  ground_station power_plant defense_network gs_gateway pp_gateway dn_gateway
```

> **트윈 네트워크 격리(로드맵 F ★★★)**: 트윈 3종은 `internal:true` 네트워크에만 있어
> 인터넷 egress와 트윈 간 lateral 이동이 차단된다(익스플로잇 유출 방지). 호스트 접근은
> `*_gateway`(nginx) 리버스 프록시를 통해서만 이뤄지므로 위 게이트웨이 3종을 반드시 함께 띄운다.
> 격리는 `SMOKE` §9 또는 `bash scripts/smoke_test.sh`로 자동 검증된다.

센서까지 전부 띄우려면(무겁고 오래 걸림):
```bash
docker compose up --build -d          # 17개 전체(센서 포함)
```

### 포트 맵 (호스트 → 서비스)

| 포트 | 서비스 | 비고 |
|------|--------|------|
| 8001 | ground_station (gs_twin) | 디지털 트윈 — **gs_gateway 경유**(트윈은 격리, 호스트 미노출) |
| 8002 | power_plant (pp_twin)    | 디지털 트윈 — **pp_gateway 경유** |
| 8003 | defense_network (dn_twin)| 디지털 트윈 — **dn_gateway 경유** |
| 8010 | event_collector | 이벤트 수집 |
| 8020 | scoring_engine  | 채점 |
| 8030 | config_service  | 패치 토글/설정 |
| 8040 | siem_api        | SIEM API (+ 1514/udp syslog) |
| 8045 | scenario_engine | 시나리오 |
| 8050 | instructor_api  | 강사 API |
| 8070 | noc_monitor     | 트윈 헬스 폴링 + 복구판정(asset_recovered) |
| 8090 | aar_report      | 사후 리포트 |
| **18080** | edr_backend | ⚠ 원래 8080, 로컬 포트충돌로 리맵 |

---

## 2. 정상 동작 검증

```bash
# 2-1. 헬스체크 (전부 HTTP 200 / {"status":"ok",...} 기대)
for p in 8001 8002 8003 8010 8020 8030 18080; do
  echo -n "$p -> "; curl -s localhost:$p/health; echo
done

# 2-2. 취약점 존재 확인 (14종 전부 VULNERABLE 기대)
python3 shared/safe_probe.py
#   GS-001~005 / PP-001~005 / DN-001~004

# 2-3. 통합 스모크 테스트 (전체 E2E 한 방 검증, 실패 시 exit 1)
bash scripts/smoke_test.sh
SMOKE_RECOVERY=1 bash scripts/smoke_test.sh   # 복구판정+MTTR E2E까지(트윈 재기동 ~35초)

# 2-4. 유닛 테스트 (docker 불필요, 수 초) — AAR/SIEM/EDR 로직 회귀 방지
pip install -r requirements-dev.txt
python3 -m pytest tests/ -v
```

> CI: `.github/workflows/ci.yml` 이 푸시/PR마다 위 유닛 테스트 + docker 통합 스모크를 자동 실행한다.

문제가 있으면: `docker compose logs <서비스명>` 으로 원인 확인 → 수정 → 재기동.

---

## 3. 챌린지 검증 (C-QA 파이프라인)

각 웹 챌린지는 **격리된 자체 compose(deploy/)** 로 배포되고, 아래 파이프라인이
schema → secret → safety → **docker 배포** → 정답솔브 → 빈제출거부 → 플래그결정성 → teardown
순으로 전부 실행된다. 통과 시 `QA_PASSED` 마커가 생성된다.

```bash
# 3-1. 풀 QA (docker 실제 배포/teardown 포함) — docker 필수
python3 infra/challenge_qa/run_all.py --challenge WEB-003
python3 infra/challenge_qa/run_all.py --challenge WEB-005   # hardened(RCE)
python3 infra/challenge_qa/run_all.py --challenge WEB-007

# 3-2. docker 없이 스키마/안전성만
python3 infra/challenge_qa/run_all.py --challenge WEB-003 --skip-docker

# 3-3. 익스플로잇+패치 기능검증 (uvicorn 기반, docker 불필요, 빠름)
#      6단계: 익스플로잇→플래그 / red채점 / 빈제출거부 / 결정성 / blue채점(패치판) / 재익스플로잇 차단
python3 infra/challenge_qa/functional_verify.py --all
python3 infra/challenge_qa/functional_verify.py WEB-003     # 개별
```

> **주의(패치 검증)**: `run_all.py` 는 `--patch-env` 를 안 주면 blue_verify(패치판 채점)를
> 건너뛴다. 패치까지 보려면 `functional_verify.py` 를 쓰거나 `--patch-env` 를 넘겨라.

---

## 4. 정지 / 정리

```bash
docker compose down            # 코어/트윈 정지 (볼륨 유지)
docker compose down -v         # 볼륨까지 제거

# 챌린지 잔여 컨테이너 확인/정리
docker ps --format '{{.Names}}' | grep -iE 'web00|deploy'
python3 infra/challenge_qa/teardown.py --challenge-dir challenges/web/WEB-005
```

---

## 5. 트러블슈팅 (실제 겪은 것들)

| 증상 | 원인 | 해결 |
|------|------|------|
| `bind ... 8080: address already in use` | 호스트 8080을 code-server가 점유 | `docker-compose.override.yml` 로 edr를 18080에 리맵(이미 적용됨) |
| `deploy_up: health check 실패` (WEB-005) | deploy compose가 `internal: true` 네트워크만 붙여 **호스트 포트 퍼블리시 불가** | 해당 챌린지 compose에서 `internal: true` 제거(egress 차단은 플랫폼 방화벽 계층에서). ✅ 수정됨 |
| `flag_determinism: Connection reset` | 재배포 직후 **health 대기 없이** exploit 실행 | `flag_determinism.py` 에 `/health` 대기 루프 추가. ✅ 수정됨 |
| `teardown: 잔여 컨테이너 발견` | 앞선 실패 QA가 컨테이너를 남김 | `docker compose down -v` 로 정리 후 재실행 |

---

## 6. 다음 마일스톤 & 팀 에이전트 사용 지침

M1까지(코어+트윈+웹 챌린지 3종) docker 검증 완료. 남은 것:

- **M2 (EDR)** / **M3 (시나리오)** / **M4 (EDR 콘솔)** / **M5 (SIEM+센서)** / **M6 (대시보드)**
- 관련 문서: `docs/21_build_environment_guide.md`, `docs/09_team_agents_roles.md`,
  `docs/25_cqa_pipeline_and_remaining_challenges_plan.md`.

### 팀 에이전트는 언제 쓰나
`docs/09` 의 역할 분리(B0 계약 → B1 트윈 / B2 코어 / B3 시나리오 / B4 SIEM / C 출제)는
**서로 다른 디렉토리를 병렬로 빌드**할 때 효과적이다.

- **순차 검증·디버깅**(예: 이 문서의 M1 2-B) → 단일 실행이 정답. 팀 에이전트 불필요.
- **M2~M6 신규 빌드** → 스코프를 디렉토리로 분리해 병렬화 적합. 예:
  "B2 역할로 `services/edr` + 코어만 건드려서 M2 진행" 처럼 **역할+디렉토리 스코프를 명시**해 지시.

> `~/.claude/settings.json` 에 `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` 설정됨.
> 실제 병렬 실행은 사용자가 명시적으로 지시할 때 서브에이전트로 띄운다(임의 생성 안 함).
