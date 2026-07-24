# 인수인계 (HANDOFF) — Cyber Range Platform

**작성일**: 2026-07-13
**작성 위치**: `cyber-range-platform/HANDOFF.md`
**목적**: 새 세션에서 이어받을 수 있게 "어디까지 실제로 실행·검증했는지" 정리.

---

## 0. 이 프로젝트의 절대 규칙 (반드시 지킬 것)

사용자의 표준 요구사항 — 새 세션에서도 그대로 적용:

1. **"실제로 실행해서 확인해줘"** — 코드만 쓰고 "될 것 같습니다"로 끝내지 말 것.
2. **"안 되면 왜 안 됐는지 설명하고 고쳐줘"** — 실패를 숨기지 말고, 원인 설명 → 수정 → 재실행.
3. **"'될 것 같다'가 아니라 실제로 통과한 걸 보여줘"** — 명령어 실제 실행 결과(출력)를 첨부.
4. 작업 지목은 **문서 번호 + 마일스톤**으로 받는다. 예: "22번 문서 M5.2 진행해줘".
5. 역할 스코프 지정 시 준수. 예: "B2(Platform Backend Engineer) 역할로 services/core, services/config_service만 건드려줘".

---

## 1. 환경 특이사항 (중요 — 새 세션에서 헷갈리기 쉬움)

- **작업 루트**: `/home/mintkangaroo/Project/Cyber_offensive_Defense_Project/`
- **통합 리포**: `cyber-range-platform/` (M0에서 병합 완료. 이게 정본.)
- **플랫폼**: WSL2 (Linux). git 저장소 아님(`git init` 안 돼 있음).
- **`python` 명령 없음** → 반드시 **`python3`** 사용. (문서들은 `python` alias 가정하고 쓰여 있음.)
- **`unzip` 바이너리 없음** → `python3 -c "import zipfile; ..."` 로 대체.
- **passwordless sudo 없음** → `/etc/hosts` 수정 불가. 도커 호스트명 대신 env var로 우회했었음
  (`CONFIG_SERVICE_URL`/`EDR_BACKEND_URL`/`EVENT_COLLECTOR_URL=localhost`).
- **⚠️ 이 샌드박스에는 Docker가 없었음** → M1 검증을 **uvicorn 대체 방식**으로 했음.
  **사용자가 지금 Docker 설치 중.** 설치 후 첫 확인 명령:
  ```
  docker --version && docker compose version
  ```
  Docker 잡히면 아래 "2-B. Docker로 재검증 (설치 후 할 일)" 진행.
- **포트 충돌(샌드박스 한정)**: edr_backend가 쓰는 8080/8081은 code-server(pid 457)가 점유.
  샌드박스에서만 발생 — docker/GCP는 컨테이너별 netns라 충돌 없음. 검증 때 edr은 18080으로 띄웠음.

---

## 2. 완료된 작업 (전부 실제 실행·통과 확인함)

### M0 — 리포 병합 ✅ (실행 완료)
- `cyber-range/` + `cyber-range-contracts/` → `cyber-range-platform/` 로 17번 문서 구조대로 재배치.
- `platform/` → `services/` 로 통일 (파이썬 stdlib `platform` 충돌 회피).
- **import 경로 수정**: 트윈/collector의 `sys.path` 를 `.parent.parent` → `.parent.parent.parent`
  (repo root = shared/ 위치)로 수정. Dockerfile도 `COPY services/<n>/`, `WORKDIR /app/services/<n>`
  로 맞춰서 local·docker 양쪽에서 `.parent.parent.parent == /app` 성립하게 함.
- `shared/event_schema.py`: 두 버전 병합 + `session_trace_id()` staticmethod 추가.
- `requirements.txt`: 두 리포 union.
- `docker-compose.yml`: 17개 서비스 통합, 전부 `context: .`, `dockerfile: services/<n>/Dockerfile`.
- **실행 검증(전부 통과)**:
  - `pip install -r requirements.txt` → 성공
  - `python3 tests/test_contracts.py` → 8/8 통과
  - `python3 infra/ci/secret_scan.py --path .` → clean

### M1 — 코어 플랫폼 기동 ✅ (Docker 재검증까지 완료 — 2026-07-13)
- ~~Docker 없어서 uvicorn 대체 검증~~ → **Docker(29.6.1/Compose v5.3.1)로 실제 재검증 완료**.
  - 앱 서비스 11개 `docker compose up --build -d` → 트윈3 + 코어4 **7/7 health HTTP 200**
    (edr는 override로 18080. 8080은 code-server pid511 점유).
  - `python3 shared/safe_probe.py` → **14종 전부 VULNERABLE** (GS5/PP5/DN4).
- 신규 파일: `docker-compose.override.yml` — edr 호스트포트만 18080 리맵(`ports: !override`).
  정상/GCP 환경에선 이 파일 지우면 8080으로 뜸.
- Suricata/Zeek 센서 6종은 M5용 대용량 이미지라 M1 검증에선 제외하고 앱 11종만 띄움.

### 챌린지 3종 (WEB-003 / WEB-005 / WEB-007) ✅ (스키마 QA + 실제 익스플로잇까지 통과)
25번 문서 2절 "Web (C1)" 항목. WEB-002 를 템플릿으로, 12번 문서 형식.
- **WEB-003** (IDOR, medium, standalone): mission plan 소유자 검증 누락.
  4000~4004는 본인 소유, 4137(CLASSIFIED, owner=command)이 검증 없이 열람됨.
  동적 플래그 `flag{idor_mission_<hmac16>}`. 패치 `PATCH_WEB_003` → 403.
- **WEB-005** (pickle RCE, hard, hardened): `POST /api/historian/import` base64 pickle → RCE.
  정적 플래그 `flag{pickle_rce_<sha16>}` (/tmp/flag.txt). 패치 `PATCH_WEB_005` → json.loads.
  docker-compose에 cap_drop:[ALL]/read_only/mem_limit/tmpfs/internal 넣음(hardened safety_scan 통과용).
- **WEB-007** (upload bypass, medium): `POST /api/upload`, content_type만 신뢰 → .py 우회.
  동적 플래그 `flag{upload_bypass_<hmac16>}`. 패치 `PATCH_WEB_007` → 실제 확장자 화이트리스트.
- **검증 (전부 PASS)**:
  1. `run_all.py --challenge <ID> --skip-docker` → 3종 다 QA_PASSED 마커 생성.
  2. 추가로 **실제 익스플로잇 기능 검증** (docker 없이 uvicorn으로 앱 띄워 6단계):
     익스플로잇→플래그 획득 / red_grader 정답 통과 / 빈제출 거부 / 플래그 결정성 /
     blue_grader 패치판 통과 / 패치 후 재익스플로잇 차단. → **3종 전부 RESULT PASS**.
  - 검증 드라이버: `scratchpad/verify_challenge.py` (세션 스크래치패드. 아래 3절에 재현법).

### 기타 설정
- `~/.claude/settings.json` 에 `"env": { "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1" }` 설정함
  (팀 에이전트용, tmux와 함께 사용 예정). 린터가 `"effortLevel": "medium"` 추가한 상태.

---

## 3. 재현/재검증 명령어 모음

```bash
cd /home/mintkangaroo/Project/Cyber_offensive_Defense_Project/cyber-range-platform

# M0 계약 검증
python3 tests/test_contracts.py
python3 infra/ci/secret_scan.py --path .

# 챌린지 스키마/안전성 QA (docker 불필요)
python3 infra/challenge_qa/run_all.py --challenge WEB-003 --skip-docker
python3 infra/challenge_qa/run_all.py --challenge WEB-005 --skip-docker
python3 infra/challenge_qa/run_all.py --challenge WEB-007 --skip-docker

# 챌린지 실제 익스플로잇 기능 검증 (docker 불필요, uvicorn 사용)
# ★ 리포 영구 위치에 있음 (infra/challenge_qa/functional_verify.py):
python3 infra/challenge_qa/functional_verify.py --all        # 등록된 3종 전부
python3 infra/challenge_qa/functional_verify.py WEB-003      # 개별
#   동작: deploy/main.py 를 uvicorn(포트 8100 vuln / 8101 patched)으로 띄우고,
#   solution/exploit.py:solve(base,team) 로 플래그 획득,
#   grader/red_grader.py:grade_red / grader/blue_grader.py:grade_blue 로 채점.
#   VULN 모드: 익스플로잇 성공+red통과+빈제출거부+결정성 / PATCH 모드: blue통과+재익스플로잇 차단.
#   ⚠ grader/exploit 는 CHALLENGE_SECRET 을 "모듈 로드 시점"에 읽으므로,
#     드라이버는 반드시 env 를 grader load 이전에 세팅함(단일 프로세스 오염 방지).
```

---

## 2-B. Docker로 재검증 ✅ **완료 (2026-07-13)**

Docker 설치·검증 끝. 결과:
- **M1 전체 기동 OK**: 앱 11종 health 7/7, safe_probe 14/14 VULNERABLE.
- **챌린지 full QA 3종 전부 통과** (docker 실배포/teardown 포함):
  - WEB-003 → QA_PASSED (flag{idor_mission_ff0e616d110eaca7})
  - WEB-005 → QA_PASSED (flag{pickle_rce_b9ae51162e9340e7})
  - WEB-007 → QA_PASSED (flag{upload_bypass_05a7fd204ecb2d0f})
- **functional_verify --all → 3종 RESULT PASS** (익스플로잇+패치+재익스플로잇차단).
- **docker 켜야만 드러난 잠복버그 2건 발견·수정**:
  1. `infra/challenge_qa/flag_determinism.py`: 재배포 직후 health 대기 없이 exploit →
     ConnectionReset. `_wait_health()` 추가.
  2. `challenges/web/WEB-005/deploy/docker-compose.yaml`: `internal: true` 네트워크가
     호스트 포트 퍼블리시를 막아 챌린지 접속 불가 → `internal` 제거(egress 차단은
     플랫폼 방화벽 계층에서). safety_scan은 여전히 통과(cap_drop/read_only/mem_limit 유지).
- **소켓 권한**: passwordless sudo 없어서, 사용자가 본인 터미널에서
  `sudo chmod 666 /var/run/docker.sock` 실행 → 접근 가능해짐(임시, 재시작 시 원복).
- **사용 가이드 신규 작성**: `USAGE.md` (기동/검증/트러블슈팅/팀에이전트 지침).

<details><summary>(참고) 당시 재검증 명령</summary>

설치되면:

```bash
cd /home/mintkangaroo/Project/Cyber_offensive_Defense_Project/cyber-range-platform

# 0) 도커 확인
docker --version && docker compose version
# (docker 그룹 미포함이면 sudo 필요할 수 있음 — 사용자에게 확인 요청)

# 1) M1 전체 기동 (docker에선 8080 포트충돌 없음)
docker compose up --build -d
curl localhost:8001/health; curl localhost:8002/health; curl localhost:8003/health   # 트윈
curl localhost:8010/health; curl localhost:8020/health; curl localhost:8030/health; curl localhost:8080/health
python3 shared/safe_probe.py    # 14종 VULNERABLE 기대
# 문제 시: docker compose logs <서비스명> 으로 진단 → 수정 → 재기동

# 2) 챌린지 full QA (blue_verify.py 포함, docker 실제 배포/teardown까지)
python3 infra/challenge_qa/run_all.py --challenge WEB-003   # --skip-docker 빼면 full
python3 infra/challenge_qa/run_all.py --challenge WEB-005
python3 infra/challenge_qa/run_all.py --challenge WEB-007
```
※ `blue_verify.py` 가 내부적으로 `docker compose up -d --build` 실행함 → docker 필수.
   이전엔 docker 부재로 이 단계만 스킵했음.
</details>

---

### M2 — EDR 연동 검증 ✅ **완료 (2026-07-13, docker 실검증)**
doc21 M2의 3항목 + kill 워크플로우까지 라이브로 통과. edr는 18080(override).
- **#1 hosts online**: `curl localhost:18080/edr/hosts` → 트윈 3개 전부 `online`.
  트윈 3종 모두 `start_edr_agent()` 호출, 5초마다 psutil 스냅샷 전송 확인.
- **#2 커맨드인젝션 → EDR 알림** (PP-003 `/api/diagnostics/ping`, shell=True):
  - EDR-002(리버스쉘 cmdline): `python3 -c ...socket` 주입 → 탐지. fresh ts로 확인.
  - EDR-001(웹서버가 쉘 생성): `parent=uvicorn child=sh` → 탐지(pid 43/49/55).
  - ⚠ 주입 팁: PP-003은 `subprocess.run(..., timeout=3)`이라 인젝션 프로세스가 3초에 죽음.
    EDR-002는 `"127.0.0.1; python3 -c '...time.sleep(30)' >/dev/null 2>&1 &"` (pipe fd 해제 →
    subprocess 즉시 리턴 + python 30초 생존)로 결정적 탐지. EDR-001(단명 sh)은 sh 유지
    페이로드 `"127.0.0.1 && sleep 10"`를 2.5초 간격 6회 뿌려 스냅샷 창(5초) 커버.
- **#3 Isolate → 트윈 503**: `POST /edr/hosts/power_plant/isolate` → config_service quarantine →
  트윈 업무 엔드포인트 503. **단 `/health`는 설계상 격리 제외(계속 200)** — 검증은 반드시
  업무 엔드포인트(`/api/diagnostics/ping` 등)로 할 것. unisolate로 원복 200 확인.
- **(보너스) kill 워크플로우**: 악성 pid kill 요청 → 큐잉 → 에이전트가 실제 os.kill(SIGTERM) →
  `done`/pid 소멸/audit 기록. 안전장치: 서버 pid(1) kill은 "not flagged"로 거부, 이름이 아닌
  **server_pid로 보호**(python3 이름이어도 pid≠server_pid면 kill 진행).
- 재현 스크래치: 세션 scratchpad의 `pp003b.json`(EDR-002용)/`pp003c.json`(EDR-001용).

### M3 — 시나리오 엔진 검증 ✅ **완료 (2026-07-13, docker 실검증)**
doc21 M3: 시나리오 로드 + 단일 킬체인 순서 공격 → stage_completed + chain_bonus.
- **로드**: `/health`/`/scenario/list` → single 3(SAT-KILLCHAIN-01, SCADA-SABOTAGE-01,
  DEFENSE-EXFIL-01) + crossover 2 = 5개 로드 확인.
- **SAT-KILLCHAIN-01 완주**: GS-005→GS-002→GS-001→GS-003 순서 공격(ground_station 8001) →
  `completed_stages`가 [1]→[1,2]→[1,2,3]→[1,2,3,4], **chain_bonus=True**.
  event_collector에 stage_completed ×4 + red_objective_success(chain_bonus:50) 기록 확인.
- **순서 강제**: stage3(GS-001)을 stage1/2 없이 먼저 쏘면 `completed_stages=[]`(미인정),
  정상 순서 후 [1,2,3] — requires_stage 정상.
- **🐛 버그 발견·수정 (docker 실검증에서만 드러남)**: 트윈 emit_event는 `scenario_id="default"`로
  발행하는데(트윈은 활성 시나리오를 모름) scenario_engine의 이벤트 라우팅은 `scenario_id`로
  트래커를 찾아서(`_active_trackers.get(sid)`) **트윈 공격 이벤트가 트래커에 영영 안 갔음** →
  stage가 완료 불가였다. `services/scenario_engine/api.py`에 `_route_event()` 추가:
  scenario_id 정확 매칭 우선, "default" 이벤트는 **target_asset으로 single 트래커에 라우팅**
  (crossover는 멀티에셋이라 전달, 각 트래커가 stage match로 재필터). 재빌드 후 통과.
- **공격 요청 형태**(재현용): GS-005 `GET /api/debug/config` / GS-002 `POST /api/login
  {"username":"admin","password":"admin123"}` / GS-001 `GET /api/telemetry?sensor_id=' OR '1'='1`
  / GS-003 `GET /api/mission-plan/1`. 전부 `X-Team-Id` 헤더로 팀 구분.

### M4 — EDR 콘솔 프론트엔드 검증 ✅ **완료 (2026-07-13)**
doc21 M4: `npm install` → `npm run dev` → 콘솔에서 호스트/프로세스/알림 + Isolate/Kill.
Node v20.20.2 / npm 10.8.2. 백그라운드 세션이라 브라우저 시각확인 대신, 컴파일·서빙·
브라우저 데이터경로(CORS 포함)를 실제로 검증.
- **npm install** OK(99 패키지). **npm run build** → tsc 타입체크 + vite 번들(35 모듈→dist/) OK.
- **npm run dev** → `localhost:5173` 서빙, main.tsx TSX→JS 실시간 변환(200) 확인.
- **콘솔 데이터경로 시뮬(Origin: 5173 헤더)**: fetchHosts(3 online)+config/quarantine,
  fetchAlerts, fetchProcessTree(ground_station roots=[uvicorn]), Isolate/Unisolate POST →
  전부 ACAO 헤더 붙어 정상. Kill POST도 동일 CORS.
- **🐛 버그 2건 발견·수정 (실행 안 해봤으면 못 잡을 것)**:
  1. **`src/vite-env.d.ts` 누락** → `import.meta.env` 타입 없어 `npm run build`가 TS2339로
     실패(as-is 컴파일 불가). 표준 Vite 참조파일 추가(+ 커스텀 env 타입 선언).
  2. **edr_backend·config_service에 CORS 없음** → 브라우저(5173)의 크로스오리진 fetch가
     전부 차단돼 콘솔 UI가 아무것도 못 띄우고 버튼 무동작. 두 서비스 main.py에 CORSMiddleware
     인라인 추가(허용 origin은 `EDR_CONSOLE_ORIGINS` env로 재정의, 기본 vite dev origin들).
     ※ 두 Dockerfile이 `shared/`를 COPY 안 해서 공용 헬퍼 대신 인라인으로 넣음.
- **환경 특정(코드 아님)**: client.ts 기본 EDR base가 `localhost:8080`인데 이 샌드박스는 18080
  리맵 → console에 `.env.local`(VITE_EDR_BACKEND_URL=http://localhost:18080) 생성. 정상/GCP는
  이 파일 없이 기본값 사용. `.env.local`/`*.local`은 .gitignore에 추가함.
- **콘솔 실행법**: `cd services/edr/console && npm install && npm run dev` → localhost:5173.

### M5 — SIEM 코어 검증 ✅ **완료 (2026-07-13, docker 실검증)**
doc21 M5는 "코드 없음"이라 했지만 **실제로는 이미 전 구현**(ingestion/parsers/detection/
storage/api). 그래서 신규 빌드가 아니라 연동 검증 성격 → 단일 진행이 맞았음(서브에이전트 불요).
siem_api 8040, 규칙 18개(app10+net5+periodicity1+seq2. doc는 "20종"이라 문서-코드 불일치).
- **인제스천 2경로 검증**:
  - **트윈 access log**(공유볼륨 `siem_logs:/var/log/siem/{asset}_access.log` tail): GS 공격 →
    `/sources/health` twin:* green, `/search`에 정규화 이벤트 인덱싱.
  - **pfsense syslog UDP(1514)**: filterlog CSV 라인 전송 → 파싱 → 이벤트화.
  - (Suricata/Zeek 경로는 센서 사이드카 미기동이라 데이터 없음 = 정상. 센서 띄우면 활성.)
- **탐지 4종 kind 전부 발화 확인**: match(TWIN-SQLI-001, GS-001), threshold-network
  (FW-BLOCK-SPIKE-001, distinct dst.port≥5), threshold-twin(TWIN-IDOR-SCAN-001, distinct
  raw.endpoint≥3), sequence(SEQ-RECON-TO-EXPLOIT-001, GS-005→GS-002). periodicity는 동일
  수정 적용됐고 트리거만 생략.
- **Live Fire 연동**: SIEM 탐지 → `blue_detection_success`를 event_collector로 push(5→6 증가,
  rule_id/mitre 포함) → Blue 점수 경로 작동.
- `/detection/attack-coverage`(16 techniques), `/stats`(source/severity/top-sig 집계) OK.
- **🐛 버그 3건 발견·수정 (docker 실검증에서만 드러남)**:
  1. **탐지 크래시(치명)**: `model_dump(mode="json")`가 timestamp를 ISO **문자열**로 만드는데
     threshold/sequence/periodicity가 `ts - window_sec`(float 가정) 연산 → `str - int` TypeError.
     게다가 `_syslog_consumer_loop`에 예외 가드가 없어 **첫 이벤트에서 소비자 태스크가 죽어**
     이후 syslog 인제스천 전체가 멈춤(pfsense lines가 1에서 안 늘던 원인). →
     `engine.py`에 `_event_epoch()`(float/ISO/datetime 흡수) 추가·3개 호출부 교체.
  2. **방어**: `DetectionEngine.evaluate()`에 규칙별 try/except — 한 규칙 예외가 전체 탐지/
     인제스천을 못 죽이게 격리.
  3. **죽은 규칙 2건(필드명 오류)**: SEQ-RECON-TO-EXPLOIT-001·TWIN-IDOR-SCAN-001이 존재하지
     않는 flat 필드 `src_ip`를 group_by로 사용(정규화 이벤트는 nested `src.ip`) → group_key=None
     조기 return으로 영영 미발화. TWIN-IDOR는 `distinct(endpoint)`도 top-level에 없어 이중 오류.
     → `src_ip`→`src.ip`, `distinct(endpoint)`→`distinct(raw.endpoint)`로 수정(탐지 시점 in-memory
     이벤트엔 두 경로 다 존재. 저장 라운드트립에선 nested src가 유실되지만 탐지는 저장 전 수행).
- **검증용 syslog 전송**: `python3 -c "socket.sendto(...1514)"` 로 filterlog 라인 주입(스크래치).

### M6 — 대시보드 / AAR 검증 ✅ **완료 (2026-07-13, docker 실검증)**
두 파트. 둘 다 코드 이미 존재 → 검증 성격.
**Part A — aar_report 백엔드(8090)**: event_collector `/replay/events` + scoring `/scores` +
siem `/alerts`를 모아 MTTD/MTTR/탐지율/오탐률/heatmap/추천/PDF 생성.
- SAT-KILLCHAIN-01·default 시나리오로 리포트 생성 → red_performance(flags/stages),
  blue_performance(**mttd 1.2s, detection_rate 31.6%**), attack_heatmap(기술별 occurred/detected),
  recommendations, **PDF 렌더링(reportlab, 유효 %PDF-1.4)** 전부 확인.
- **🐛 버그 2건 수정**:
  1. **heatmap 기술ID가 문자로 쪼개짐**: siem `AlertStore.list_alerts`가 mitre/matched_event를
     `json.dumps`한 **문자열 그대로 반환** → aar가 `'["T1234"]'`를 char 단위 순회('[','"','T'...).
     alert_store에서 읽을 때 `json.loads`로 역직렬화 + `attack_heatmap`에 `_as_list()` 방어 추가.
  2. **MTTD/탐지율 항상 0/None**: SIEM의 blue_detection_success는 matched_event_id에 **trace_id**를
     넣는데(다른 프로세스라 event_id를 모름) `metrics.py`는 **event_id로 조인** → 전부 미매칭.
     event_id **또는 trace_id**로 상관하도록 수정(trace_id는 세션 최이른 공격 기준).
- ⚠️ scenario_id별 AAR은 scenario_engine 파생 이벤트(stage_completed 등)만 잡힘. 트윈 red 공격/
  SIEM 탐지는 scenario_id="default"라(M3 라우팅과 동일 구조) 실제 red/blue 상관은 `default`
  리포트에서 확인. (근본 해결은 scenario_id 전파 개선 — 별도 과제.)
**Part B — 대시보드 2종(Vite/React)**: `dashboards/livefire`(5174, event/scoring/config/instructor),
`dashboards/siem`(5175, siem_api). Node 20.
- npm install → **build(tsc+vite) OK**(livefire 54모듈 / siem 37모듈) → dev 서빙(5174/5175) →
  크로스오리진 데이터 fetch로 실제 렌더 경로 확인(siem: stats/alerts/sources green, livefire: events/scores).
- **🐛 버그 2건 수정**:
  1. **두 대시보드 `src/vite-env.d.ts` 누락** → `import.meta.env` 타입 없어 build 실패(M4와 동일). 추가.
  2. **대시보드가 치는 백엔드 4종(event_collector/scoring_engine/instructor_api/siem_api) CORS 전무**
     → 브라우저 fetch 전부 차단. 6개 UI-facing 서비스(위 4 + config + edr)에 CORS 통일 적용
     (`allow_origin_regex`로 localhost 전 포트 허용 — 5173 콘솔/5174 LiveFire/5175 SIEM 자동 커버).
     M4에서 넣었던 edr/config의 5173-한정 origin 리스트도 이 정규식으로 교체(livefire 5174 커버).
- 대시보드 실행: `cd dashboards/livefire && npm install && npm run dev`(→5174), siem은 →5175.

---

## 4. 다음 마일스톤 (사용자가 지목하면 진행)

M1에서 예고한 "같은 패턴" 후속. 사용자가 **"N번 문서 M번 마일스톤 진행해줘, 실제 검증까지"** 로 지목함.

- ~~**M2 (EDR)**~~ ✅ 완료 (위 "M2 — EDR 연동 검증" 참고)
- ~~**M3 (시나리오)**~~ ✅ 완료 (위 "M3 — 시나리오 엔진 검증" 참고)
- ~~**M4 (EDR 콘솔)**~~ ✅ 완료 (위 "M4 — EDR 콘솔 프론트엔드 검증" 참고)
- ~~**M5 (SIEM)**~~ ✅ 완료 (위 "M5 — SIEM 코어 검증" 참고)
- ~~**M6 (대시보드/AAR)**~~ ✅ 완료 (위 "M6 — 대시보드 / AAR 검증" 참고)

**🎉 M0~M6 전 마일스톤 Docker 실검증 완료.**

### P1-1 — 서비스 복구 판정 + MTTR 배선 ✅ 완료

로드맵 A ★★★ "서비스 복구 판정"이 코드는 있으나 **미배포 상태**였음(`services/noc_monitor/`,
`services/core/recovery_watcher.py`가 `docker-compose.yml`에 없어 `asset_recovered`가 한 번도 발행된 적
없고 AAR MTTR이 항상 null). 이를 실제로 배선·검증 완료:

- **noc_monitor 배포**: Dockerfile 신규 작성(`services/core`도 함께 COPY) + compose에 서비스 추가
  (포트 8070, `range_control` + 3개 `twin_*` 네트워크 연결로 트윈 /health 폴링). 트윈 3종 폴링 정상.
- **복구 흐름 E2E 실검증**(트윈을 실제 stop/start): `asset_compromised(scenario) → noc WS 구독자가
  record_compromise → config_service 패치 → 트윈 다운 → 복구 후 3회 연속 정상 → RecoveryWatcher가
  patched 확인 → asset_recovered(dwell_sec) 발행 → scoring blue +50 → AAR MTTR 산출`.
  **MTTR=31.4s** 실측(이전 null).

이 경로가 처음 실제로 돌면서 **버그 2건**을 잡아 수정:
1. **recovery_watcher가 scenario_id 미전파** → 복구 점수가 침해와 다른 "default" 버킷에 떨어짐.
   `CompromiseRecord.scenario_id` 보존 + `record_compromise`/`_emit_asset_recovered`/noc WS 구독자까지
   전 구간 전파. 이제 침해와 동일 시나리오 버킷(SCADA-SABOTAGE-01)에 정확히 귀속.
2. **aar_report `metrics.py:52` MTTR 계산 크래시** — `e["metadata"]["dwell_sec"]`가 metadata를 dict로
   가정하나 event_collector `/replay/events`는 JSON 문자열로 반환(M6 히트맵/alert_store와 같은 계열).
   `_metadata()` 정규화 헬퍼 추가로 해결.

스모크 테스트에 옵션형 복구 케이스 추가(`SMOKE_RECOVERY=1`, 트윈 재기동 ~35초). 전체 **33/33 PASS**.

### P1-3 — 트윈 네트워크 격리 ✅ 완료

로드맵 F ★★★ "네트워크 격리 강화". **격리 전 상태를 컨테이너 내부에서 실측해 두 취약점 확인**:
트윈끼리 lateral 이동 가능(`gs_twin → pp_twin:8002` 성공), 트윈이 인터넷 egress 가능
(`gs_twin → 8.8.8.8:53` 성공). 둘 다 `range_control` 공유가 원인.

**설계 상충**: `twin_*` 네트워크를 `internal:true`로 하면 egress/lateral은 막히지만 트윈의
호스트 포트(8001~3) 퍼블리시도 함께 끊긴다(internal 네트워크는 published port 미동작 — 실측 확인).
→ **per-twin 리버스 프록시 게이트웨이**로 해결:

- `twin_*` 3개를 `internal:true`로 전환, 트윈에서 `range_control` 제거(트윈은 자기 internal
  네트워크에만 존재 → 직접 lateral·egress 원천 차단).
- 트윈이 의존하는 코어 3종(event_collector/config_service/edr_backend)을 각 `twin_*`에 연결
  (트윈→코어 통신만 허용).
- 호스트 접근은 `gs_gateway`/`pp_gateway`/`dn_gateway`(nginx:alpine)가 range_control + 자기
  트윈 네트워크 하나에만 걸쳐 8001~3을 리버스 프록시. **per-twin 분리로 "트윈→게이트웨이→형제
  트윈" 간접 lateral까지 차단**(단일 게이트웨이면 열렸음 — 실측으로 확인 후 분리). 트윈 stop/start
  시 IP 변동 대응 위해 docker DNS(127.0.0.11) 런타임 resolver 사용.

**격리 4대 속성 실측(스모크 §9로 회귀 커버)**: 직접 lateral 차단 ✅ / 간접(게이트웨이 경유)
lateral 차단 ✅ / 인터넷 egress 차단 ✅ / 트윈→코어 통신·호스트 접근 유지 ✅.
전체 스모크 **34/34 PASS**(복구 포함 시 38/38).

주: egress를 compose 레벨에서 차단(방화벽 계층 불필요)했으므로 USAGE.md의 "egress는 방화벽 계층에서"
전제는 트윈에 한해 해소됨. 챌린지별 deploy compose(WEB-005 등)는 여전히 자체 격리 정책을 따름.

### P1-2 — 서비스 유닛 테스트 + CI ✅ 완료

기존엔 `services/` 하위 유닛 테스트 0개, CI 없음 → 회귀 안전망이 스모크 하나뿐이었음.
**순수 로직 유닛 테스트 + GitHub Actions CI** 추가:

- **유닛 테스트 35개**(`tests/unit/`, `python -m pytest tests/` 로 계약 8개 포함 43개 전부 통과,
  0.9초). 지금까지 고친 버그를 정조준한 회귀 테스트:
  - `test_aar_metrics.py` — `_metadata` JSON문자열 흡수, `compute_mttr`(P1-1 크래시),
    MTTD/탐지율의 event_id·trace_id 이중 상관(M6).
  - `test_aar_heatmap.py` — `_as_list`가 JSON문자열 mitre를 글자 단위로 쪼개지 않음(M6).
  - `test_siem_engine.py` — `_event_epoch` float/ISO/Z/datetime/None/쓰레기 흡수(M5).
  - `test_edr_rules.py` — EDR-001/002/003 트리거·비트리거 경계.
- **CI**(`.github/workflows/ci.yml`) 2개 job:
  - `unit`: `pip install -r requirements-dev.txt` → `pytest tests/`(docker 불필요, 수 초).
  - `integration`: 전체 docker 스택 build+up → `SMOKE_RECOVERY=1 scripts/smoke_test.sh` → down.
- **스모크 이식성 개선**: EDR 호스트 포트 자동 감지(로컬은 override로 18080, CI는 override 없어
  8080). `docker compose config`로 CI/로컬 매핑 차이 확인, 스모크가 양쪽 자동 처리.
- dev 의존성 분리: `requirements-dev.txt`(pytest, 런타임 이미지엔 미포함).

주: CI 러너가 없어 GitHub Actions 실행 자체는 못 돌렸지만, 두 job의 명령을 로컬에서 그대로 실행해
검증(unit=43 pass, YAML 유효, requirements-dev 설치 OK, base-only 매핑에서 edr=8080 확인).

### P2 — C-QA docker 게이트 실검증 + 파이프라인 이식성 수정 ✅ 완료

15개 챌린지 전부 `QA_PASSED` 마커를 갖고 있었으나, **대부분 `--skip-docker` 결과**였음(doc25 명시).
실제 docker로 돌려보니 파이프라인의 근본 결함 2개를 발견·수정:

**근본 결함 1 — run_all의 base_url 8100 하드코딩.** 챌린지마다 배포 포트가 다른데(WEB-000=8101,
AI-000=8102, WEB-002/003/005/007=8100) run_all이 8100 고정이라, **8100을 쓰는 챌린지만 우연히
docker QA를 통과**하고 WEB-000·AI-000은 health check가 엉뚱한 포트를 찔러 실패했다(= docker 검증된
적 없음). → `_derive_base_url()`로 각 챌린지 `deploy/docker-compose.yaml`의 published 포트를 자동
추출해 base URL을 만들도록 수정(사용자가 `--base-url` 명시 시 존중).

**근본 결함 2 — 아티팩트형/무포트형이 docker 모드에서 혼란스럽게 실패.** DET/FOR/NET/REV(8개)는
배포 서비스가 없고(compose 없음), AI-001은 compose는 있으나 포트 미노출(오프라인 모델 훈련형).
이들은 deploy_up이 애초에 맞지 않는데 "compose 없음"으로 실패했다. → **compose에 published 포트가
있어야만 docker 배포 게이트를 적용**하도록 판정 로직 추가. 서비스 없는 챌린지는 스키마/안전성 검사만
받고 명확한 안내 메시지 출력.

**실검증 결과(이번 세션 실제 docker 실행):**
- 배포형 서비스 6종 **full docker QA PASS**: WEB-000(8101)·WEB-002·WEB-003·WEB-005(hardened RCE)·
  WEB-007(8100)·AI-000(8102) — 각 deploy_up→intended_solve(실플래그)→blank_submit→flag_determinism
  →teardown 전부 통과, 잔여 컨테이너 0.
  - **WEB-000·AI-000은 이번에 처음으로 실제 docker QA를 통과**(포트 자동추출 수정 덕분).
- 서비스 없는 9종(AI-001 + 아티팩트 8): 자동 스킵 + 스키마/안전성 PASS로 정상 처리 확인.

**남은 후속(문서화):** 아티팩트형 exploit 시그니처가 HTTP형과 불일치(`solve(path)` vs
`solve(base_url, team_id)`)해 아티팩트 solve/grader 검증이 아직 run_all에 통합되지 않음 → 시그니처
통일이 P2b 후속과제. 분야별 문제 수 확충(현재 각 2~5개 → 목표 ~7)도 별도 authoring 작업으로 잔존.

### P2b — 아티팩트 exploit 계약 통일 + C-QA 통합 ✅ 완료

P2에서 남긴 갭: 아티팩트형 exploit의 시그니처/반환이 제각각(`solve(path)->dict`, `solve(path)->str`,
`solve(team_id)->str`)이라 HTTP 전용 intended_solve가 이들을 검증하지 못했다. **하버스 계약 계층에서
통일**했다:

- **`infra/challenge_qa/artifact_solve.py`** 신규: 생성기(deploy/generate_artifact.py 등)를 deploy/에서
  실행 → exploit.solve를 시그니처로 분기 호출(경로형/team_id형/HTTP형) → 반환을 submission dict로
  정규화(dict 그대로, str→`{"flag":...}`) → `grade_red({team_id, **submission}, {challenge_dir})` 채점 →
  정답 PASS + **빈 제출 FAIL**까지 확인. 생성한 아티팩트 중 사전에 없던 파일은 끝나고 정리(리포 오염 방지).
- **NET-002 exploit**을 canonical dict 반환(`{"path": ...}`)으로 정규화(grader가 `{path}` 기대).
- **run_all 통합**: 아티팩트형(compose 없음 + `exploit.solve` 존재)은 docker 게이트 대신 artifact_solve
  게이트 실행. DET처럼 exploit.solve 없는 탐지형은 answer_rule.yaml을 SIEM 엔진으로 채점하는 별도
  모델이라 스키마/안전성만.

**실검증(run_all 실제 실행):** NET-000·NET-002·FOR-000·FOR-002·REV-000·REV-001 **6종 artifact_solve
PASS**(각 solve 실행 + grade_red 통과 + 빈제출 거부). 유닛 테스트 6개 추가(`test_artifact_solve.py`:
정규화 + 시그니처 분기) → 전체 **58 pass**. WEB-000 등 서비스형은 여전히 docker 게이트(회귀 없음).

### 탐지형(DET) SIEM 채점 통합 ✅ 완료

DET는 익스플로잇이 아니라 **탐지 규칙(answer_rule.yaml)**을 제출하고 우리 진짜 SIEM DetectionEngine이
채점하는 별도 모델(`grade_blue(context)`). 이를 위한 게이트를 통합:

- **`infra/challenge_qa/detection_solve.py`** 신규: 데이터셋 생성(generate_datasets.py) → 정답 규칙으로
  `grade_blue` PASS(공격 탐지 + 정상 오탐 0) 확인 → **no-op 규칙으로 FAIL 확인**(채점기 판별력 보증) →
  생성 데이터셋 정리.
- **run_all 통합**: 탐지형(exploit.solve 없음 + blue_grader + generate_datasets 존재)은 detection_solve 게이트.

**전체 15개 챌린지 C-QA 최종 실검증(각 타입별 올바른 게이트로 전부 PASS):**
| 타입 | 게이트 | 챌린지 |
|---|---|---|
| 서비스형 6 | deploy_up(docker) | WEB-000·002·003·005·007, AI-000 |
| 아티팩트형 6 | artifact_solve | NET-000·002, FOR-000·002, REV-000·001 |
| 탐지형 2 | detection_solve(SIEM 엔진) | DET-000·001 |
| 특수 1 | 스키마/안전성 | AI-001(무포트·표준 solve 진입점 없음) |

**남은 후속:** AI-001 exploit에 표준 solve 진입점 부여, 분야별 문제 확충(~7).

### 챌린지 확충 (진행 중) — 신규 4종 ✅

완성한 C-QA 파이프라인으로 완전 검증 가능한 신규 챌린지를 얇은 분야에 추가(전부 **run_all 전체
C-QA PASS** + 팀별 동적 값 유니크성 실측):

- **FOR-001 "명령 이력 포렌식"**(forensics, easy, T1048): 셸 이력에서 base64 유출 명령을 찾아
  C2 호스트/비밀/기법 복원. → forensics 3
- **NET-001 "DNS 터널링 분석"**(network, medium, T1071.004): DNS 조회 로그에서 서브도메인 라벨에
  hex로 실린 유출 데이터를 재조립·복원. → network 3
- **REV-002 "반복키 XOR 복원"**(reversing, medium, T1027): 4바이트 반복키 XOR를 known-plaintext로
  복원(단일바이트 REV-000의 상위판). → reversing 3
- **DET-002 "웹 로그 SQLi 탐지"**(detection, easy, T1190): match 규칙(`raw.uri ~UNION SELECT`)을
  진짜 SIEM 엔진으로 채점(공격 탐지 + 유사 검색어 오탐 0). → detection 3

2라운드 추가(각기 다른 기법):
- **FOR-003 "세션 하이재킹 흔적"**(forensics, medium, T1539): 한 세션이 2개 IP에서 재사용된 하이재킹
  탐지. → forensics 4
- **NET-003 "C2 비콘 간격 분석"**(network, medium, T1071): (src,dst) 등간격 연결로 비콘 식별 +
  implant 복원. → network 4
- **REV-003 "다단계 인코딩 복원"**(reversing, medium, T1140): base64→역순→XOR 3계층 해제. → reversing 4
- **DET-003 "웹쉘 킬체인 탐지"**(detection, medium, T1505.003): **sequence 규칙**(.php 업로드→실행)을
  진짜 SIEM 엔진으로 채점(엔진 sequence 기능도 함께 검증). → detection 4

3라운드 추가(또 다른 기법):
- **FOR-004 "이메일 헤더 포렌식"**(easy, T1566): Received 체인 역추적으로 피싱 발신 IP/사칭발신자/토큰 복원.
- **NET-004 "ARP 스푸핑 탐지"**(easy, T1557): 한 IP를 두 MAC이 주장하는 MITM 식별.
- **REV-004 "스택 VM 리버싱"**(hard, T1027): PUSH/ADD/XOR/EMIT 바이트코드 VM 인터프리터 구현.
- **DET-004 "C2 비콘 주기성 탐지"**(hard, T1071): **periodicity 규칙** + allowlist 튜닝을 SIEM 엔진 채점.

→ **SIEM 4가지 규칙 종류(match·threshold·sequence·periodicity) 전부** DET 챌린지로 커버 완료.

4라운드 추가(각기 다른 기법, AI 분야 포함):
- **AI-002 "프롬프트 인젝션 흔적 분석"**(ai, easy, T1059): LLM 챗 로그에서 지시 무시형 인젝션과
  노출된 API 키 복원 — **ML 의존 없이 검증 가능**해 뒤처진 AI 분야를 키움. → ai 3
- **FOR-005 "메모리 덤프 문자열 분석"**(easy, T1003): strings 추출로 잔존 자격증명 복구. → forensics 6
- **NET-005 "포트 노킹 시퀀스 복원"**(medium, T1205): 보호 포트 접속 직전 노킹 순서 복원. → network 6
- **REV-005 "LCG 스트림 사이퍼"**(hard, T1027): LCG 키스트림 재현해 XOR 복호화. → reversing 6
- **DET-005 "Log4Shell(JNDI) 탐지"**(medium, T1190): UA/URI 다중필드 match 규칙 SIEM 채점. → detection 6

5라운드 추가(목표 7 도달):
- **FOR-006 "지속성 흔적(스케줄 작업)"**(easy, T1053) → forensics 7
- **NET-006 "TCP 세그먼트 재조립"**(medium, T1041) → network 7
- **REV-006 "비트 회전 사이퍼(ROL)"**(medium, T1027) → reversing 7
- **DET-006 "DNS DGA 탐지"**(medium, T1568.002, threshold distinct) → detection 7
- **AI-003 "데이터 포이즈닝 흔적"**(medium, T1195) → ai 4

6라운드 추가(web·ai 마무리 → 전 분야 7 달성):
- **WEB-001 "명령 주입"**(medium, T1059) / **WEB-004 "경로 순회"**(medium, T1083): docker 서비스
  챌린지(정적 플래그, WEB-005 패턴). **full docker C-QA PASS**(deploy_up→intended_solve→
  flag_determinism→teardown). → web 7
- **AI-004 "RAG 간접 프롬프트 인젝션"**(medium) / **AI-005 "모델 추출 API 남용"**(easy) /
  **AI-006 "훈련 데이터 memorization 유출"**(medium): 인시던트 분석형(ML 의존 없이 검증). → ai 7

🎯🎯 **web / forensics / network / reversing / detection / ai — 6개 전 분야 7개 목표 달성.**

모두 표준 구조 + 팀별 동적 값(HMAC). **전체 42개 챌린지 C-QA PASS**(비서비스 34종 run_all +
서비스형 8종 docker QA). 이번 세션 누적 **신규 27종**(web 2 + FOR·NET·REV·DET·AI 각 5).

**현황:** web 7 / forensics 7 / network 7 / reversing 7 / detection 7 / ai 7 = **42개**.
난이도 easy~hard, 기법 무중복(로그 파싱/base·hex 디코딩/XOR·ROL·LCG 암호/스택VM/TCP·DNS 재조립/
SIEM 규칙 4종/웹 취약점 3종/AI 보안 인시던트 5종).

### P3 — RBAC(역할 기반 접근제어) ✅ 완료

기존엔 컨트롤플레인 전체가 **단일 공유 Bearer 토큰**(`_require_instructor`)만 확인했고, 실측 결과
**EDR isolate는 `authorization` 헤더를 받고도 검증하지 않아 누구나 호스트를 격리**할 수 있고,
**scoring `/score/adjust`는 무인증이라 누구나 임의 가감점**이 가능한 갭이 있었다. 역할 기반으로 전환:

- **`shared/rbac.py`** 신규: 토큰→역할 매핑(instructor/red/blue/observer) + `require_role(auth, allowed)`.
  - 토큰 설정: 개별 변수(`INSTRUCTOR_TOKEN`/`RED_TOKEN`/`BLUE_TOKEN`/`OBSERVER_TOKEN`) 또는
    `RBAC_TOKENS="tok:role,..."` 병합.
  - 인증 정책: 무효 토큰 **401**, 역할 부족 **403**. 토큰 미설정 로컬 dev는 관대 통과(dev_mode,
    기존 동작 보존). **하위호환**: INSTRUCTOR_TOKEN만 있으면 그 토큰=instructor로 그대로 작동.
  - JWT 확장 시 `authenticate()`만 교체하면 됨.
- **배선**: config_service(교관 조작 → instructor 전용), instructor_api(전 액션 → instructor 전용),
  edr isolate/unisolate/kill(방어 액션 → **instructor 또는 blue**, 무검증 갭 차단).
  config_service·edr는 Dockerfile에 `shared/` COPY + sys.path 추가(WORKDIR가 서비스 디렉토리라서).

**docker 실증(역할 매트릭스):**
| 엔드포인트 | 무토큰 | red | blue | instructor |
|---|---|---|---|---|
| config `/instructor/patch/toggle` | 401 | — | **403** | 200 |
| instructor_api `/scenario/start` | — | — | **403** | 200 |
| edr `/isolate` (방어) | **401**(갭 차단) | **403** | **200** | 200 |
| scoring `/score/adjust` (수동 가감점) | **401**(갭 차단) | — | **403** | 200 |

- 유닛 테스트 9개(`tests/unit/test_rbac.py`: dev모드/401/403/역할구분/RBAC_TOKENS 파싱) → 전체 **58 pass**.
- 스모크 §4에 RBAC 역할 구분 검사 추가(blue→instructor 엔드포인트 403) → **35/35 PASS**.
- `.env`에 역할 토큰 추가, compose 4개 서비스(config/instructor_api/edr/scoring)에 `RED/BLUE/OBSERVER_TOKEN`
  전달. edr→config, instructor_api→scoring S2S 호출(INSTRUCTOR_TOKEN)도 정상 유지 확인. CI는 역할 토큰
  미설정이라 RBAC 구분 검사는 자동 스킵(무해).
- **scoring `/score/adjust` 무인증 갭 차단**: 이전엔 누구나 직접 임의 가감점이 가능했다(scoring에 env
  토큰 자체가 없어 dev 모드로 열려 있던 것도 발견·수정). 자동 채점 경로 `/score/ingest`는 내부 S2S라 유지.

### 통합 스모크 테스트 ✅ 통과 (`scripts/smoke_test.sh`)

`docker compose up -d` 후 `bash scripts/smoke_test.sh` 한 줄로 전체 E2E를 실검증(하나라도 깨지면 exit 1).
기본 **35/35 PASS**(RBAC 역할구분 포함), `SMOKE_RECOVERY=1` 포함 시 **38/38 PASS**. 검증 경로:

1. 12개 서비스 헬스체크(noc_monitor 포함)
2. 트윈 텔레메트리 + 공격표면(로그인 401 → access log)
3. **트윈 → SIEM 인제스천** (실트래픽 후 이벤트 수 증가 확인)
4. **Config 교관조작** — 미인증 401 차단(음성) → 토큰 패치토글 → read-back → audit 기록
5. **event_collector → scoring_engine** (red_objective 이벤트 → 점수 0→100 자동 반영)
6. **instructor_api → scenario_engine** (activate → progress → deactivate)
7. **EDR** (리버스쉘 스냅샷 인제스트 → EDR-002 탐지 알림)
8b. **복구 판정 E2E** (옵션, `SMOKE_RECOVERY=1`) — asset_compromised→패치→트윈복구→asset_recovered→MTTR
8. **AAR** 집계(mttd_sec/detection_rate) + PDF 렌더(`%PDF` 매직)
9. **트윈 네트워크 격리** — 직접/간접 lateral 차단 + egress 차단 + 트윈→코어 통신 유지

주: 최초 실행 시 5건 FAIL은 전부 시스템 정상이었고 스크립트의 응답구조/인증 가정 오류였음(§0 규칙대로 실제
응답으로 원인 확인 후 스크립트 수정: SIEM stats 필드명, Config 토큰 미전달, /scores 시나리오 파라미터, AAR
필드 경로). 재실행 시 29/29 통과.

관련 문서: `docs/21_build_environment_guide.md`(M1~M6 정의), `docs/22_*`, `docs/09_team_agents_roles.md`(역할),
`docs/25_cqa_pipeline_and_remaining_challenges_plan.md`(남은 챌린지 목록).

---

### insane 티어 6종 추가 ✅ 완료 (2026-07-14) — 난이도 곡선 보강

문서 `docs/18_difficulty_curve_easy_insane.md` 설계대로 **각 분야 insane 1문제씩 6종** 추가.
6개 전 분야가 easy~insane 곡선 완성(분야당 8문제, 총 42→**48**). 전부 실제 실행·C-QA PASS 확인.

| ID | 게이트 | 배점 | 핵심 검증 |
|---|---|---|---|
| REV-009 | artifact_solve | red 300 | 핸들러테이블 순열+LCG 키스트림+8op 스택VM 복원, 팀별 유니크 |
| FOR-009 | artifact_solve | red 300 | 저널>MFT 타임스톰프 탐지→슬랙 base64 은닉채널→반복키 XOR, 팀별 유니크 |
| NET-009 | artifact_solve | red 300 | Modbus 미인가쓰기(rogue)→커버트 레지스터→하위바이트 base64, 팀별 유니크 |
| AI-009 | artifact_solve | red 300 | 선형 IDS 로그 재평가→최소 L0 전이회피 쿼리→섭동인덱스 키 XOR (ML 프레임워크 불요), 팀별 유니크 |
| DET-009 | detection_solve | blue 200 | APT low-and-slow(1800s) periodicity 헌팅: window 15000+관측수6+지터0.1+다중 allowlist. attack 1알림/normal 0오탐 |
| WEB-009 | **full docker** | red 300 / blue 150 | 문자블랙리스트 WAF 우회(`/**/`·`>`·무따옴표 unicode/substr)+블라인드 불리언 SQLi 이진탐색. deploy_up/intended_solve/blank_submit/**flag_determinism 재배포 일관**/teardown 전부 통과 |

- 검증 방식: 아티팩트 4종은 `run_all.py --challenge <ID>`로 생성→solve→grade + 빈제출 거부 + teamA/B/C
  유니크성 실측. DET-009는 SIEM DetectionEngine 실채점(no-op 규칙 거부까지). WEB-009는 실제 docker
  build+기동 후 HTTP 블라인드 SQLi로 flag 추출, 재배포 후 flag 일관성 확인.
- WEB-009 **blue(방어) 실증**: `PATCH_WEB_009=true` 재기동 시 우회 페이로드 `400 invalid id`,
  정상 id=1 `found:true`, 기존 익스플로잇 완전 차단까지 수동 확인(하네스 `blue_verify.py`는 재기동 후
  health 대기 로직이 없어 connection reset이 나는 알려진 레이스가 있으나, 기본 C-QA엔 미포함이라 무관).
- 배점은 실 저장소 스케일(hard REV-003≈140, WEB-005≈250)에 맞춰 설계안(400~450)에서 하향.
- 회귀: 유닛 테스트 **58 pass** 유지(챌린지는 순수 추가라 플랫폼 서비스/유닛에 영향 없음). 통합 스모크는
  플랫폼 서비스 E2E라 이번 변경과 무관(현재 스택은 환경 재시작으로 down 상태 — 재검증 시 `docker compose up -d`
  후 `bash scripts/smoke_test.sh`).

---

## 📌 세션 연속성 메모 (2026-07-14 insane 티어 완료 후 — 최신)

> **이번 세션 성과**: insane 티어 6종(REV/FOR/NET/AI/DET/WEB-009) 신규 추가 → 전부 C-QA PASS
> 실검증(바로 위 "insane 티어 6종 추가" 섹션 참조). 총 챌린지 42→**48**, 6개 전 분야 easy~insane
> 곡선 완성(분야당 8). 유닛 테스트 **58 pass** 유지. `docs/18`·`HANDOFF.md` 갱신 완료.
> 인계 시점 실측:
> - **플랫폼 스택 down**: `docker ps -a` 기준 코어/트윈/게이트웨이/noc 15개 컨테이너가 Exited(255)
>   상태(환경 재시작 때문, 이번 챌린지 작업과 무관). 재검증 시 `docker compose up -d` 후
>   `bash scripts/smoke_test.sh`로 그린 확인. WEB-009 등 챌린지 docker는 격리된 자체 compose라
>   플랫폼 스택과 독립(C-QA 시 자동 build+up+teardown, 잔여 컨테이너 없음 확인함).
> - **이전 인계 시점 참고(플랫폼이 Up이던 때 실측)**: `docker ps` 기준 15개 컨테이너 Up(11~17h).
>   (Suricata/Zeek 센서 6종은 M5용 대용량이라 이 부팅에선 미기동 — 필요 시 `docker compose up -d` 전체.)
> - **M3 라이브 재검증 통과(문서 정확성 확인)**: `SAT-KILLCHAIN-01` 활성화 → GS-005→002→001→003
>   순서 공격(ground_station 8001, `X-Team-Id` 구분) → `completed_stages=[1,2,3,4]` +
>   **`chain_bonus_awarded=true`**. event_collector에 `stage_completed×4` +
>   `red_objective_success(chain_bonus:50)` + `red_attack_started×3`/`flag_exfiltrated×1`,
>   덤으로 SIEM `blue_detection_success×4`까지 기록 확인. 검증 후 deactivate로 정리함.
>   → §2의 M3 "`_route_event()` scenario_id 라우팅 수정"이 현재도 정상 동작함을 재확인.
> - **소켓 권한**: 재부팅 시 `sudo chmod 666 /var/run/docker.sock` 다시 필요할 수 있음(§1-(a)).
> - **다음 착수 후보**: (난이도 곡선/insane 티어는 이번 세션에 완료) 옵저버 read 엔드포인트 세분화,
>   AI 분야 실 ML/docker 확충, 빈 medium/hard 칸 채우기(REV/FOR/NET medium 등). 새 세션은 먼저
>   `docker compose up -d` + `bash scripts/smoke_test.sh`로 플랫폼 그린 확인 권장(현재 스택 down 상태).

---

---

## 📌 세션 연속성 메모 (2026-07-24 — 후속 3작업 + GitHub 관리 시작)

> **이번 세션 성과**: 이전 인계의 "다음 착수 후보" 3건을 전부 구현·실검증하고 **GitHub 저장소로
> 관리 시작 + 상세 한글 README(스크린샷 6종) 작성**.
>
> 1. **옵저버 read 엔드포인트 세분화**: `shared/rbac.py`에 `require_read()`/`read_enforced()` 추가.
>    scoring(`/scores`,`/scores/history`) + edr(`/edr/hosts`,`processes`,`timeline`,`alerts`,`audit`)에 배선.
>    **`OBSERVER_READ_ENFORCE` 옵트인**(기본 off=공개 → 대시보드/스모크/CI 무영향; on → read에 유효토큰
>    요구, 무토큰 401 / 관전자 이상 200). docker 역할 매트릭스 실증(read: obs 200 / 무토큰 401 / red 200,
>    write: obs 403 / 무토큰 401, isolate 유효body 403/401). compose(scoring/edr)에 플래그 pass-through.
> 2. **AI-007**(hard, 실 ML/docker): numpy 2층 MLP 직접 학습(seed 고정, weight decay) → docker 서빙
>    (`/model` 화이트박스, `/source`, `/classify` 예산·박스 검사). 화이트박스 **PGD**로 L∞ 예산(0.12) 안
>    오분류 유도 시 팀별 HMAC 플래그. **full docker C-QA PASS**. 포트 8107.
> 3. **FOR-007**(hard, artifact): 프로세스 할로잉 — private+RX 이상영역 탐지→은닉 스테이저(base64)→XOR 복호.
>    **NET-007**(hard, artifact): 다중 홉 피벗 체인 — netflow 시간·바이트 상관으로 체인 복원→토큰 XOR 복호.
>    둘 다 **artifact_solve C-QA PASS** + 팀별 유니크 실측.
>    → **ai/forensics/network hard 티어 0→1 해소**. 6개 전 분야 easy~insane 완성. **총 51 챌린지**.
>
> - **회귀**: 유닛 테스트 58→**66 pass**(RBAC read 게이트 테스트 +8), 통합 스모크 **35/35 PASS**(변경 무영향).
> - **GitHub**: `https://github.com/MintKangaroo/Cyber-Offensive-and-Defensive-Exercise` (PUBLIC, 기본 main).
>   `gh auth setup-git`로 HTTPS 자격증명 설정, 원격 초기 README를 상세 README로 대체(unrelated histories
>   merge -X ours). **588파일 커밋 → main 푸시 완료**. .env/node_modules/dist는 .gitignore로 제외(시크릿
>   스캔 clean). 기존 계약문서(구 README)는 **CONTRACTS.md**로 보존.
> - **README**: 상세 한글(아키텍처 mermaid + 챌린지 카탈로그 51 + 빠른시작 + 검증 + RBAC 매트릭스) +
>   **실제 UI 스크린샷 6종**(`docs/images/`: EDR 콘솔 개요·호스트, Live Fire, SIEM discover·alerts·coverage).
>   스크린샷은 dev서버 3종(5173/5174/5175) 기동 + 킬체인/EDR/SIEM 데이터 시딩 후 **playwright(docker
>   mcr playwright 이미지 --network host)** 로 캡처(호스트에 chromium 시스템 라이브러리 없어 컨테이너 사용).
> - **환경 특이(신규)**: 로컬 18080을 **별도 프로젝트 patchtower-nginx가 점유** → `docker-compose.override.yml`
>   의 edr 호스트포트를 **18080→18090**으로 변경. `scripts/smoke_test.sh` 포트 자동감지에 18090 추가,
>   `services/edr/console/.env.local`도 18090으로. (patchtower/triphelper 등 무관 컨테이너가 상시 떠 있음.)
>
> **추가 작업(같은 세션 후반, 사용자 요청):**
> - **자산명 변경**: `국방망` → `사내망`(defense_network의 표시 라벨). UI 4곳(edr console HostList,
>   livefire AssetMap/EventTimeline/PatchMatrix) + README + 트윈 docstring + 시나리오명. 식별자
>   `defense_network`는 불변. 영향받은 스크린샷(EDR 콘솔 2장 + LiveFire) 재캡처.
> - **트윈 취약 서비스 6종 신규**(각 트윈 +2 → 총 14→**20종**):
>   - GS-006 SSRF(`/api/tle/import`), GS-007 XXE(`/api/config/xml-import`)
>   - PP-006 미인가 Modbus 쓰기(`/api/modbus/write-register`, ICS), PP-007 서명없는 펌웨어(`/api/plc/firmware-update`, ICS)
>   - DN-005 LDAP 인젝션(`/api/directory/search`), DN-006 SSRF(`/api/webhook/preview`)
>   - 기존 패턴 그대로: ROUTE_VULN_MAP + `patched("PATCH_XX_00N")` + emit_event. `vuln_catalog.json`·
>     `safe_probe.py`(14→**20 프로브**)에도 반영. **⚠ RedPhase는 initial_access/privilege_escalation/
>     lateral_movement/data_exfiltration/objective 5개뿐**(discovery·persistence 없음 — 처음에 이걸로 500 나서 수정).
>   - **실검증**: 트윈 재빌드 → 20종 전부 safe_probe VULNERABLE, 6종 취약 동작 직접 확인,
>     GS-006 config 토글 패치 경로(patched→400→PATCHED→원복)까지 실증. 유닛 66 pass, 스모크 35/35.
> - **다음 착수 후보**: 관전자 read 게이트를 siem/scenario/event_collector/aar까지 확장(현재 scoring/edr만),
>   AI 분야 실 docker/ML 추가 확충, 신규 트윈 서비스(GS-006~DN-006)를 킬체인 시나리오/SIEM 규칙에 연동.

---

## 📌 세션 연속성 메모 (2026-07-24 — ICS/OT 섹터 8종 확장)

> **사용자 요청**: 위성/전력/사내망 3종에 더해 정유·스마트팩토리·수도·LNG·철도·공항·데이터센터·병원
> 8개 ICS/OT 섹터를 트윈으로 확장. → **11개 섹터, 취약 서비스 44종(20→44)** 달성.
>
> - **ICS 트윈 팩토리 신규**(`shared/ics_twin.py`): `Vuln(id,path,method,event_type,phase,handler)` 목록 +
>   `make_ics_twin(asset,title,vulns)` 로 트윈을 선언적으로 생성. EDR 에이전트/SIEM access log/Config
>   무중단 패치/격리·킬스위치/이벤트 발행을 공통 상속. 핸들러 시그니처 `handler(patched,payload,emit)->dict`,
>   패치 거부는 `deny(status,detail)`. GET=query, POST=query+json 병합해 payload 전달.
> - **신규 트윈 8종**(각 3 서비스, 포트 8201~8208, `services/<name>/main.py`+Dockerfile):
>   refinery_plant(REF, OPC UA/SIS/HART) / smart_factory(FAC, PLC·Robot·MES) / water_utility(WTR) /
>   lng_terminal(LNG, ESD/BOG/F&G) / railway_signaling(RWY) / airport_ot(AIR) / datacenter_bms(DCX) /
>   hospital_ot(HSP). compose에 range_control 직결로 추가(**per-twin 게이트웨이 격리는 신규 섹터엔
>   미적용 — 후속 과제**. 기존 3종만 internal+gateway 격리).
> - **safe_probe 데이터 기반 확장**(20→**44 프로브**): `SECTOR_PROBES` 리스트 + `_sector_check` 루프.
>   `vuln_catalog.json`도 11자산 44종으로 확장.
> - **대시보드 라벨**: livefire(AssetMap/EventTimeline/PatchMatrix) + edr console HostList에 8개 섹터
>   한글 라벨 추가(topology 좌표 ASSET_POS는 미추가 — 신규 섹터는 토폴로지 도형엔 미표시, 목록/피드엔 표시).
> - **실검증**: 8종 docker 빌드+기동 → 헬스 그린, safe_probe **44종 전부 VULNERABLE**, REF-002 config
>   토글 패치 경로(200→403→원복) 실증, EDR 11 호스트 등록 확인. 대시보드 2종 빌드 OK. 유닛 66 pass,
>   스모크 35/35. 신규 스크린샷 `docs/images/edr-console-fleet.png`(11 호스트).
> - **⚠ 함정**: RedPhase엔 discovery/persistence 없음(5개뿐). 팩토리 핸들러 phase는 유효값만.
> - **다음 착수 후보**: 신규 섹터 per-twin 게이트웨이 격리 패리티, 섹터별 킬체인 시나리오/SIEM 규칙,
>   LiveFire 토폴로지에 신규 섹터 배치(ASSET_POS), 섹터 CTF 챌린지.

## 5. 상태 요약 한 줄

M0 병합 / M1 **Docker 재검증** / **M2(EDR)** / **M3(시나리오)** / **M4(EDR 콘솔)** / **M5(SIEM 인제스천+탐지4종+LiveFire)** / **M6(대시보드/AAR)** 라이브 검증 완료 → **M0~M6 전 마일스톤 Docker 실검증 완료** / **P1-1 복구판정+MTTR 배선 완료(noc_monitor 배포, MTTR 실측)** / **P1-3 트윈 네트워크 격리 완료(per-twin nginx 게이트웨이, lateral·egress 차단 실측)** / **P1-2 유닛테스트 43개+GitHub Actions CI 완료** / **P2 C-QA docker 게이트 실검증(배포형 6종 full docker QA PASS, run_all 포트자동추출+아티팩트 감지 수정)** / **P3 RBAC(역할별 토큰, edr isolate 무검증 갭 차단)** / **P2b 아티팩트 exploit 계약 통일(artifact_solve, NET/FOR/REV 6종 solve+grade 실검증)** / **유닛 테스트 58 pass** / **통합 스모크 테스트 `scripts/smoke_test.sh` 35/35 PASS(+복구=38/38)** / **전체 48개 챌린지 C-QA PASS**(서비스형 9 docker + 아티팩트형 31 artifact_solve + 탐지형 8 detection_solve) / **insane 티어 6종 신규 완료·전부 C-QA PASS**(REV-009 핸들러테이블VM / FOR-009 안티포렌식3단 / NET-009 OT사보타주 Modbus / AI-009 전이회피 로그분석 / DET-009 APT low-and-slow 헌팅 / WEB-009 WAF우회+블라인드SQLi full-docker) → **6개 전 분야 easy~insane 곡선 완성(각 8문제)** / 버그 14건 수정(QA2 + 시나리오 라우팅1 + 콘솔 vite-env/CORS2 + SIEM timestamp/가드/죽은규칙3 + AAR 히트맵/상관키2 + 대시보드 vite-env/백엔드 CORS2 + 복구 scenario전파/AAR MTTR metadata2) / USAGE.md / **다음: 옵저버 read 엔드포인트 세분화, AI 분야 확충(실 ML/docker), 빈 medium/hard 칸 채우기(REV/FOR/NET medium 등).**
