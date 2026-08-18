# PHASE 3 — 통합 감사 리포트

- 감사일: 2026-08-14 / 대상 리비전: `main` HEAD `09e9378` (작업트리 clean)
- 방식: **정적 분석 전용.** 도커·make·training·pytest 미실행(사용자 메모리 제약).
- 기준선: CCE(사이버공격방어대회), Locked Shields, DEF CON CTF Attack/Defense, NIST SP 800-84.
- 입력: `audit/00_inventory.md` + 축별 리포트 10건(A~J).

---

## 0. 총평

이 저장소는 **A/D 게임 엔진(`services/attack_defense/`, 10,224 LOC) 하나만 대회급이고, 그것을 둘러싼
훈련 플랫폼 전체가 미완성**이다. 저장소 전체 백엔드 테스트의 56%가 그 한 디렉터리에 몰려 있고
(`tests/attack_defense/` 2,959 LOC), 나머지 컨트롤 플레인은 인증·테스트·관측성이 모두 비어 있다.

가장 심각한 구조적 문제는 기능 결손이 아니라 **허위 보증**이다. 플랫폼이 스스로
"격리 100%"(`services/range_control/main.py:308-321`)와 "다음 훈련 시작 가능"
(`services/range_control/main.py:283`)을 출력하는데, 둘 다 실제 상태를 측정하지 않는다. 운영자가
이 표시를 믿고 훈련을 개시하면 아무도 위험을 인지하지 못한 채 진행된다.

잘된 부분 한 줄: `shared/ics/modbus.py`의 MBAP 프레이밍·PDU 처리·예외응답과
`services/attack_defense/flag_service.py`의 플래그 검증(replay·cross-match·expiry 전 분기 테스트됨)은
외부 라이브러리 없이 정확하게 구현돼 있다.

---

## 1. 치명적 결함 (Showstopper)

이 상태로 실제 훈련을 개최하면 훈련이 중단되거나 결과가 무효화되는 항목이다.
각 항목에 **발생 시나리오**를 붙였다.

### S-1. 플랫폼이 격리 상태를 측정하지 않고 "안전"을 출력한다 — 허위 보증

| 근거 | 내용 |
|---|---|
| `services/range_control/main.py:308-321` | `/safety/status`가 `internet_egress: "BLOCKED"`, `docker_socket_exposure: "NONE"`, `unauthorized_destination_attempts: 0`을 **하드코딩 상수**로 반환. 항상 `range_containment_score: 100%` |
| `services/range_control/main.py:263` → `shared/safe_probe.py:20-22` | `verify-baseline`이 호출하는 프로브의 타깃이 **하드코딩 `localhost`**. 컨테이너 내부 실행 시 전량 연결 실패 |
| `shared/safe_probe.py:291-292` | 연결 실패 항목은 결과 목록에서 제외 → `summary.patched == 0` |
| `services/range_control/main.py:274,283` | 그 결과가 `passed=True`, "✅ 다음 훈련 시작 가능"으로 렌더 |
| `docker-compose.yml:1056` | 실제로는 `ad_team_access`에 `internal:` 지시자가 없어 A/D 팀 서비스 6개가 인터넷 egress 가능 |

**발생 시나리오.** 교관이 훈련 개시 전 Control Tower에서 격리 상태 100%를 확인하고 GO를 낸다.
라운드 1 종료 후 `verify-baseline`을 눌러 "다음 훈련 시작 가능"을 받고 라운드 2를 연다. 실제로는
두 검사 모두 아무것도 측정하지 않았다. 참가자가 제출한 패치 이미지(`ad_team_*` 서비스)는 처음부터
인터넷으로 나갈 수 있었고, 훈련 종료 후 외부 통신 로그가 발견되어 사고 조사가 시작된다. 이때
플랫폼 로그에는 전 구간 "격리 100%"만 남아 있어 **언제부터 뚫려 있었는지 입증할 수 없다.**

### S-2. Live Fire 채점 계통이 무인증이고 참가자 네트워크에서 도달 가능하다

| 근거 | 내용 |
|---|---|
| `services/event_collector/main.py:128-129` | `ingest_event(event: Event)` — `authorization` 파라미터 자체가 없음 |
| `services/scoring_engine/main.py:142-143` | `score_ingest(event)` 게이트 없음. `:271` 주석이 "내부 S2S라 보호 대상 아님"이라고 명시적으로 포기 |
| `docker-compose.yml:30,32` | event_collector가 `ports: ["8010:8010"]` + 11개 `twin_*` internal 망에 **동시 소속** |
| `docker-compose.yml:39` | scoring_engine `ports: ["8020:8020"]` |
| `infra/gateway/nginx.conf:46-47` | `auth_request`만 통과하면 red/blue/observer 누구나 `/api/events/`·`/api/scoring/`에 POST 가능. location에 역할 조건 없음 |
| `services/power_plant/main.py:315,343,364,398` | 팀 귀속이 `x_team_id: str = Header(default="default")` — 클라이언트 헤더 |

**발생 시나리오.** 참가자가 트윈 한 대를 장악한다(그것이 훈련 목표다). 그 컨테이너는 event_collector와
같은 `twin_*` 망에 있다. `curl -XPOST http://event_collector:8010/events`로 `X-Team-Id`를 자기 팀으로
바꾼 임의 성공 이벤트를 주입한다. 인증이 없으므로 전부 통과한다. 동시에 상대 팀 ID로 실패 이벤트를
넣어 상대를 감점시킬 수도 있다. 훈련 종료 후 이의제기가 들어오면 — **점수 조정 이력에 actor도 reason도
기록되지 않으므로**(`services/scoring_engine/main.py:272-284`, `require_role` 반환 Identity 미사용,
`reason` 검증 후 폐기, INSERT에 actor/reason 컬럼 없음) — 어느 점수가 정당한지 판별할 방법이 없다.
**이 계통으로 채점된 훈련 결과는 사후 이의제기를 견딜 수 없다.**

### S-3. 56개 챌린지의 플래그를 전량 위조할 수 있다

| 근거 | 내용 |
|---|---|
| `challenges/*/grader/red_grader.py:14` 외 56개 파일 | `os.environ.get("CHALLENGE_SECRET", "ai000-dev-secret")` — 기본값이 저장소에 평문 |
| `docker-compose.yml:504-508` | challenge_portal env에 `CHALLENGE_SECRET` **부재** → 기본값 강제 사용 |
| `services/challenge_portal/main.py:186-189,261` | 제출 API에 인증 파라미터 없음. 본문의 `team_id`를 그대로 신뢰 |
| `services/challenge_portal/Dockerfile:8` | `COPY challenges/` — `solution/exploit.py`·`writeup.md`가 참가자 접점 컨테이너에 동봉 |

**발생 시나리오.** 참가자가 저장소(또는 컨테이너 내부 `/app/challenges/`)에서 `red_grader.py`를 읽어
`CHALLENGE_SECRET` 기본값과 HMAC 산식을 확보한다. 팀별 동적 플래그가 HMAC 기반이므로
(`challenges/ai/AI-002/deploy/generate_artifact.py:16-17`) **문제를 풀지 않고 전 팀·전 문제의 플래그를
계산**할 수 있다. 제출 API가 무인증이고 `team_id`를 본문에서 받으므로 타 팀 명의 제출도 가능하다.
동봉된 `solution/exploit.py`까지 있으므로 정답 경로 자체가 노출된다. 담합 탐지
(`services/challenge_portal/anticheat.py:86-91`)는 목록만 반환하고 `passed`를 뒤집지 않아
(`main.py:301-311`) 담합 팀 전원이 그대로 득점한다.

### S-4. 기본 시크릿 + fail-open으로 인증 체계 전체가 무력화된다

| 근거 | 내용 |
|---|---|
| `docker-compose.yml:188,242,341` | `AUTH_JWT_SECRET:-demo-jwt-secret-change-before-production-32bytes` — 공개 기본값 |
| `docker-compose.yml:42` | `INSTRUCTOR_TOKEN:-dev-instructor-token` |
| `shared/rbac.py:92-94,135-136` | 토큰·JWT 시크릿이 모두 없으면 `role="instructor", dev_mode=True` 반환 후 **모든 역할 검사 스킵** |
| `docker-compose.prod.yml:14,36` vs `:31,38,40,42,44,46,48,50,52` | prod에서 fail-fast(`:?`)는 2개뿐. 나머지 9곳은 `${AUTH_JWT_SECRET}` 기본값·검증 없음 |

**발생 시나리오.** 두 경로가 있다. (a) `.env` 없이 기동하면 fail-open으로 전원이 instructor가 된다.
(b) `.env`를 만들었지만 일부 키를 채우지 않으면 prod에서 event_collector만 부팅 실패하고 scoring·edr·
instructor는 **빈 시크릿으로 조용히 뜬다** — 서비스마다 다른 시크릿을 보는 반쪽 기동이다. 어느
경우든 참가자가 기본 시크릿으로 JWT를 위조해 임의 `team_id`와 instructor 역할을 획득한다.

### S-5. 팀 간 격리가 없다

| 근거 | 내용 |
|---|---|
| `docker-compose.yml:425,434,443,452,461,470` | 팀 서비스 6개가 전부 `networks: [ad_team_access, ad_game_attack, ad_management]` |
| `docker-compose.yml:316,415` | `ad_postgres`·`ad_registry`도 `ad_management` 소속 |
| `docker-compose.yml:361`, `.env.example:47` | K8s NetworkPolicy는 `GAME_RUNTIME=kubernetes`에서만. 기본값은 `docker_compose` |
| `docker-compose.yml:494,565,582,596,677~1033` | `siem_logs` 볼륨을 34개 컨테이너가 **rw**로 마운트(`siem_api`만 `:ro`, `:106`) |

**발생 시나리오.** 01팀이 자기 취약 서비스를 장악한 뒤 같은 L3 세그먼트에 있는 02·03팀 컨테이너,
게임 DB(`ad_postgres`), 이미지 레지스트리(`ad_registry`)에 직접 접근한다. DEF CON A/D에서는 팀 간
공격이 게임의 일부지만, **관리 평면(`ad_management`)에 참가자 코드가 함께 있는 것**은 게임이 아니라
플랫폼 붕괴다. 레지스트리를 장악하면 타 팀 패치 이미지를 바꿔치기할 수 있다. 별도로 `siem_logs`가
34개 컨테이너에 rw로 공유되므로, 트윈 1대만 잡아도 **전 섹터 탐지 로그를 위조·삭제**할 수 있다 —
네트워크 격리를 우회하는 out-of-band 통로다.

### S-6. clean 호스트에서 레인지가 기동하지 않는다

| 근거 | 내용 |
|---|---|
| `scripts/bootstrap_attack_defense_demo.py:9`, `services/attack_defense/cli.py:11` | `dotenv` 임포트 |
| `requirements.txt:1-12`, `requirements-dev.txt:1-4` | `python-dotenv` **없음** |
| `scripts/training_environment.py:271-276` | 실패 핸들러가 스택 전체를 내림 |

**발생 시나리오.** 훈련 당일 새 호스트에 저장소를 클론하고 문서대로 `pip install -r requirements.txt`
후 `./training up`을 실행한다. 3단계 bootstrap에서 `ModuleNotFoundError: dotenv`로 죽고, 실패 핸들러가
방금 올린 75개 컨테이너를 전부 내린다. `make beginner-defense`도 같은 경로로 죽는다. 어떤 문서에도
`pip install python-dotenv`가 적혀 있지 않으므로 원인 파악에 시간이 걸린다. 추가로 node/npm 설치와
`.env` 수동 생성(`scripts/gen_secrets.sh`)도 문서화되지 않은 선행 조건이다.

### S-7. 크로스오버 시나리오 3종이 완주 불가능하고 우회 수단이 없다

| 근거 | 내용 |
|---|---|
| `services/scenario_engine/runner.py:195` | `submit_objective` 호출자 **0건** |
| `services/scenario_engine/api.py:123-258` | 목표 제출 엔드포인트 없음 |
| `services/scenario_engine/loader.py:33-38` | `CrossoverObjective`에 expected 필드 없음 |
| `scenarios/crossover/XOVER-IT-OT-PIVOT-01.yaml:64-73` | 정답이 **YAML 주석**으로만 존재 |
| `services/scenario_engine/api.py` 전체 | force-unlock/skip 엔드포인트 없음 |

**발생 시나리오.** 훈련 2시간차, 팀이 크로스오버 시나리오 phase 1을 완료하고 목표를 제출하려 한다.
제출할 API가 없다. 채점기는 정답을 모른다(주석에만 있음). 시나리오가 phase 1~2에서 영구 정지하고,
교관이 강제로 다음 단계로 넘길 수단도 없다. **해당 팀의 훈련 후반부 전체가 소실된다.**
단일 시나리오도 마찬가지로 stage 우회 경로가 없어(A14), 한 stage에서 막히면 그 팀은 끝이다.

### S-8. 이벤트가 조용히 유실되고 점수가 소리 없이 사라진다

| 근거 | 내용 |
|---|---|
| `shared/event_client.py:52-55` | `requests.post(timeout=1.5)` 후 `except RequestException: pass` |
| `services/event_collector/main.py:162,199-201` | fire-and-forget `asyncio.create_task`, `except httpx.HTTPError: pass`. 재시도·DLQ·백필 없음 |
| `services/scoring_engine/main.py:297-334` | `reconcile`이 `achievements` 합계 vs `team_scores`만 비교. `events.db`와 대조하지 않음 |
| `shared/sse_bus.py:54-55` | `except QueueFull: pass` — 드롭 카운터·로그 전무 |
| `services/siem/api/main.py:130` → `storage/sqlite_backend.py:68-72` | `async` 함수 내부에서 **동기** `connect→INSERT×2→commit→close` |
| `services/{event_collector,scoring_engine,config_service}/main.py`, `siem/storage/{sqlite_backend,alert_store}.py` | 전부 맨몸 `sqlite3.connect()` — WAL 없음, 쓰기 직렬화 + 커밋마다 fsync |

**발생 시나리오.** 관전자가 늘어 SSE 팬아웃과 폴링(관전자 100명 기준 약 163 RPS)이 겹치는 구간에서
scoring_engine의 SQLite 쓰기가 fsync로 밀린다. 응답이 1.5초를 넘기는 순간부터
`shared/event_client.py:52-55`가 예외를 삼키고 **그 구간의 이벤트가 영구 소실**된다. 로그도 카운터도
남지 않는다. `reconcile`은 events.db를 보지 않으므로 이 상태를 "정상"으로 보고한다. 훈련이 끝난 뒤
팀이 "우리 공격이 점수에 안 들어갔다"고 이의를 제기해도 **유실 여부를 확인할 데이터가 없다.**

### S-9. A/D 훈련 전체가 SIEM 사각지대이고, 트래픽 귀속이 불가능하다

| 근거 | 내용 |
|---|---|
| `docker-compose.yml:223-250` | attack_defense에 `siem_logs` 볼륨 없음. A/D용 Suricata/Zeek 사이드카 0건 |
| `infra/twin_gateway/gs.conf:9-12` + `shared/siem_access_log.py:78` | X-Forwarded-For 미설정 + `request.client.host` → **모든 src_ip가 게이트웨이 IP** |
| `services/siem/ingestion/file_tailer.py:39` + `parsers/zeek.py:61-63` | 최초 오픈 시 `seek(0, SEEK_END)` → Zeek `#fields` 헤더 유실 시 다음 로테이션(기본 1시간)까지 Zeek 이벤트 0건 |
| `docker-compose.yml:98` vs `rules/app_layer.yaml` | `INCIDENT_MIN_SEVERITY=5`인데 app_layer 최고 severity=4 → 27룰(CMDI·역직렬화·PLC write 포함) 전부 인시던트 미승격. 승격 대상은 52룰 중 11개뿐 |

**발생 시나리오.** Blue 팀이 SIEM 앞에 앉는다. A/D 취약 서비스에 대한 공격은 로그가 한 줄도 없다.
트윈 공격은 보이지만 **모든 출발지 IP가 게이트웨이 IP 하나**로 찍혀 어느 팀이 공격했는지 알 수 없고,
src.ip 기반 threshold·sequence 룰이 전부 무의미해진다. 컨테이너 기동 타이밍에 따라 Zeek 이벤트가
1시간 통째로 비어 있을 수 있다. 웹 계열 고위험 탐지는 인시던트로 승격되지 않아 Control Tower에
뜨지 않는다. **Blue 훈련이 성립하지 않는다.**

### S-10. 훈련 중 사고가 나도 되돌릴 수단이 없고, 라운드 2가 라운드 1에 오염된다

| 근거 | 내용 |
|---|---|
| `services/range_control/main.py:43-48` | 리셋 대상이 event_collector·scoring_engine·config_service·challenge_portal **4개뿐** |
| `services/incident/main.py:261`, `services/injects/main.py:292` | `/admin/reset`이 **구현돼 있는데 호출되지 않음** |
| `services/range_control/main.py:206-213` | "스냅샷"이 카운터 2개. restore 엔드포인트 부재 |
| `services/attack_defense/patch_pipeline.py:590-596`, `service_fabric.py:115-125` | 팀 롤백이 이미지만 교체. `ad_team_XX_notes_data` 볼륨 유지 |
| `services/attack_defense/game_engine.py:138-147` | `pause_match`만 `ends_at` 보정. 크래시 다운타임 보정 경로 없음 |
| `services/range_control/main.py:292,359-367` | `/safety/team-pause`가 메모리 set에 기록만. 소비자 0건 |

**발생 시나리오.** 훈련 3시간차에 tick 프로세스가 죽고 30분 뒤 재기동한다. 매치는 재개되지만
(`api.py:200-249`) 다운타임이 보정되지 않아 `now >= ends_at`이 되어 **라운드가 체커를 한 번도 못
돌리고 즉시 종료·채점**된다. 교관이 라운드를 되돌리려 하지만 스냅샷 복원 경로가 없다. 전면
리셋(`down -v`)밖에 없고 그러면 전 팀 점수가 날아간다. 부분 리셋을 쓰면 SIEM·EDR·incident·injects가
리셋 대상이 아니어서 라운드 1의 알림과 티켓이 그대로 남아 **라운드 2의 Blue 채점이 오염**된다.
공격자가 심은 웹셸은 데이터 볼륨에 있어 이미지 롤백 후에도 살아남는다.

### S-11. 컨트롤 플레인에 자원 상한이 없어 OOM이 호스트 전체를 죽인다

| 근거 | 내용 |
|---|---|
| `docker-compose.yml:11-20` 앵커 | `<<: *ad-service-security` 상속 서비스는 **7개뿐**(전부 `ad_team_*`) |
| `docker-compose.yml:23-33,85-108,773-795` | event_collector·siem_api·suricata/zeek 정의에 `mem_limit` 없음 |
| `infra/hardening/docker-compose.hardening.yml:54-60` | 상한을 주는 유일한 경로. **siem_api는 여기에도 없음** |
| `scripts/training_environment.py:220`, `Makefile:19,30` | 하드닝 오버레이를 `-f`로 로드하는 기동 경로 **0건** |
| grep 결과 | `retention`/`rollover`/`vacuum`/`purge` 전 저장소 0건. logrotate 미설정 |

**발생 시나리오.** 8시간 훈련 중 SIEM SQLite와 `siem_logs` 볼륨이 상한 없이 성장한다. 보존·롤오버
코드가 없다. suricata/zeek 22개 컨테이너도 메모리 상한이 없다. 부하가 몰리는 후반부에 siem_api가
호스트 메모리를 잠식하고 OOM killer가 **무관한 컨테이너를 죽이기 시작**한다. 하드닝 오버레이가
있지만 어떤 기동 경로에서도 로드되지 않으므로 이 시나리오는 기본 배포에서 그대로 성립한다.

---

## 2. 2차 결함 (훈련은 진행되나 품질·방어가능성이 훼손됨)

| # | 결함 | 근거 | 영향 |
|---|---|---|---|
| T-1 | 물리 파국이 점수에 미연결 | `asset_compromised` 소비 지점이 scoring_engine에 없음 (B축) | ICS 훈련의 최종 목적(물리 피해)이 채점에 반영되지 않음 |
| T-2 | Modbus가 배포상 도달 불가 | B축 판정 | 유일한 실 프로토콜을 참가자가 못 씀 |
| T-3 | 실 프로토콜이 3종뿐 | Modbus 502 / SMTP 25 / syslog 1514. OPC UA·DNP3·61850·S7·SMB·Kerberos·LDAP·Docker API·kubelet 전부 JSON 스텁 | 실툴(plcscan·GetUserSPNs·opcua-client) 사용 불가 |
| T-4 | 위성 지상국에 TT&C·CCSDS 없음 | `services/ground_station/main.py` 400 LOC 전수. CCSDS 문자열 0건 | 위성 도메인이 웹 취약점 세트(pickle·SSRF·XXE·경로순회) |
| T-5 | 인젝트 엔진 사실상 부재 | `services/injects/main.py` 302L에 스케줄러 없음, `scenarios/**/*.yaml`에 `inject` 키 0건, 대시보드 참조 0건 | NIST SP 800-84 TT&E 핵심 장치 없음. 교관 수동 API 호출만 |
| T-6 | 힌트 체계 미전달 | `shared/challenge_schema.py:37,47` 모델만. `challenge_portal/main.py:161-166` `_public()`에서 제외 | 힌트 25개(비용 5~70)가 전달도 차감도 안 됨 |
| T-7 | 부분점수 미반영 | `challenge_portal/main.py:315` — grader `got` 무시하고 만점 부여 | 필드 1개만 맞춰도 만점. 18개 그레이더 영향 |
| T-8 | 배점 상한 불일치 | FOR-003(55 vs 50), ICS-006(130 vs 120), NET-001(60 vs 50), NET-003(55 vs 50) | 광고 배점 도달 불가 |
| T-9 | Blue 채점 2,080점 미도달 | `challenge_portal/main.py:428` | 선언 3,280점 중 DET 1,200점만 유효 |
| T-10 | ICS 챌린지 11개가 동일 템플릿 | `challenges/ics/ICS-002~012/solution/exploit.py` | 1문제 풀면 나머지 10개는 프로토콜명만 다른 반복 |
| T-11 | ATT&CK 히트맵 "발생" 축 상시 공백 | `aar_report/attack_heatmap.py:31-39` vs `metadata.mitre` 발행 0건 | 갭 분석 무의미 |
| T-12 | ICS Impact 전술 미표현 | `T0879/T0880/T0826/T0837/T0813/T0815` 저장소 0건 | 물리 피해가 프레임워크상 부재 |
| T-13 | Lateral Movement 문제 1개 | `challenges/network/NET-002/challenge.yaml:8` (T1021 유일) | IT→OT 피벗 표방 대비 결정적 결손 |
| T-14 | Sigma 로더 데드코드 | `sigma_loader.py` 호출부 0건, condition은 `selection`만 지원 | 공개 Sigma 룰셋 사용 불가 |
| T-15 | `SEQ-KILLCHAIN-001` 영구 미발화 | `NormalizedEvent`에 `event_type` 필드 없음(`shared/siem_schema.py:25-53`) | 킬체인 상관 룰 사망 |
| T-16 | 비콘 allowlist 무효 | `periodicity_rules.yaml` allowlist는 서비스명, 비교 대상은 `dst.ip`(`engine.py:235,238`) | 플랫폼 헬스 폴링이 C2로 오탐 |
| T-17 | EDR 5초 미만 프로세스 미탐지 | `shared/edr_agent.py:30` `_POLL_INTERVAL_SEC = 5`, 신규 pid만 평가 | `sh -c 'cat /flag'` 영구 미탐지 |
| T-18 | EDR isolate가 L3 격리 아님 | `shared/ics_twin.py:69-70` — 앱 레이어 503 반환 | 격리 우회 가능 |
| T-19 | NOC 자산 9종 누락 | `noc_monitor/api/main.py:186-190` — 3개만 등록 | 트윈 12종 중 9종 헬스·복구 판정 없음 |
| T-20 | AAR·instructor audit 무인증 | `aar_report/main.py` `require_role` 0건 + `docker-compose.yml:143`(8090 공개); `instructor_api/main.py:165-167` authorization 파라미터 없음 | 참가자가 미탐지 기술 목록(정답 힌트)·교관 개입 사유 열람 |
| T-21 | AAR PDF 전량 소실 | `aar_report/main.py:36` `/tmp/aar_reports`, compose에 volumes 절 없음 | 컨테이너 재생성 시 산출물 소멸 |
| T-22 | 타임라인 재구성 불가 | AAR이 event_collector만 조회. A/D 감사이벤트·챌린지 제출·SIEM 원시로그 미조회. NTP 없음, 순서 타이브레이크 없음 | "공격이 먼저였나 탐지가 먼저였나"가 조회마다 달라짐 |
| T-23 | PCAP 자동 캡처 없음 + 원본 폐기 | `infra/suricata/suricata.yaml:16-27`에 `pcap-log` 없음. `pcap_privacy.py:610` sanitize본만 기록 | 원시 증거 부재 |
| T-24 | 개인 단위 평가 불가 | `Event` actor가 red/blue/system 3값 enum(`shared/event_schema.py:50-53`) | 개인 수료증·성적표 발급 불가 |
| T-25 | NICE/KSA 매핑 0건 | 전수 grep 0 | 역량 평가가 아니라 점수 집계 |
| T-26 | `latest` 태그 22곳 + digest 미고정 | `docker-compose.yml` | 한 달 뒤 재배포 시 Suricata/Zeek 엔진이 달라져 채점 재현성 붕괴 |
| T-27 | 탐지형 챌린지 13종 비결정적 | `challenges/detection/DET-000/deploy/generate_datasets.py:13,28` 등 `t0 = time.time()` | 사후 이의제기 시 "그때 그 데이터셋" 복원 불가 |
| T-28 | restart 정책 8개뿐, healthcheck 2개뿐 | `docker-compose.yml:20,315,381,400` / `:309,373` | 호스트 재부팅 시 자동 복귀 없음, 부팅 경합 잔존 |
| T-29 | 팀별 아티팩트 공용 경로 덮어쓰기 | `challenge_portal/main.py:237-252` | 동시 요청 시 타팀 아티팩트 배포 |
| T-30 | 체커 시크릿 전 팀 공유 | `docker-compose.yml:422-423` 앵커 재사용. 팀별 파생은 K8s에서만 | 한 팀이 토큰 확보 시 전 팀 체커 위조 |

---

## 3. CCE / DEF CON CTF 기준 갭

실전 대회 대비 **결정적으로 빠진 요소**만 적는다.

| # | 요소 | 대회 표준 | 현 상태 | 근거 |
|---|---|---|---|---|
| G-1 | 채점 인프라의 참가자망 분리 | 채점망은 물리/논리 분리, 참가자 도달 불가 | event_collector가 11개 트윈망에 동시 소속 + 무인증 | `docker-compose.yml:30,32` |
| G-2 | First Blood | DEF CON·CCE 공통 필수 | **코드 0건** | `first_blood` 전수 grep 0 |
| G-3 | 동점 처리 규칙 | 사전 공표된 결정론적 타이브레이크 | Live Fire 계통 미구현. A/D만 암묵 구현 | `attack_defense/scoring.py:344-346` |
| G-4 | 통합 리더보드 | 단일 순위표 | 채점 계통 3개가 서로 다른 저장소에 기록, 통합 없음 | C축 §0 |
| G-5 | 점수 조정 감사 추적 | 누가·언제·왜를 불변 기록 | actor·reason 컬럼 없음, admin_reset은 DELETE 후 카운트만 | `scoring_engine/main.py:272-284,339-352` |
| G-6 | 플래그 서명·팀별 시크릿 분리 | 팀별 파생 키 | 전 팀 공통 기본 시크릿 | `docker-compose.yml:504-508` |
| G-7 | SLA 체커의 실경로 검증 | 체커는 대회 전 실부하 검증 | 테스트가 전량 Fake 대체, `HttpFlagInjector`·`HttpWorkflowChecker` 인스턴스화 0회 | `tests/attack_defense/fakes.py:14-49` |
| G-8 | 라운드 다운타임 보정 | 필수(중단 시 시간 연장) | 크래시 보정 경로 없음 | `game_engine.py:138-147` |
| G-9 | 팀 환경 개별 롤백(데이터 포함) | 필수 | 이미지만 교체, 데이터 볼륨 유지 | `service_fabric.py:115-125` |
| G-10 | 인젝트 기반 상황 부여 | Locked Shields 핵심 | 시간/조건 트리거·콘텐츠·UI 전부 부재 | H축 H1~H6 |
| G-11 | 배경 트래픽 | 탐지 훈련 전제 | 생성기는 있으나 기본 비활성, SIEM 이벤트만 합성(네트워크 계층 아님) | `docker-compose.yml:99` |
| G-12 | 부하 실측 | 대회 전 필수 | 실행 결과 0건. `test_load_profile.py`는 순차 100회 호출 | `tests/attack_defense/test_load_profile.py:8-19` |
| G-13 | 공급망 게이트 | 취약 서비스 포함 저장소는 필수 | trivy·semgrep·bandit·pip-audit·SBOM 0회 | `.github/workflows/ci.yml` 128줄 |
| G-14 | 원시 증거(PCAP) 보존 | 이의제기 대응 필수 | 자동 캡처 없음, 원본 폐기 | `infra/suricata/suricata.yaml:16-27` |

---

## 4. 우선순위 매트릭스 (영향도 × 구현 비용)

```
                    구현 비용 낮음 (≤2일)              구현 비용 높음 (>2일)
        ┌──────────────────────────────────┬──────────────────────────────────┐
        │ ■ 즉시 실행 (QUICK WIN)          │ ■ 계획 수립 (MAJOR PROJECT)      │
        │                                  │                                  │
 영향도 │ S-6 python-dotenv 추가           │ S-2 채점 계통 인증·망분리        │
  높음  │ S-3 CHALLENGE_SECRET 강제 주입   │ S-5 팀 간 격리(NetworkPolicy)    │
        │ S-4 기본 시크릿 제거·fail-fast   │ S-7 크로스오버 제출 API·정답키   │
        │ S-1 하드코딩 안전상태 제거       │ S-8 이벤트 전달 신뢰성(큐·DLQ)   │
        │ S-11 mem_limit·하드닝 -f 적용    │ S-9 SIEM 커버리지(A/D·XFF·Zeek)  │
        │ T-20 AAR·audit 인증 추가         │ S-10 스냅샷·복원·다운타임 보정   │
        │ T-21 AAR PDF 볼륨               │ T-22 통합 타임라인               │
        │ A19 Dockerfile에서 solution 제외 │ T-1 물리 파국 → 채점 연결        │
        │ G15 INCIDENT_MIN_SEVERITY 조정   │ T-3 실 프로토콜 확장(OPC UA 등)  │
        │ T-15 SEQ 룰 필드 수정            │ G-12 부하 실측 하네스            │
        │ T-16 비콘 allowlist 수정         │                                  │
        ├──────────────────────────────────┼──────────────────────────────────┤
        │ ■ 여유 시 처리 (FILL-IN)         │ ■ 보류 (THANKLESS)               │
        │                                  │                                  │
 영향도 │ T-8 배점 상한 정합               │ T-4 위성 TT&C/CCSDS 실구현       │
  낮음  │ T-17 EDR 폴링 주기 단축          │ T-25 NICE 프레임워크 매핑        │
        │ T-19 NOC 자산 등록 보완          │ T-24 개인 단위 평가 스키마 개편  │
        │ T-26 이미지 digest 고정          │ T-10 ICS 챌린지 재저작 11종      │
        │ T-27 탐지형 시드 고정            │ T-14 Sigma 완전 지원             │
        │ T-28 restart·healthcheck 보완    │ T-5 인젝트 엔진 전면 구현        │
        └──────────────────────────────────┴──────────────────────────────────┘
```

**해석.** 좌상단(QUICK WIN) 11건은 전부 설정·상수·데코레이터 수준이고 합계 2주 이내다.
이것만 처리해도 S-1·S-3·S-4·S-6·S-11이 해소되어 **"훈련이 아예 안 뜨거나 결과가 즉시 무효화되는"
등급은 벗어난다.** 우상단은 아키텍처 변경이라 4주 계획에서 착수만 하고 완료는 그 이후다.

---

## 5. 다음 4주 실행 계획

각 항목에 **DoD(완료 판정 기준)**를 명시했다. DoD는 전부 자동 검증 가능한 형태로 적었다.

### 1주차 — "허위 보증 제거 + 기동 복구"

목표: 플랫폼이 거짓말을 멈추게 하고, clean 호스트에서 뜨게 한다.

| # | 작업 | DoD |
|---|---|---|
| 1.1 | `requirements.txt`에 `python-dotenv` 고정 추가 | CI에 "clean 컨테이너에서 `pip install -r requirements.txt` 후 `python -c 'import dotenv'`" 잡 추가, 녹색 |
| 1.2 | `/safety/status` 하드코딩 제거 | 상수 반환 삭제. 실측 불가 항목은 `"UNKNOWN"` 반환. `grep -n '"BLOCKED"\|"NONE"' services/range_control/main.py` 결과 0건 |
| 1.3 | `safe_probe` 타깃을 env 주입으로 전환 | `shared/safe_probe.py`에 `localhost` 리터럴 0건. 연결 실패 항목이 결과에 `UNREACHABLE`로 **포함**되고, 1건이라도 있으면 `verify-baseline`이 `passed=False` |
| 1.4 | `CHALLENGE_SECRET` 기본값 제거 | 56개 grader에서 기본값 삭제, 미설정 시 `RuntimeError`. `docker-compose.yml` challenge_portal env에 `CHALLENGE_SECRET: ${CHALLENGE_SECRET:?}` 추가. 미설정 기동 시 컨테이너 exit≠0 |
| 1.5 | 기본 시크릿 제거 + prod fail-fast 전면화 | `docker-compose.yml`에서 `:-demo-`·`:-dev-` 기본값 0건. `docker-compose.prod.yml` 전 시크릿 참조가 `:?` 형식. `grep -c ':-dev-\|:-demo-' docker-compose.yml` = 0 |
| 1.6 | `rbac.py` fail-open 제거 | 시크릿 미설정 시 `dev_mode`가 아니라 기동 실패. `tests/unit/test_rbac.py`에 "시크릿 없으면 예외" 케이스 추가, 통과 |
| 1.7 | `challenge_portal/Dockerfile`에서 solution/writeup 제외 | 빌드된 이미지에 `find / -name 'exploit.py'` 결과 0건. CI에서 검사 |
| 1.8 | AAR·instructor audit 인증 추가 | `aar_report`·`instructor_api` 전 엔드포인트에 `require_role`. 무토큰 요청이 401. 계약 테스트로 검증 |

### 2주차 — "격리 실체화 + 자원 상한"

목표: 격리를 문서가 아니라 기동 경로에 넣는다.

| # | 작업 | DoD |
|---|---|---|
| 2.1 | 하드닝 오버레이를 기본 기동 경로에 결합 | `scripts/training_environment.py`·`Makefile` 전 기동 경로가 `-f docker-compose.yml -f infra/hardening/...`. `grep -c 'hardening' scripts/training_environment.py Makefile` ≥ 2 |
| 2.2 | 컨트롤플레인·트윈·센서에 `mem_limit`/`cpus` 부여 | `docker-compose.yml` 전 서비스에 리소스 상한. 상한 없는 서비스 0건을 CI 스크립트로 검증 |
| 2.3 | `ad_team_access`에 egress 통제 | `internal: true` 또는 명시적 egress 프록시. 팀 컨테이너에서 외부 도달 불가를 `infra/ci/isolation_test.py`가 검증 |
| 2.4 | `ad_management`에서 팀 서비스 분리 | 팀 서비스 6개의 networks에서 `ad_management` 제거. `ad_postgres`·`ad_registry` 도달 불가를 isolation_test가 검증 |
| 2.5 | `siem_logs` 공유 제거 | 트윈은 자기 섹터 경로만 마운트하거나 `:ro`. rw 마운트 컨테이너 수 ≤ 12(센서만) |
| 2.6 | `isolation_test.py`·`secret_scan.py` CI 편입 | `.github/workflows/ci.yml`에 두 잡 추가, PR에서 필수 체크. 의도적 취약 챌린지는 allowlist로 분리 |
| 2.7 | 공급망 스캔 도입 | trivy(이미지) + pip-audit + npm audit + bandit을 CI에 추가. High 이상 발견 시 실패. baseline 파일로 기존 이슈 억제 |
| 2.8 | 이미지 태그 고정 | `latest` 22곳을 digest 또는 명시 버전으로. `grep -c ':latest' docker-compose.yml` = 0 |

### 3주차 — "채점 무결성"

목표: 결과가 이의제기를 견디게 한다.

| # | 작업 | DoD |
|---|---|---|
| 3.1 | event_collector·scoring_engine 인증 게이트 | 두 서비스 전 write 엔드포인트에 서비스 토큰 검증. 무토큰 POST가 401. 계약 테스트 통과 |
| 3.2 | 채점망에서 트윈망 분리 | event_collector가 `twin_*` 11개 망에서 이탈. 트윈은 전용 ingest 프록시 경유. isolation_test가 트윈→8010 직접 도달 불가를 검증 |
| 3.3 | 팀 귀속을 서버측 결정으로 전환 | `X-Team-Id` 헤더 신뢰 제거. 토큰/세션에서 team_id 도출. `grep -c 'x_team_id.*Header' services/` 대폭 감소, 잔존분은 화이트리스트 |
| 3.4 | 점수 조정 감사 로그 | `score_adjustments` 테이블에 actor·reason·timestamp·before/after. `admin_reset`은 스냅샷 생성 후 실행. 조정 API 호출 → 감사 레코드 1건 생성을 테스트로 검증 |
| 3.5 | 이벤트 전달 신뢰성 | 예외 삼킴 제거, 재시도 + 실패 시 로컬 스풀(DLQ). 드롭 카운터를 `/metrics`로 노출. scoring_engine 강제 다운 후 복구 시 이벤트 0건 유실을 통합 테스트로 검증 |
| 3.6 | `reconcile`에 events.db 대조 추가 | 이벤트 수 vs achievement 수 불일치를 리포트. 인위적 유실 주입 시 reconcile이 불일치를 탐지 |
| 3.7 | SQLite WAL + busy_timeout 전면 적용 | 컨트롤플레인 5개 저장소 전부 `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout`. `grep -c 'WAL' services/` ≥ 5 |
| 3.8 | scoring_engine 단위 테스트 신규 | 10개 이벤트 타입 분기 전수 + 중복 채점 + 음수 하한 + `_award` 경합. `pytest-cov` 도입 후 `services/scoring_engine` 라인 커버리지 ≥ 80% |
| 3.9 | First Blood·타이브레이크 구현 | 규칙 코드화 + 테스트. 동점 입력에 대해 결정론적 순위 반환 |

### 4주차 — "관제 복구 + 운영 안전망"

목표: Blue 훈련이 성립하고, 사고가 나도 되돌릴 수 있게 한다.

| # | 작업 | DoD |
|---|---|---|
| 4.1 | X-Forwarded-For 전 게이트웨이 설정 | `infra/twin_gateway/*.conf` 11개에 XFF 설정. `shared/siem_access_log.py`가 XFF 우선 사용. SIEM 이벤트의 고유 src_ip 수 > 1을 통합 테스트로 검증 |
| 4.2 | Zeek 헤더 유실 레이스 수정 | `file_tailer.py` 최초 오픈 시 헤더 구간 파싱 후 tail. 컨테이너 재기동 직후에도 Zeek 이벤트 수신을 검증 |
| 4.3 | A/D 스택 SIEM 편입 | attack_defense·팀 서비스에 `siem_logs` + 액세스 로그 미들웨어. A/D 공격이 SIEM에 기록됨을 검증 |
| 4.4 | `INCIDENT_MIN_SEVERITY` 정합 | 임계값을 4로 낮추거나 app_layer severity 재조정. 52룰 중 승격 대상 ≥ 40 |
| 4.5 | 죽은 탐지 룰 복구 | `SEQ-KILLCHAIN-001` 필드 수정, 비콘 allowlist를 IP 기준으로. 각 룰의 발화 테스트 1건씩 추가 |
| 4.6 | 라운드 리셋 범위 확대 | siem·edr·incident·injects·attack_defense를 리셋 대상에 편입(이미 있는 `/admin/reset` 활용). 리셋 후 전 저장소 잔존 레코드 0건 검증 |
| 4.7 | 다운타임 보정 | tick 정지 구간을 `ends_at`에 가산. 강제 크래시 → 재기동 후 라운드 잔여시간이 보존됨을 테스트로 검증 |
| 4.8 | AAR PDF 영속 볼륨 + 보존 정책 | `aar_report`에 volumes 추가. `siem_logs`·events.db에 롤오버/보존 기간 설정. 용량 상한 초과 시 자동 정리 |
| 4.9 | 크로스오버 제출 API + 정답 키 이전 | `submit_objective` 노출, 정답을 주석에서 스키마 필드로 이전. 크로스오버 3종 완주를 통합 테스트로 검증 |
| 4.10 | 부하 하네스 실행 + 기준선 기록 | k6 3종을 CI(nightly)에 편입, 결과를 `loadtest/results/`에 커밋. 수용 인원 기준선 문서화 |

**4주 후에도 남는 것**(별도 계획 필요): 실 프로토콜 확장(OPC UA·DNP3·61850), 위성 TT&C 실구현,
인젝트 엔진 전면 구현, 통합 타임라인, NICE 매핑, 개인 단위 평가, ICS 챌린지 11종 재저작.

---

## 6. UNVERIFIED — 직접 확인이 필요한 항목

도커 미기동 제약으로 정적 분석만으로는 판정할 수 없었던 것들이다. **다음 검증 라운드에서
스택을 기동해 확인해야 한다.** 확인 방법을 함께 적었다.

| # | 항목 | 왜 정적으로 판정 불가 | 확인 방법 |
|---|---|---|---|
| U-1 | Modbus 502 실제 응답 | 리스너 바인딩은 코드로 확인했으나 실제 도달성은 런타임 문제 | 스택 기동 후 호스트에서 `mbpoll -a 1 -r 1 -c 4 <twin> -p 502`. B축이 "배포상 도달 불가"로 판정했으므로 이 결과가 T-2의 최종 판정이 된다 |
| U-2 | 공격 → SIEM → 대시보드 E2E 지연 | 구간별 상수는 추출했으나 실측 없이는 합산이 추정 | tmux 2창: 한쪽에 SSE 스트림(`curl -N .../events/stream`), 다른 쪽에서 Modbus write 주입. 타임스탬프 차이 측정 |
| U-3 | 동시 팀·관전자 수용 한계 | 이론 RPS(163 @ 관전자 100)는 계산했으나 실제 포화점은 측정 필요 | `loadtest/k6/*.js`를 단계적 VU로 실행하며 p95 지연·에러율 기록 |
| U-4 | S-1의 실제 격리 상태 | `/safety/status`가 거짓을 반환하므로 진짜 상태를 모른다 | 팀 컨테이너에서 `curl -m 5 https://1.1.1.1` 및 외부 DNS 질의. `infra/ci/isolation_test.py` 실행 |
| U-5 | Zeek 헤더 레이스의 실제 발생률 | 타이밍 의존 | 스택을 10회 기동하며 Zeek 이벤트 수신 여부 집계 |
| U-6 | OOM 시나리오(S-11) | 8시간 부하 필요 | 축약 부하(1시간)로 메모리 증가 기울기를 측정해 외삽 |
| U-7 | `verify-baseline` 오판정 재현 | H23은 코드 추론 | 컨테이너 내부에서 `range_control`의 verify-baseline 호출 후 반환값 확인 |
| U-8 | A/D 체커의 실 HTTP 경로 | 테스트가 전량 Fake이므로 실경로 미검증 | 팀 서비스를 인위적으로 다운·지연시키고 체커가 `"timeout"`/`"connection"`을 올바로 분류하는지 확인 |
| U-9 | prod 프로파일 기동 성립 여부 | `docker-compose.prod.yml` 경로는 정적 검토만 | `-f docker-compose.yml -f docker-compose.prod.yml config` 후 기동. E4(START HERE·A/D 누락) 확인 |
| U-10 | `AI-009`의 `T1551` 유효성 | ATT&CK 카탈로그 대조 필요 | MITRE ATT&CK Enterprise 최신판에서 T1551 할당 여부 확인 |

**검증 라운드 권고 순서**: U-4 → U-7 → U-1 → U-2 → U-9 → U-8 → U-3 → U-5 → U-6.
U-4와 U-7이 S-1(허위 보증)의 실제 위험도를 결정하므로 최우선이다.

---

## 7. 결론

**현 상태로 실제 훈련을 개최해서는 안 된다.** 근거는 S-6(clean 호스트에서 기동 실패) 하나만으로도
충분하지만, 설령 기동하더라도 S-3(플래그 전량 위조)·S-2(무인증 채점)로 **결과가 훈련 당일에 무효화**되고,
S-1(허위 격리 보증)으로 **안전 사고를 인지조차 못 한다.**

1주차 8개 항목(전부 설정·상수 수준)을 처리하면 "즉시 무효화" 등급은 벗어난다.
3주차까지 완료하면 내부 시연은 가능하다. **대외 공개 훈련은 4주차 완료 + 검증 라운드(§6) 통과가
최소 조건**이다.
