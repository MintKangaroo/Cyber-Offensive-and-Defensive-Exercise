# D축 감사 — 격리·안전성 (Isolation & Safety)

감사 방식: 정적 분석 전용. Docker/make/training/iptables 미실행. 모든 판정은 설정 파일 원문 인용에 근거한다.
기준 레퍼런스: CCE, Locked Shields, DEF CON CTF A/D, NIST SP 800-84.

---

## 1. 요약 판정 테이블

| # | 경계 | 판정 | 근거 (path:line) | 악용 시나리오 |
|---|------|------|------------------|----------------|
| D-1 | 트윈망(11종) → 인터넷 egress | **부분 차단** | `docker-compose.yml:1042-1052` (11개 `internal: true`) | 트윈 자체는 egress 불가. 그러나 D-2의 브리지 컨테이너 경유 경로가 열려 있다 |
| D-2 | 트윈망 → 코어(range_control) 브리지 | **미차단 — 결함** | `docker-compose.yml:32`, `:64`, `:83` (event_collector/config_service/edr_backend가 11개 twin_* + 비-internal `range_control`에 동시 소속) | 트윈에서 코어 3종 중 하나를 장악하면 `range_control`(비-internal, `:1053`) 경유로 인터넷 egress 획득 |
| D-3 | A/D 팀 서비스 → 인터넷 egress | **완전 미차단 — 치명** | `ad_team_access: { driver: bridge }` `docker-compose.yml:1056` (internal 없음), 6개 팀 서비스 `:417-472` | 팀이 제출한 패치 이미지가 그대로 인터넷 아웃바운드 가능 |
| D-4 | 팀 간 격리 (A/B/C 팀) | **없음 — 치명** | 6개 컨테이너 전부 `networks: [ad_team_access, ad_game_attack, ad_management]` (`:425`, `:434`, `:443`, `:452`, `:461`, `:470`) | 01팀 컨테이너가 02/03팀 컨테이너·DB·레지스트리에 L3 직접 도달 |
| D-5 | 훈련망 → 관리망(ad_management) | **미차단 — 치명** | 팀 서비스가 `ad_management` 소속(위와 동일 라인), `ad_postgres:316`·`ad_registry:415`도 동일 망 | 참가자 코드가 관리 평면에 직접 존재 |
| D-6 | 컨테이너 → 하이퍼바이저/도커 탈출 | **직접 경로 없음** | 저장소 전체에 `docker.sock` 바인드마운트·`privileged: true`·`hostPath` 0건 (grep 결과, 아래 3절) | — |
| D-7 | 팀 ID 위조 | **기본 배포에서 가능 — 치명** | `AUTH_JWT_SECRET:-demo-jwt-secret-change-before-production-32bytes` `docker-compose.yml:188,242,341`; 검증 로직 `shared/rbac.py:63-82`, `services/attack_defense/api.py:296-308` | 공개된 기본 시크릿으로 JWT 위조 → 임의 team_id·instructor 역할 |
| D-8 | 트윈 컨테이너 하드닝 | **미적용 — 심각** | `docker-compose.yml`의 `read_only`/`cap_drop`은 `:11-16` 앵커와 `:226-229,293,321,388,407`, 즉 A/D·레지스트리 계열에만. 11종 트윈 서비스 정의(`:555-772`)에 전무. `services/*/Dockerfile`에 `USER` 없음 | 트윈은 root·쓰기가능 rootfs·기본 capability·메모리/PID 무제한으로 기동 |
| D-9 | 하드닝 오버레이 실제 적용 | **경로 없음 — 결함** | `infra/hardening/docker-compose.hardening.yml` 존재하나, `scripts/training_environment.py:220`은 `docker compose up -d` (오버레이 `-f` 없음). `Makefile:19,30`도 없음. 참조는 문서(`infra/hardening/README.md:11`)뿐 | 하드닝은 "문서상 존재", 실행 경로 0 |
| D-10 | 공유 볼륨 `siem_logs` | **횡단 채널 — 심각** | 34개 컨테이너가 rw 마운트(`docker-compose.yml:494,565,582,596,677~1033`), `siem_api`만 `:ro`(`:106`) | 트윈 1대 장악 → 전 섹터 탐지 로그 위조·삭제. 네트워크 격리를 우회하는 out-of-band 통로 |
| D-11 | `/safety/status` 격리 계측 | **하드코딩 — 치명(허위 보증)** | `services/range_control/main.py:308-321` — `"internet_egress": "BLOCKED"`, `"docker_socket_exposure": "NONE"`, `unauthorized_destination_attempts: 0` 전부 상수 | 실제 상태와 무관하게 항상 `range_containment_score: 100%` 표시 |
| D-12 | CI에서 격리·시크릿 게이트 실행 | **미실행 — 결함** | `.github/workflows/ci.yml` 128줄 전체에 `isolation_test`/`secret_scan`/`trivy`/`bandit`/`semgrep` 문자열 0건 (grep 결과 공백) | 격리 회귀가 CI에서 절대 검출되지 않음 |
| D-13 | 실제 악성 바이너리 | **없음 — 적합** | `challenges/reversing/*/challenge.yaml:20-26` 등 전부 `profile: "standard"` + "합성 바이너리… 실행 파일 아님". `find challenges -name "*.exe|*.dll|*.bin|*.elf"` 결과 0건 | — |
| D-14 | K8s NetworkPolicy 적용 | **compose 경로 미적용** | `infra/attack_defense/kubernetes/control-planes.yaml`은 `GAME_RUNTIME=kubernetes`일 때만. 기본값은 `GAME_RUNTIME:-docker_compose` (`docker-compose.yml:361`, `.env.example:47`) | 잘 작성된 default-deny 정책이 기본 배포에서 아무 효력 없음 |
| D-15 | `network-policies.yaml` (legacy) | **적용 금지 문서화됨** | `infra/attack_defense/network-policies.yaml:1-5` "Do not apply this file to a tournament cluster" | 오적용 시 팀별 네임스페이스 격리 없이 단일 ns 정책 |

---

## 2. 네트워크 토폴로지 표

### 2.1 네트워크 정의 (`docker-compose.yml:1038-1061`) — 원문 인용

```yaml
1042:  twin_ground_station: { driver: bridge, internal: true }
...(11종 동일)...
1052:  twin_hospital_ot: { driver: bridge, internal: true }
1053:  range_control: { driver: bridge }
1054:  # Logical A/D planes. Docker Compose cannot enforce directional egress;
1055:  # production NetworkPolicy examples live under infra/attack_defense/.
1056:  ad_team_access: { driver: bridge }
1057:  ad_game_attack: { driver: bridge, internal: true }
1058:  ad_scoreboard_api: { driver: bridge }
1059:  ad_management: { driver: bridge, internal: true }
1060:  # Host-side push/pull path. Game service containers are deliberately absent.
1061:  ad_registry_host: { driver: bridge }
```

**internal 아닌 네트워크: `range_control`, `ad_team_access`, `ad_scoreboard_api`, `ad_registry_host` (4종).**
이 4종에 붙은 컨테이너는 전부 인터넷 egress 가능하다. `:1054-1055` 주석이 스스로 인정하듯 compose 수준 방향성 egress 통제는 **부재**하며, 대체 수단은 K8s 전용이다(D-14).

### 2.2 호스트 포트 publish 전수 (노출 후보)

`127.0.0.1` 바인딩이 없는 것은 전부 `0.0.0.0` — 호스트 네트워크 전체에 노출된다.

| 컨테이너 | 라인 | publish | 바인드 | 소속 networks | 참가자 도달성 |
|---|---|---|---|---|---|
| event_collector | :30 | 8010 | 0.0.0.0 | range_control + twin_×11 | **도달** (호스트 + 전 트윈망) |
| scoring_engine | :47 | 8020 | 0.0.0.0 | range_control | 도달(호스트) |
| config_service | :63 | 8030 | 0.0.0.0 | range_control + twin_×11 | **도달** — 관리 인터페이스가 전 트윈망에 노출 |
| edr_backend | :80 | 8080 | 0.0.0.0 | range_control + twin_×11 | **도달** — 관리 인터페이스가 전 트윈망에 노출 |
| siem_api | :103-104 | 8040, 1514/udp | 0.0.0.0 | range_control | 도달(호스트). syslog UDP는 무인증 주입면 |
| scenario_engine | :120 | 8045 | 0.0.0.0 | range_control | 도달 |
| **instructor_api** | :137 | 8050 | 0.0.0.0 | range_control | **도달 — 교관 API가 호스트에 평문 노출** |
| aar_report | :153 | 8090 | 0.0.0.0 | range_control | 도달 |
| match_proxy | :161 | 8088 | 0.0.0.0 | range_control | 도달 |
| **range_control** | :178 | 8055 | 0.0.0.0 | range_control | **도달 — 긴급정지/안전 제어면** |
| auth | :190 | 8051 | 0.0.0.0 | range_control | 도달 |
| incident | :201 | 8095 | 0.0.0.0 | range_control | 도달 |
| injects | :212 | 8096 | 0.0.0.0 | range_control | 도달 |
| observability | :220 | 8097 | 0.0.0.0 | range_control, ad_scoreboard_api | 도달 |
| **attack_defense** | :237 | 8100 | 0.0.0.0 | range_control, ad_management, ad_scoreboard_api | **도달 — 채점 API + 관리망 브리지** |
| ad_ha_gateway | :393 | 8110 | **127.0.0.1** | range_control, ad_scoreboard_api | 호스트 로컬만 (적합) |
| ad_registry | :406 | 5000 | **127.0.0.1** | ad_management(alias registry.local), ad_registry_host | 호스트 로컬만. **단, ad_management 내부에서는 무인증 도달** |
| ad_team_01/02/03 notes | :421,:440,:458 | 9101/9102/9103 | 0.0.0.0 | ad_team_access, ad_game_attack, ad_management | **도달(설계상 의도)** |
| ad_team_01/02/03 vault | :430,:449,:467 | 9201/9202/9203 | 0.0.0.0 | ad_team_access, ad_game_attack, ad_management | **도달(설계상 의도)** |
| cloud_native | :490 | 8209 | 0.0.0.0 | range_control | 도달 |
| challenge_portal | :503 | 8060 | 0.0.0.0 | range_control | 도달 |
| noc_monitor | :518 | 8070 | 0.0.0.0 | range_control, twin_gs/pp/dn | 도달 |
| 트윈 게이트웨이 11종 | :537,:545,:553,:609,:617,:625,:633,:641,:649,:657,:665 | 8001-8003, 8201-8208 | 0.0.0.0 | range_control + 자기 twin_* 1개 | 도달(설계상 의도) |
| ad_postgres | :316 | 없음 | — | ad_management | 호스트 미도달. **ad_management 내부에서는 도달** |
| attack_defense_ha | :318-382 | `expose` only | — | range_control, ad_management, ad_scoreboard_api | 내부만 |
| ad_patch_sandbox | :474-483 | 없음 | — | ad_management | 내부만 |
| 트윈 본체 11종 | :555-772 | **없음** | — | 자기 twin_* 1개만 | 게이트웨이 경유만 (적합) |
| suricata/zeek 22종 | :773-1037 | 없음 | — | `network_mode: service:<twin>` | 트윈 netns 공유 |

**관리 인터페이스 판정**: `instructor_api`(8050), `range_control`(8055), `config_service`(8030), `edr_backend`(8080), `siem_api`(8040), `attack_defense`(8100), `ad_registry`(ad_management 내부) — 전부 참가자 도달 가능 네트워크에 노출된다. 관리망 전용 세그먼트가 별도로 존재하지 않는다.

### 2.3 게이트웨이 격리 (적합 판정)

`infra/twin_gateway/gs.conf:5-13` — 게이트웨이는 `set $twin ground_station; proxy_pass http://$twin:8001$request_uri;`로 자기 트윈 1개만 대상으로 하고, 자기 twin 네트워크 1개에만 소속(`docker-compose.yml:538`)한다. 게이트웨이 경유 간접 lateral은 차단된다. 이 설계는 타당하다.

---

## 3. 탈출·횡단 경로 목록

### 3.1 전수 grep 결과 (탈출 프리미티브)

| 프리미티브 | 결과 |
|---|---|
| `/var/run/docker.sock` 바인드마운트 | **0건.** 저장소 내 언급은 전부 문서(`USAGE.md:22`, `HANDOFF.md:133`)·검증 로직(`services/attack_defense/network_policy.py:38`, `patch_pipeline.py:294`)·테스트(`tests/attack_defense/test_security.py:367`) |
| `privileged: true` | **compose 0건.** `services/attack_defense/kubernetes_runtime.py:364`은 `"privileged": False` 강제 |
| `cap_add` | **22건 — 전부 suricata/zeek 사이드카**, `["NET_ADMIN","NET_RAW"]` (`docker-compose.yml:777,789,801,813,824,836,850,862,874,886,898,910,922,934,946,958,970,982,994,1006,1018,1030`) |
| `network_mode: service:*` | **22건 — 동일 사이드카** (`:783,795,807,819,831,843,857,869,881,893,905,917,929,941,953,965,977,989,1001,1013,1025,1037` 부근) |
| 호스트 경로 바인드마운트 | 설정 파일 `:ro` 마운트만 (`./infra/twin_gateway/*.conf`, `./infra/suricata/*`, `./infra/zeek/local.zeek`, `./infra/attack_defense/haproxy-ha.cfg`, `./infra/match/match_proxy.conf`). 쓰기 가능 호스트 바인드 **0건** |
| `user: root` / `user: "0"` | **0건.** 명시적 `user`는 `ad_ha_gateway`의 `"99:99"`(`:387`) 뿐 |
| `hostPath` / `/proc:` / `/sys:` | **0건** |

**판정: 참가자가 도커 데몬/호스트를 직접 탈출하는 경로는 발견되지 않는다.** 이 부분은 실제로 방어되어 있다.

### 3.2 실재하는 횡단(lateral) 경로

**경로 A — 트윈 → 코어 → 인터넷 (egress 우회)**

1. 참가자가 게이트웨이(예: 8002)를 통해 `pp_twin`의 취약점(커맨드 인젝션 PP-003)으로 코드 실행 획득.
2. `pp_twin`은 `twin_power_plant`(internal)에만 있으므로 직접 egress는 실패한다.
3. 그러나 같은 네트워크에 `event_collector`·`config_service`·`edr_backend`가 붙어 있다(`docker-compose.yml:32,64,83`).
4. 이 3종은 `range_control`(비-internal, `:1053`)에도 동시 소속 → **인터넷 egress 가능한 컨테이너**다.
5. 코어 서비스 취약점 또는 SSRF성 기능을 통해 외부 호출 유도 → 훈련망 밖으로 데이터 반출.
   추가로 `config_service`는 설정/패치 컨트롤 플레인이며 기본 `INSTRUCTOR_TOKEN=dev-instructor-token`(`:58`)으로 보호된다 → 사실상 무보호.

**경로 B — 팀 서비스 → 관리망 (ad_management)**

1. 팀 A가 A/D 패치 파이프라인으로 자기 이미지를 제출한다. 배포 시 `image: ${AD_IMAGE_AD_TEAM_01_NOTES:-...}`(`:419`)로 **참가자가 통제하는 이미지가 기동**된다.
2. 해당 컨테이너는 `ad_management`에 소속된다(`:425`).
3. `ad_management`에는 `ad_registry`(`:415`, alias `registry.local`)와 `ad_postgres`(`:316`)가 있다.
4. `ad_registry`는 `image: registry:2`에 인증 환경변수가 **전혀 없다**(`:403-416` 전체에 `REGISTRY_AUTH*` 없음) → 익명 push/pull. 팀 A가 타 팀 태그를 덮어써 다음 라운드 배포를 오염시킨다.
5. `ad-ha` 프로파일 사용 시 `ad_postgres` 비밀번호 기본값 `ad-ha-dev-password-change-me`(`:304`) → 채점 DB 직접 조작.
6. `attack_defense` API(`:288`)도 `ad_management`에 있다.

**경로 C — 팀 간 직접 도달 (팀 격리 부재)**

6개 팀 서비스가 `ad_team_access`·`ad_game_attack`·`ad_management` **3개 망을 모두 공유**한다(`:425,434,443,452,461,470`). 도커 임베디드 DNS로 `ad_team_02_vault:9000`이 이름 해석되며, `ad_game_attack`이 internal이어도 **동일 망 내 컨테이너 간 통신은 차단하지 않는다**(`internal`은 외부 egress만 막는다). 팀 A 컨테이너가 팀 B의 인프라·데이터 볼륨 서비스에 직접 접속한다. `docker-compose.yml:1054-1055` 주석이 이를 스스로 인정한다.

**경로 D — 공유 볼륨 `siem_logs`를 통한 전 섹터 횡단**

11종 트윈 + `cloud_native` + 22종 센서가 `siem_logs`를 **쓰기 가능**하게 마운트한다(총 34건). 어느 한 트윈을 장악하면 다른 모든 섹터의 Suricata/Zeek 로그를 삭제·위조할 수 있다. `siem_api`만 `:ro`(`:106`)이므로 SIEM은 오염된 입력을 그대로 채점한다. **네트워크 격리(internal:true)를 완전히 우회하는 공유 상태 채널이다.**

**경로 E — JWT 위조에 의한 권한 상승**

`AUTH_JWT_SECRET` 기본값이 `demo-jwt-secret-change-before-production-32bytes`로 **저장소에 평문 커밋**되어 있다(`docker-compose.yml:188,242,341`). `shared/rbac.py:63-82`가 이 시크릿으로 HS256 JWT를 검증하고 `team_id`/`role` 클레임을 그대로 신뢰한다. 참가자는 임의 `team_id`·`role: "instructor"` JWT를 서명해 타 팀 인스턴스 조회(`api.py:1169`), 플래그 제출 귀속 조작(`api.py:1242`), 패치 제출(`api.py:1311`)을 수행할 수 있다.

> 팀 ID가 `X-Team-Id` 헤더로만 구분되는지 확인했다 — **그렇지 않다.** `team_id`는 서명된 JWT 클레임에서만 온다(`shared/rbac.py:79`, `api.py:301-308`). 헤더 위조는 불가하다. 위조 가능성의 원인은 **기본 시크릿 공개**이지 헤더 신뢰가 아니다. 이 점은 설계상 올바르며, 시크릿만 교체하면 닫힌다.

### 3.3 사이드카 위험도 판정

`cap_add: ["NET_ADMIN","NET_RAW"]` + `network_mode: service:<twin>` 22종:

- **위험도: 중.** NET_ADMIN은 트윈의 네트워크 네임스페이스 내에서 iptables/route 조작을 허용한다. 사이드카가 트윈보다 먼저 침해되면 해당 트윈망의 트래픽을 조작할 수 있으나, 네임스페이스가 internal이므로 호스트 방화벽에는 도달하지 못한다.
- **단, 사이드카에는 `read_only`·`cap_drop`·`pids_limit`·`mem_limit`·`user`가 하나도 없다**(`:773-1037` 전 구간에 해당 키 부재 — 2절 grep 결과와 일치). root + 쓰기 가능 rootfs로 기동된다. IDS를 root로 돌리는 것은 패킷 파서 취약점(Suricata/Zeek는 역사적으로 다수 존재)이 곧 컨테이너 root 실행을 의미한다.
- `services/attack_defense/network_policy.py:34`는 `cap_add`가 있으면 무조건 `capability_add_forbidden`으로 판정한다. **즉 플랫폼 자신의 정책 검증기가 자기 compose를 위반으로 판정한다.** 그러나 이 검증기는 compose에 대해 실행되지 않는다(43 LOC, A/D 패치 이미지 스펙 전용).

---

## 4. 자격증명 스캔 결과

### 4.1 의도적 취약 시드 (결함 아님 — 훈련 설계)

| 값 | 위치 | 판정 |
|---|---|---|
| `JWT_SECRET = "supersecret123"` | `services/ground_station/main.py:72` | 의도적. GS-002 챌린지, 주석에 "훈련용 취약 시크릿" 명시. `infra/ci/secret_scan.py:31` 허용리스트 등록됨 |
| `admin123`, `operator`, `B@ckup2019!` | 트윈 더미 계정 | 의도적. `infra/ci/secret_scan.py:32` 허용리스트 |
| challenges/ 하위 플래그·시드값 | 팀별 HMAC 더미 | 의도적. `challenges/*/*/challenge.yaml`의 `safety.notes`에 문서화 |

### 4.2 컨트롤 플레인 실제 기본 비밀번호 (**전부 결함**)

`docker-compose.yml`의 `${VAR:-default}` 구문은 **변수가 비어 있어도 기본값으로 대체**된다. `.env.example`은 모든 시크릿을 **빈 값**으로 배포한다(`.env.example:9-12,20-22,25-27,43,72-73`). 따라서 `cp .env.example .env` 후 `scripts/gen_secrets.sh`를 실행하지 않으면 — 그리고 이를 강제하는 코드는 없다 — 아래 값들이 **전부 활성화**된다.

| 변수 | 기본값 | compose 라인 |
|---|---|---|
| `INSTRUCTOR_TOKEN` | `dev-instructor-token` | :42, :58, :74, :118, :132, :177, :243, :342, :507 (9곳) |
| `AUTH_JWT_SECRET` | `demo-jwt-secret-change-before-production-32bytes` | :188, :242, :341 |
| `AUTH_ADMIN_PASSWORD` | `demo-operator-change-me` | :189 |
| `ATTACK_DEFENSE_FLAG_SECRET` | `attack-defense-dev-flag-secret-change-me` | :239, :338 |
| `ATTACK_DEFENSE_FLAG_HASH_SECRET` | `attack-defense-dev-hash-secret-change-me` | :240, :339 |
| `ATTACK_DEFENSE_MANAGEMENT_TOKEN` | `attack-defense-dev-management-token` | :241, :340, :423 |
| `AD_POSTGRES_PASSWORD` | `ad-ha-dev-password-change-me` | :304, :334 |
| `PCAP_ANONYMIZATION_SECRET` | `attack-defense-dev-pcap-anonymize-change-me` | :274, :368 |
| `PCAP_WATERMARK_SECRET` | `attack-defense-dev-pcap-watermark-change-me` | :275, :369 |

**`ATTACK_DEFENSE_FLAG_SECRET`이 공개 기본값이라는 것은 플래그를 오프라인으로 생성할 수 있다는 뜻이다** — `services/attack_defense/flag_service.py:62-63`가 `f"v1:{match_id}:{round_id}:{team_id}:{service_id}"`를 이 시크릿으로 HMAC한다. match/round/team/service ID는 참가자에게 노출되는 값이다. 공격 없이 전 팀 플래그를 계산해 제출할 수 있다.

**dev_mode 우회 판정**: `shared/rbac.py:92-94` — 토큰과 JWT 시크릿이 **모두** 없을 때만 `dev_mode=True`(무인증 instructor)가 된다. 그러나 compose가 항상 기본값을 주입하므로 실제로는 dev_mode에 빠지지 않고, 대신 **"공개된 시크릿으로 인증되는" 더 나쁜 상태**가 된다 — 계측상으로는 인증이 켜져 있는 것으로 보인다. A/D API는 `api.py:299`에서 `dev_mode`를 추가로 거부하므로 이 부분만은 방어된다.

### 4.3 커밋된 키

- `git ls-files | grep .env` → `.env.example`만. `.env`는 `.gitignore:1`로 제외됨, `git check-ignore` 확인 완료.
- `-----BEGIN * PRIVATE KEY-----`, `AKIA[0-9A-Z]{16}`, `gh[pousr]_`, `xox[baprs]-`, `AIza` → 저장소 코드 경로에서 **0건**.
- `node_modules/` 하위 playwright 타입 정의의 예시 문자열(`s3cr3t`)은 서드파티 문서, 무해.

---

## 5. 결함 목록 (심각도 순)

### CRITICAL-1. A/D 팀 서비스 평면에 egress 차단이 전혀 없다
`ad_team_access`(`:1056`)와 `ad_scoreboard_api`(`:1058`)에 `internal: true`가 없다. 6개 팀 서비스(`:417-472`)는 이 망에 소속되며 호스트 0.0.0.0:9101-9103/9201-9203으로도 publish된다.
**발생 시나리오**: 대회 중 팀이 제출한 패치 이미지가 그대로 기동된다(`:419` `${AD_IMAGE_*}`). 그 이미지 안의 코드는 아무 제약 없이 인터넷으로 나갈 수 있다 — 외부 C2 비컨, 플래그 유출, 외부 협력자에게 실시간 중계, 또는 실수로 실제 인터넷 자산을 스캔. 국가 기반시설 live-fire 레인지에서 이는 컨테인먼트 실패다.
**추가 악화 요인**: 트윈 평면은 `internal: true`로 제대로 막아 두었기에, 운영자는 "이 레인지는 egress가 차단된다"고 믿게 된다. 실제로 참가자 코드가 도는 유일한 평면만 열려 있다.

### CRITICAL-2. 팀 간 격리가 존재하지 않는다
6개 팀 컨테이너 전부가 `ad_team_access` + `ad_game_attack` + `ad_management` 3개 망을 공유한다(`:425,434,443,452,461,470`). `internal: true`는 **외부 egress만** 막고 동일 망 내 컨테이너 간 통신은 막지 않는다.
**발생 시나리오**: 팀 A는 취약 서비스를 익스플로잇할 필요조차 없다. 자기 패치 이미지에 스크립트를 넣어 `ad_team_02_vault:9000`, `ad_team_03_notes:9000`에 직접 접속해 타 팀 플래그를 수확한다. 스코어링은 이를 정상 공격과 구분할 수 없다.
**설계 의도와의 괴리**: `infra/attack_defense/kubernetes/control-planes.yaml`은 팀별 네임스페이스 + default-deny를 올바르게 정의한다. 그러나 기본 런타임은 `GAME_RUNTIME=docker_compose`(`:361`, `.env.example:47`)이므로 **이 정책은 한 줄도 적용되지 않는다.** 문서에 "있다"고 쓰인 격리가 실행 경로에는 없는 전형적 사례다.

### CRITICAL-3. 참가자 통제 코드가 관리망(ad_management)에 상주한다
팀 서비스가 `ad_management`에 소속되고, 같은 망에 무인증 도커 레지스트리(`:403-416`, `REGISTRY_AUTH` 환경변수 부재)와 `ad_postgres`(`:290-316`)와 `attack_defense` API(`:288`)가 있다.
**발생 시나리오**: 팀 A의 패치 이미지가 `registry.local:5000`에 익명으로 `PUT /v2/<타팀서비스>/manifests/base`를 보내 타 팀 베이스 이미지를 오염시킨다. 다음 라운드 재배포 시 팀 B/C가 팀 A의 코드를 실행한다. 대회 전체가 무효화된다.
`services/attack_defense/patch_pipeline.py:285-291`의 `dangerous_runtime_request` 검사는 **이미지 자신이 선언한 라벨**(`org.cyber-range.privileged` 등)만 본다 — 공격자는 라벨을 붙이지 않으면 된다. 보안 가치 0이다.

### CRITICAL-4. 컨트롤 플레인 시크릿이 저장소에 평문 기본값으로 존재한다
4.2절 표의 9개 변수. 특히 `AUTH_JWT_SECRET`과 `ATTACK_DEFENSE_FLAG_SECRET`.
**발생 시나리오**: 저장소를 읽을 수 있는 누구나(공개 리포/사내 GitHub) `role: "instructor"`, 임의 `team_id` JWT를 서명한다. `shared/rbac.py:70`의 `jwt.decode(token, secret, algorithms=["HS256"])`이 이를 통과시킨다. 교관 전용 엔드포인트, 타 팀 상태 조회, 점수 조정(`api.py:769-773`)이 열린다. 별도로 `ATTACK_DEFENSE_FLAG_SECRET`으로 전 팀 플래그를 오프라인 계산한다.
**근본 원인**: `.env.example`이 값을 비워 두고, compose가 `:-`로 기본값을 채우며, 이를 강제 검증하는 부팅 게이트가 없다. `scripts/gen_secrets.sh`는 존재하지만 어떤 실행 경로(`training`, `Makefile`, `scripts/training_environment.py`)에서도 호출되지 않는다.

### CRITICAL-5. `/safety/status`가 실측 없이 격리 성공을 상수로 보고한다
`services/range_control/main.py:308-321`:
```python
checks = {
    "internet_egress": "BLOCKED",          # 11개 트윈 internal:true 네트워크
    "cross_team_traffic": "BLOCKED",        # per-twin 네트워크 격리(형제 트윈 도달 불가)
    "docker_socket_exposure": "NONE",       # compose에 docker.sock 마운트 없음
    ...
    "unauthorized_destination_attempts": 0,  # egress 차단으로 시도 자체가 도달 불가
}
```
어떤 프로브도 실행하지 않는다. `range_containment_score`는 이 상수들로부터 계산되므로 **항상 100%**다. `dashboards/livefire/src/components/Instructor/RangeControlPanel.tsx:51`이 이를 그대로 초록불로 표시한다.
**발생 시나리오**: CRITICAL-1의 egress가 열려 있고 CRITICAL-2의 팀 간 통신이 열려 있는 상태에서, 교관 대시보드는 "cross_team_traffic: BLOCKED, containment 100%"를 표시한다. `cross_team_traffic` 주석이 명시적으로 트윈 평면만 근거로 삼는데 라벨은 전역이다. NIST SP 800-84 관점에서 이는 단순 버그가 아니라 **안전 계측의 허위 보증**이며, 사고 발생 시 운영자가 컨테인먼트가 유지되고 있다고 오판하게 만든다.

### HIGH-6. 11종 트윈 컨테이너에 하드닝이 전혀 적용되지 않는다
`docker-compose.yml`의 `read_only`/`cap_drop`/`no-new-privileges`는 `:11-16` 앵커와 `:226-229,293-297,321-324,388-391,407-410`, 즉 A/D·레지스트리·HA 계열에만 적용된다. 트윈 서비스 정의(`:555-772`)에는 `read_only`, `cap_drop`, `security_opt`, `user`, `pids_limit`, `mem_limit`이 **전부 없다**. `services/{ground_station,power_plant,defense_network,refinery_plant,hospital_ot}/Dockerfile`에 `USER` 지시자도 없다.
**발생 시나리오**: `power_plant`는 커맨드 인젝션(PP-003)과 역직렬화(PP-004)를 의도적으로 보유한다(`infra/hardening/docker-compose.hardening.yml:26` 주석). 익스플로잇 성공 시 root 쉘 + 쓰기 가능 rootfs + 기본 capability 세트(CHOWN/SETUID/SETGID/MKNOD/NET_RAW 등) + 무제한 fork/메모리. 포크폭탄 한 줄로 호스트 자원을 고갈시켜 전 대회를 중단시킬 수 있다.

### HIGH-7. 하드닝 오버레이가 어떤 실행 경로에서도 적용되지 않는다
`infra/hardening/docker-compose.hardening.yml`은 HIGH-6를 정확히 해결하는 설정(`:15-52` cap_drop/read_only/user 1000/pids_limit 64)을 담고 있다. 그러나:
- `scripts/training_environment.py:220`: `run(["docker", "compose", "up", "-d"])` — `-f` 없음
- `Makefile:19,30`: `docker compose up -d --build ...` — `-f` 없음
- `training:24-26`: `training_environment` 호출
- 유일한 참조는 `infra/hardening/README.md:11`과 `CONTRACTS.md:40` — **문서 지시뿐**
**판정: 미구현.** 오버레이 파일의 존재는 하드닝이 적용된다는 근거가 아니다. 게다가 `:9-10` 주석이 "개발 편의를 위해 기본은 false"라고 적고 있으나 실제 베이스 compose는 이미 `internal: true`이므로 주석 자체가 stale이다.

### HIGH-8. `siem_logs`가 34개 컨테이너에 쓰기 공유되어 격리를 우회한다
`docker-compose.yml`에 `siem_logs:/var/log/siem` (rw) 34건, `:ro`는 `siem_api`(`:106`) 1건.
**발생 시나리오**: 공격자가 `hospital_ot` 트윈을 장악한다. 네트워크상으로는 `twin_hospital_ot`(internal)에 갇혀 있어 `power_plant`에 도달할 수 없다. 그러나 `/var/log/siem`에 쓰기가 가능하므로 `pp_suricata`/`pp_zeek`의 로그 파일을 truncate하거나 위조 alert를 삽입한다. Blue 팀의 전 섹터 탐지 채점이 무너진다. **네트워크 격리 설계가 공유 볼륨 하나로 무력화되는 구조다.**

### HIGH-9. `instructor_api`·`range_control`이 0.0.0.0에 노출된다
`docker-compose.yml:137`(8050), `:178`(8055). 관리 평면 전용 인터페이스가 호스트의 모든 인터페이스에 바인딩된다. `ad_ha_gateway`(`:393`)와 `ad_registry`(`:406`)만 `127.0.0.1` 바인딩을 쓴다 — **같은 파일 안에 올바른 패턴이 존재하는데 관리 API에는 적용되지 않았다.**
**발생 시나리오**: 참가자 VLAN에서 호스트에 도달 가능한 구성이면(레인지에서는 통상 그렇다), 참가자가 기본 `dev-instructor-token`으로 `range_control:8055`의 긴급정지 엔드포인트를 호출해 대회를 중단시킨다.

### MEDIUM-10. CI에 격리·시크릿·취약점 게이트가 하나도 없다
`.github/workflows/ci.yml` 128줄 전체에서 `isolation_test`, `secret_scan`, `trivy`, `bandit`, `semgrep`, `pip-audit`, `safety_scan` 문자열 **0건**. `integration` 잡(`:71-128`)은 도커 스택을 띄우고 헬스체크·Modbus 프로브까지 하면서 `infra/ci/isolation_test.py`를 호출하지 않는다.
**발생 시나리오**: 누군가 `internal: true`를 지우거나 팀 서비스에 네트워크를 추가하는 PR이 CI 전부 초록으로 머지된다. 격리 회귀에 대한 자동 방어선이 0이다. 도구는 이미 작성되어 있으므로 비용은 CI 3줄이다.

### MEDIUM-11. `isolation_test.py`의 커버리지가 배포 구성과 어긋난다
`infra/ci/isolation_test.py:118` — `twins = ["gs_twin", "pp_twin", "dn_twin"]`. 트윈은 11종이며 나머지 8종(`refinery_plant`~`hospital_ot`, `docker-compose.yml:668-772`)은 검사 대상이 아니다. A/D 평면(CRITICAL-1·2의 실제 결함 지점)은 **단 한 항목도 검사하지 않는다.** 컨테이너명 자체는 `:557,574,588`의 `container_name`과 일치하므로 유효하다.
또한 `:134,141-143` — `--skip-if-no-docker`가 도커 부재 시 **exit 0**을 반환한다. CI에 연결되더라도 도커 없는 러너에서 무조건 통과한다.

### MEDIUM-12. `secret_scan.py`가 compose 기본값을 탐지하지 못한다
`infra/ci/secret_scan.py:24`의 `generic_high_entropy_secret` 패턴은 `['\"][A-Za-z0-9_\-]{32,}['\"]` — **따옴표로 감싼** 값만 매치한다. compose의 `AUTH_JWT_SECRET=${AUTH_JWT_SECRET:-demo-jwt-secret-change-before-production-32bytes}`는 따옴표가 없고 `:-`를 포함하므로 매치되지 않는다. 4.2절의 9개 실제 결함을 **전부 놓친다.**

### MEDIUM-13. `siem_api`가 1514/udp를 0.0.0.0에 무인증 노출한다
`docker-compose.yml:104` — `"1514:1514/udp"`. syslog는 인증이 없다. 참가자가 임의 호스트에서 위조 syslog를 주입해 탐지 채점을 조작하거나 SIEM 저장소를 고갈시킬 수 있다.

### LOW-14. `network_policy.py`가 자기 플랫폼을 검증하지 않는다
`services/attack_defense/network_policy.py`(43 LOC)는 `privileged`/`host network`/`cap_add`/`host mount`를 올바르게 금지한다. 그러나 호출부는 A/D 패치 이미지 스펙 검증뿐이며, `docker-compose.yml` 자체를 이 정책으로 검사하는 경로가 없다. 검사했다면 22개 사이드카의 `cap_add`(`:34-35`)가 즉시 위반으로 잡혔을 것이다.

### LOW-15. `challenge_qa/safety_scan.py`의 hardened 검증이 문자열 존재 확인에 불과하다
`infra/challenge_qa/safety_scan.py:54` — `missing = [k for k in ["cap_drop","read_only","mem_limit"] if k not in text]`. 값을 파싱하지 않으므로 `read_only: false`도 통과한다. 또한 `:43-46`에서 RCE 카테고리(`ai`, `reversing`)가 hardened가 아니어도 **경고만 하고 실패시키지 않는다**. 실제로 `challenges/reversing/*/challenge.yaml`은 전부 `profile: "standard"`이므로 이 게이트는 아무것도 강제하지 않는다. (다만 D-13대로 실제 악성 바이너리가 없어 현재 실질 위험은 낮다.)

---

## 6. 적합 판정 항목 (결함 아님, 근거 명시)

- **하이퍼바이저/도커 탈출 프리미티브 부재**: 3.1절 전수 grep. docker.sock·privileged·hostPath·host PID/IPC 0건.
- **`services/cloud_native`는 순수 모사**: `main.py:35-49` — `docker_exec`/`kubelet_exec`가 실제 소켓이나 10250 포트에 접속하지 않고 `emit({...})`으로 이벤트만 발생시킨다. `169.254.169.254`는 `_META_HOSTS` 문자열 상수(`:19`)로만 존재. **실제 소켓 노출 아님.**
- **`kubernetes_runtime.py` 권한 모델**: `:346-348` `runAsNonRoot: True, runAsUser: 65532, seccompProfile: RuntimeDefault`, `:364-368` `privileged: False, readOnlyRootFilesystem: True, allowPrivilegeEscalation: False, capabilities.drop: ["ALL"]`, `:469-482`에 동일 조건 재검증. Pod Security 관점에서 restricted 준수. `:67-72`에서 kubectl 바이너리명 정규식 검증·kubeconfig 존재 검증. **적합.**
- **팀 ID가 헤더로 위조되지 않음**: 3.2-E 참조. JWT 서명 클레임 전용.
- **트윈 본체 11종의 호스트 포트 미노출 + per-twin 게이트웨이**: 2.2·2.3절. 간접 lateral 차단 설계가 실제로 구현되어 있다.
- **실제 악성 바이너리 부재**: D-13.
- **`.env` 미커밋**: 4.3절.
- **`ad_patch_sandbox`**: `:474-483` — `<<: *ad-service-security` 적용, 포트 미노출, `/data`가 noexec tmpfs. 적합.

---

## 7. UNVERIFIED 목록

| 항목 | 사유 | 확인 방법 |
|---|---|---|
| `internal: true`의 실제 egress 차단 동작 | 도커 실행 금지. 설정상 올바르나 런타임 실측 없음 | `docker exec gs_twin curl -m3 https://1.1.1.1` → 실패해야 함. `infra/ci/isolation_test.py:44-54`가 정확히 이를 수행한다 |
| 호스트 iptables/nftables 규칙 존재 여부 | 호스트 상태 조회 금지. 저장소 내 `iptables`/`nft`/`ufw` 설정 파일 또는 스크립트 **0건** — 즉 저장소가 제공하는 호스트 방화벽은 없다 | 배포 호스트에서 `iptables -L -n -v`, `nft list ruleset` |
| `ad_team_access` 실제 egress 여부 | 동일 | `docker exec ad_team_01_notes ...` (해당 이미지에 curl 부재 가능, `python3 -c "import socket"` 사용) |
| 팀 간 실제 도달성 | 동일 | `docker exec ad_team_01_notes python3 -c "import socket;socket.create_connection(('ad_team_02_vault',9000),3)"` → 연결되면 CRITICAL-2 확정 |
| `ad_registry` 익명 push 가능 여부 | 도커/HTTP 실행 금지. compose에 `REGISTRY_AUTH*` 부재가 근거이나 registry:2 이미지 자체 기본값 미확인 | `curl -X PUT http://127.0.0.1:5000/v2/test/manifests/latest` |
| 배포 시 `.env`가 실제로 채워지는지 | 현재 저장소의 `.env`(401 bytes)는 gitignore 대상이라 내용 확인이 감사 범위 밖 | 운영자에게 `scripts/gen_secrets.sh` 실행 여부 확인. 부팅 시 기본 시크릿 감지 → 기동 거부 게이트 추가 권장 |
| Suricata/Zeek 사이드카의 실행 UID | 이미지 기본값(`image:` 지정, Dockerfile 없음). compose에 `user` 미지정 | `docker inspect gs_suricata --format '{{.Config.User}}'` |
| 22개 사이드카가 `x-ad-service-security` 앵커를 상속하는지 | `:773-1037` 구간에 `<<: *ad-service-security` 문자열 부재를 grep으로 확인했으나(2절), 전 구간 육안 대조는 미수행 | `docker compose config` 렌더 결과에서 해당 서비스의 `ReadonlyRootfs`/`CapDrop` 확인 |
| `dashboards/` 프론트엔드의 토큰 취급 | D축 범위 밖(C축·A축 소관) | — |

---

## 8. 최소 시정 권고 (우선순위 순)

1. `ad_team_access`, `ad_scoreboard_api`에 `internal: true` 추가. 참가자 접근은 `range_control`에 있는 전용 인그레스 프록시(트윈 게이트웨이와 동일 패턴, `infra/twin_gateway/gs.conf` 참조)로만 허용.
2. 팀별 네트워크 분리: `ad_team_01_access`/`ad_team_02_access`/`ad_team_03_access`로 쪼개고, `ad_management`에서 팀 서비스를 제거. 체커/플래그 주입기는 별도 단방향 경로로.
3. `docker-compose.yml`의 모든 시크릿 `:-기본값` 제거 → 미설정 시 compose가 실패하도록. 또는 각 서비스 부팅 시 기본값 감지 → 기동 거부.
4. `services/range_control/main.py:308-321`의 상수를 실제 프로브로 교체하거나, 최소한 `"UNVERIFIED"`로 표기하고 `range_containment_score` 계산에서 제외.
5. `.github/workflows/ci.yml`의 `integration` 잡에 `python infra/ci/isolation_test.py` 추가(`--skip-if-no-docker` 없이), 별도 `unit` 잡에 `python infra/ci/secret_scan.py` 추가. `isolation_test.py:118`의 트윈 목록을 11종으로 확장하고 A/D 평면 검사(팀간 도달·egress) 추가.
6. `scripts/training_environment.py:220`에 `-f infra/hardening/docker-compose.hardening.yml` 추가하고, 오버레이를 11종 트윈 전부로 확장.
7. `siem_logs`를 트윈에서 분리 — 트윈은 event_collector로 push하고, 로그 볼륨은 센서 사이드카만 쓰기 마운트. 또는 트윈별 볼륨으로 분리.
8. `instructor_api`(8050)·`range_control`(8055)·`siem_api`(8040,1514/udp)를 `127.0.0.1:` 바인딩으로 변경(`ad_ha_gateway:393` 패턴).
