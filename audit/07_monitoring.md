# G축 감사 — 관제·모니터링 (자체 SIEM / EDR)

감사 대상 저장소: `/home/mintkangaroo/Project/Cyber_offensive_Defense_Project/cyber-range-platform`
방식: 정적 분석 전용(도커 미기동). 모든 판정은 `경로:라인` 근거를 붙인다.

> **전제 정정**: 감사 브리핑의 "Splunk 기준"은 저장소 실체와 불일치한다. `Splunk` 문자열은 저장소에 0건이며,
> 실제 구현은 자체 SIEM(`services/siem/`, 18파일 1,782 LOC)이다. 이하 모든 판정은 자체 SIEM 기준이다.
> Wazuh도 코드 0건이다.

---

## 1. 요약 판정 테이블

| # | 항목 | 판정 | 근거 (path:line) | 실전 영향 |
|---|---|---|---|---|
| G1 | 로그 소스 → 파서 정규화 | 부분 구현 | `services/siem/parsers/{twin,suricata,zeek,pfsense}.py` | 4종 파서는 동작하나 소스 커버리지가 좁다 |
| G2 | **twin access log의 src_ip가 전부 게이트웨이 IP** | **치명 결함** | `infra/twin_gateway/gs.conf:9-12`(X-Forwarded-For 미설정) + `shared/siem_access_log.py:78`(`request.client.host`) | 팀·공격자 귀속 불가. src.ip 기반 threshold/sequence 룰 전부 무의미 |
| G3 | **Zeek `#fields` 헤더 유실 레이스** | **치명 결함** | `services/siem/ingestion/file_tailer.py:39`(최초 오픈 시 `seek(0, SEEK_END)`) + `services/siem/parsers/zeek.py:61-63` | 헤더를 놓치면 다음 로테이션(Zeek 기본 1시간)까지 Zeek 이벤트 **0건**. 훈련 전 구간이 Zeek 사각지대 |
| G4 | Zeek conn.log 기록 시점 | 설계 결함 | `infra/zeek/local.zeek:6`(표준 conn만) — conn 레코드는 연결 종료/타임아웃 시 기록 | 지속 C2 세션은 수 분간 SIEM에 안 보임. `NET-C2-BEACON-001`의 전제가 무너짐 |
| G5 | **pfSense 파서만 있고 소스 없음** | 미구현 | 파서 `services/siem/parsers/pfsense.py:42`, 수신 `services/siem/api/main.py:238`, 그러나 `docker-compose.yml` 전 서비스 목록에 pfSense 인스턴스 0건 | `FW-BLOCK-SPIKE-001`(network_layer.yaml) 영구 무발화. `loadtest/syslog_flood.py:16`만이 유일한 합성 발신자 |
| G6 | **A/D 모드가 SIEM 사각지대** | 미구현 | `docker-compose.yml:223-250` attack_defense에 `siem_logs` 볼륨 없음, `services/attack_defense/*.py` 내 `siem` 참조 0건, A/D용 Suricata/Zeek 사이드카 0건 | DEF CON형 A/D 취약서비스에 대한 공격이 SIEM에 한 줄도 안 남는다 |
| G7 | 컨트롤플레인 감사로그 → SIEM | 미구현 | `shared/siem_access_log.py` 사용처는 트윈 12종뿐(§2 매트릭스) | auth/config/instructor/range_control 조작이 SIEM에 없음 |
| G8 | 탐지 룰 52건 로드 | 구현 | `services/siem/api/main.py:78-105`, rules/*.yaml 6개 | — |
| G9 | **룰 ↔ 시나리오/챌린지 매핑** | **미구현** | 6개 YAML 전수 키 집합에 `scenario_id`/`challenge_id`/`scenario` 키 0건(§3) | "이 시나리오는 탐지 가능한가"를 사전 검증할 수단이 없다 |
| G10 | Sigma 로더 | 사실상 미지원 | `services/siem/detection/sigma_loader.py:34-38`(condition은 `selection`만), `:50-53`(timeframe 무시), `:71-76`(필드 매핑 4개) | 공개 Sigma 룰셋 대부분을 못 읽는다. 로더는 있으나 호출부 0건 |
| G11 | Sigma 로더 호출부 | **데드코드** | `sigma_dict_to_rule`/`load_sigma_yaml` 참조가 `services/siem/api/main.py`·`tests/`에 0건 | 기능이 파이프라인에 연결돼 있지 않다 |
| G12 | sequence 상관 | 부분 구현 + 1건 사망 | `services/siem/detection/engine.py:267-285`; `sequence_rules.yaml` SEQ-KILLCHAIN-001 step3 `event_type: flag_exfiltrated` | `NormalizedEvent`에 `event_type` 필드 없음(`shared/siem_schema.py:25-53`) → 이 룰은 **영구 미발화** |
| G13 | periodicity(비콘) 구현 | 구현되나 allowlist 무효 | `engine.py:130-162`; `periodicity_rules.yaml` allowlist가 `["event_collector","scoring_engine",...]`(서비스명), 비교 대상은 `dst.ip`(`engine.py:235,238`) | allowlist 절대 매치 안 됨 → 플랫폼 자체 헬스 폴링이 C2 비콘으로 오탐 |
| G14 | `beacon_detection_note.md` | 문서 아닌 실구현 확인됨 | `detection/beacon_detection_note.md:8` 주장 ↔ `engine.py:66`(`"periodicity"` kind), `:130-162`, `:233-251` 실존 | 노트 내용은 코드와 일치. 단 G13 결함은 노트에 미기재 |
| G15 | 인시던트 자동 승격 임계 | 부분 무효 | `docker-compose.yml:98` `INCIDENT_MIN_SEVERITY=5`; app_layer.yaml 최고 severity=4 | app_layer 27룰(CMDI·역직렬화·PLC write 포함) 전부 인시던트 미승격. 승격되는 건 cloud 4 + ics 7 = **11/52** |
| G16 | 승격 인증 | 잠재 폭탄 | `services/siem/api/main.py:157`(`INCIDENT_TOKEN` 없으면 헤더 미부착) + `docker-compose.yml:192-202`(incident에 토큰 env 없음) → 현재는 `shared/rbac.py:92-94` dev_mode로 통과 | incident에 토큰을 설정하는 순간 승격이 401로 **조용히 전부 실패**(`main.py:161-162`가 예외 삼킴). 동시에 현재는 incident API가 전면 무인증 |
| G17 | EDR 텔레메트리 | 실제 구현(목업 아님) | `shared/edr_agent.py:43`(`psutil.process_iter`), `:48-53`(inet 연결), `requirements.txt:9` psutil 고정 | 실 프로세스/네트워크 수집 확인 |
| G18 | EDR kill 액션 | 실제 동작 | `services/edr/api/main.py:432-437`(큐 적재) → `shared/edr_agent.py:112-119`(`terminate`→`kill`) | 상태 플래그가 아니라 실제 SIGTERM/SIGKILL |
| G19 | EDR isolate 액션 | 실제 동작(위임) | `services/edr/api/main.py:363-369` → config_service `/instructor/quarantine`; 강제 지점은 `shared/ics_twin.py:69-70`(503 반환) | 네트워크 차단이 아니라 **앱 레이어 503**. L3 격리 아님 |
| G20 | **EDR 5초 스냅샷 diff의 구멍** | 결함 | `shared/edr_agent.py:30`(`_POLL_INTERVAL_SEC = 5`), `services/edr/api/main.py:199-220`(신규 pid만 평가) | 5초 미만 생존 프로세스(`sh -c 'cat /flag'`)는 **영구 미탐지** |
| G21 | EDR 에이전트 배포 범위 | 트윈 12종 한정 | `services/{ground_station,power_plant,defense_network}/main.py`, `shared/ics_twin.py:62` | A/D 서비스·컨트롤플레인에 EDR 없음 |
| G22 | 화이트팀 실시간 상황판 | 부분 구현 | `dashboards/control-tower/index.html:254-345` | 실데이터 기반. 단 **SIEM 알림·EDR 알림·팀별 진척 없음**(§5) |
| G23 | InstructorConsole 팀별 진척 | 미구현 | `dashboards/livefire/src/components/Instructor/InstructorConsole.tsx:37-160` | 조작 패널일 뿐 진척/헬스 뷰 없음 |
| G24 | NOC 자산 헬스 커버리지 | 결손 | `services/noc_monitor/api/main.py:186-190` — 3개 자산만 등록 | 트윈 12종 중 **9종의 헬스가 폴링되지 않음**. 복구(asset_recovered) 판정도 3종만 |
| G25 | Prometheus/OTel | 미도입 | `prometheus_client`/`opentelemetry` 코드·의존성 0건. `services/observability/metrics.py:321`은 손수 문자열 렌더 | 표준 계측 없음. 히스토그램/카운터 시맨틱 없음(전부 gauge) |
| G26 | 대시보드 하드코딩 목업 | **없음** | §6 참조 | 목업 렌더 지점은 발견되지 않았다 |
| G27 | SIEM 테스트 커버리지 | 심각 결손 | `tests/unit/test_siem_engine.py`(52 LOC)는 `_event_epoch` 헬퍼만 검증 | 파서 4종·threshold/sequence/periodicity·sqlite backend·sigma loader **테스트 0건** |
| G28 | 대시보드 테스트 | 결손 | `dashboards/siem/**` 테스트 0건; livefire는 3건(`uiLogic.test.ts`, `broadcastLogic.test.ts`, `ProcessImpact.test.ts`) | 관제 UI 회귀 미보호 |
| G29 | 노이즈 생성기 | 기본 비활성 | `docker-compose.yml:99` `SIEM_NOISE_ENABLED=false` | 오탐 트리아지 훈련(`noise_generator.py:27` is_noise 라벨) 미사용 상태 |
| G30 | 저장소 잔여물 | 위생 문제 | `dashboards/siem/src/{api,components/`, `dashboards/livefire/src/{api,store,components/` 디렉토리 실존; `services/siem/api/siem.db`·`siem_alerts.db`·`services/edr/api/edr.db`·`services/incident/incidents.db` 커밋됨 | brace-expansion 오타 잔재 + 런타임 DB 커밋 |

---

## 2. 로그 소스 × 파서 × 배선 매트릭스 (양방향 결손)

### 2-A. 파서가 추출하는 필드

| 파서 | 입력 포맷 | 추출 필드 | 미추출/결손 |
|---|---|---|---|
| `parsers/twin.py:46-81` | siem_access_log JSON 1줄 | `timestamp(ts)`, `source_ip`, `host/asset`, `severity`(status+vuln_id 파생 `:23-33`), `category="web"`, `action`, `src.ip`, `signature=TWIN-{vuln_id}`, `trace_id`, `vuln_id`, `team_id`, `raw`(전체) | `mitre=[]` 하드코딩(`:73`), `dst` 없음, `method`/`endpoint`/`ua`/`latency_ms`는 `raw.*`로만 접근 가능 |
| `parsers/suricata.py:39-97` | eve.json | `timestamp`, `src/dst.ip+port`, `severity`(맵 `:36`), `category`, `action`, `network.proto`, `signature`, `signature_id`, `raw` | `mitre=[]` 하드코딩(`:56,93`), `asset=None`(`:84` — 호출부가 주입, `api/main.py:202`), flow 바이트/패킷은 message 문자열로만 |
| `parsers/zeek.py:54-108` | TSV + `#fields` 헤더 | `timestamp`, `src/dst.ip+port`, `network.proto`, `network.log_type`, `severity`(notice=3, 그 외 0 `:99`), `raw`(전체 행) | `mitre` 필드 자체 없음, `signature` 없음, dns query/http uri는 message 문자열로만 → 룰이 구조화 필드로 매칭 불가 |
| `parsers/pfsense.py:42-77` | filterlog CSV | `severity`(block=2), `category="firewall"`, `action`, `src/dst.ip+port`, `network.{proto,iface,direction}` | **`timestamp`가 파싱값이 아니라 수신시각**(`:60` 주석 인정) → 시간 상관 부정확. `mitre` 없음 |
| `parsers/base.py:54-71` | 디스패처 | 실패 시 `_fallback_event`로 손실 방지(`:39-51`) | zeek는 레지스트리 미등록(`:27`), 특수분기 |

**공통 결손**: 어떤 파서도 `mitre`를 채우지 않는다. ATT&CK 커버리지(`api/main.py:328-335`)는 **룰의 mitre 태그만** 집계하므로 "이벤트 단위 ATT&CK 관측"은 존재하지 않는다.

### 2-B. 소스 ↔ 파서 ↔ 배선 (양방향)

| 로그 소스 | 실체 존재? | 파서 | SIEM 배선 | 판정 |
|---|---|---|---|---|
| 트윈 access log (레거시 3종: gs/pp/dn) | O — `services/ground_station/main.py:94`, `power_plant/main.py:79`, `defense_network/main.py:72` | twin | O `api/main.py:234-235` + `docker-compose.yml:563,580,594` 볼륨 | 배선 완료 |
| 트윈 access log (ICS 8종) | O — `shared/ics_twin.py:73` | twin | O `docker-compose.yml:675-768` | 배선 완료 |
| cloud_native access log | O — `services/cloud_native/main.py:84`(`make_ics_twin`) | twin | O `docker-compose.yml:492-494` | 배선 완료 |
| Modbus 활동 로그 | O — `shared/ics/twin_modbus.py:81-86`(`vuln_id`,`ics_technique`,`register` 기록) | twin | O (동일 `{asset}_access.log`) | 배선 완료 |
| SMTP 활동(defense_network) | O — `services/defense_network/main.py:90` | twin | O | 배선 완료 |
| Suricata eve.json | O — 사이드카 11개 `docker-compose.yml:773~1040` | suricata | O `api/main.py:246-249,258` | 배선 완료 |
| Zeek conn/dns/http/ssl/notice | O — 사이드카 11개 | zeek | O `api/main.py:251-260` | **G3 헤더 레이스로 실효성 의심** |
| **pfSense filterlog** | **X — compose에 인스턴스 없음** | pfsense (O) | 수신부 O `api/main.py:238` | **파서 있고 소스 없음** |
| **A/D 취약서비스(attack_defense)** | O(서비스 실존) | **X** | **X** `docker-compose.yml:223-250` 볼륨/사이드카 없음 | **소스 있고 파서·배선 없음** |
| **challenge_portal** | O `docker-compose.yml:498` | X | X | 소스 있고 배선 없음 |
| **auth / config_service / event_collector / scoring_engine / range_control / instructor_api / incident / injects** | O | X | X | 컨트롤플레인 전부 SIEM 밖 |
| **EDR 알림** | O `services/edr/api/main.py:209-214` | — | **X** (EDR 자체 DB에만) | SIEM/EDR 알림 통합 뷰 없음 |
| **cloud_native용 Suricata/Zeek** | **X** | — | `api/main.py:256-260`이 `cloud_native` 경로도 tail 시도 | 존재하지 않는 12번째 사이드카를 영구 대기(무해하나 소스 헬스에 미표시) |
| syslog 일반(`source_type="syslog"`) | 스키마에만 정의 `shared/siem_schema.py:29,67` | X | 수신 큐는 무조건 `parse_any("pfsense", ...)` `api/main.py:211` | pfSense 아닌 syslog는 전부 `parse_error` fallback |

**tail 태스크 수 계산**: TWIN_ASSETS 12종(`api/main.py:42-48`) × (twin 1 + suricata 1 + zeek 5) = 12 + 12 + 60 = **84개 asyncio 태스크가 0.5초마다 깨어난다**(`file_tailer.py:17,46-49`). 이 중 실제 파일이 존재하는 경로는 최대 12(twin) + 11(suricata) + 55(zeek) = 78. 나머지는 영구 대기.

---

## 3. 탐지 룰 집계 + 시나리오 매핑 결손

### 3-A. 파일별 집계 (YAML 전수 파싱 결과, 총 **52건**)

| 파일 | 룰 수 | kind 분포 | severity 분포 | MITRE 태그 |
|---|---|---|---|---|
| `app_layer.yaml` | 27 | match 25, threshold 2 | 2:3, 3:11, 4:13 | 27/27 보유 |
| `ics_layer.yaml` | 10 | match 10 | 4:3, 5:7 | 10/10 |
| `cloud_layer.yaml` | 5 | match 5 | 4:1, 5:4 | 5/5 |
| `network_layer.yaml` | 5 | threshold 4, match 1 | 2:4, 3:1 | 4/5 (`NET-SURICATA-ALERT-PASSTHROUGH` 미보유) |
| `sequence_rules.yaml` | 4 | sequence 4 | 3:1, 4:3 | 4/4 |
| `periodicity_rules.yaml` | 1 | periodicity 1 | 3:1 | 1/1 |
| **합계** | **52** | match 41, threshold 6, sequence 4, periodicity 1 | 2:7, 3:13, 4:17, 5:11 | 51/52 |

**소스별 편중**: `source_type: twin` 42건(81%), suricata/zeek 5건, pfsense 1건, 전체(None) 4건.
→ **탐지 역량의 81%가 애플리케이션 액세스 로그 한 종에 의존**한다. 네트워크 레이어 탐지는 5건뿐이며 그중 1건(pfSense)은 소스가 없다.

### 3-B. severity 스키마 위반

`shared/siem_schema.py:33`은 `severity: int # 0(info)~4(critical)`로 규정한다. 그러나 ics_layer 7건·cloud_layer 4건이 **severity 5**를 쓴다. `api/main.py:57`의 `_SEV_MAP = {5:"critical", 4:"high", 3:"medium"}`은 5를 전제하므로 실질 스케일은 0~5다. 스키마와 룰·매퍼가 3자 불일치.

### 3-C. 시나리오/챌린지 매핑 — **미구현**

6개 YAML의 전체 키 집합:
```
id, title, severity, mitre, source_type, kind, match,
threshold_group_by, threshold_condition, threshold_window_sec,
sequence_steps, sequence_group_by, sequence_within_sec,
periodicity_group_by_src, periodicity_group_by_dst, periodicity_min_observations,
periodicity_jitter_threshold, periodicity_window_sec, periodicity_allowlist_dst
```
`scenario_id`·`challenge_id`·`scenario`·`covers` 계열 키는 **0건**. `Rule` 데이터클래스(`engine.py:59-80`)에도 해당 필드가 없고, 로더(`api/main.py:85-101`)도 읽지 않는다.

간접 매핑 수단은 `match: {vuln_id: "..."}` 뿐이며, 이는 24/52 룰에만 존재한다. 나머지 28건(threshold/sequence/periodicity/카테고리 매치)은 어떤 시나리오를 겨냥했는지 코드·메타데이터 어디에도 없다.
→ **"이번 훈련 시나리오가 Blue에게 탐지 가능한가"를 실행 전에 검증할 방법이 없다.**

### 3-D. 개별 룰 실효성 판정 (사망/오탐 목록)

| 룰 ID | 판정 | 근거 |
|---|---|---|
| `SEQ-KILLCHAIN-001` | **영구 미발화** | step3 `{event_type: flag_exfiltrated}`. `NormalizedEvent`에 `event_type` 필드 없음(`shared/siem_schema.py:25-53`) → `_get_path`(`engine.py:20-28`)가 항상 None |
| `FW-BLOCK-SPIKE-001` | **영구 미발화** | `source_type: pfsense`. pfSense 인스턴스 부재(G5) |
| `NET-DNS-TUNNEL-001` | **고오탐 확정** | `threshold_condition: distinct(message) >= 20`, `source_type: zeek`. zeek 룰은 log_type 구분 없이 conn/http/ssl 전부 통과하고, `zeek.py:84-85`의 conn message는 duration·bytes를 포함해 **항상 유일**. 30초 내 20개 연결이면 "DNS 터널링" 발화 |
| `NET-PORTSCAN-001` / `NET-HOSTSCAN-001` | **실질 미발화** | 사이드카는 `network_mode: service:<twin>`(예 `docker-compose.yml:776`)로 트윈 netns만 본다. 트윈은 `internal: true` 네트워크(`:1042-1052`)에 있고 유일한 진입로가 게이트웨이 단일 포트 → 다중 포트/다중 호스트 스캔이 관측 불가 |
| `NET-C2-BEACON-001` | **allowlist 무효 + 오탐** | G13. `dst.ip`(IP)를 서비스명 문자열과 비교(`engine.py:238`) |
| `ICS-SAFETY-INTERLOCK-SUPPRESS` | 동작 | `raw.ics_technique` 키를 `shared/ics/twin_modbus.py:86`이 실제로 기록. `tests/unit/test_ics_detection.py:19-21`이 계약 고정 |
| `TWIN-IDOR-SCAN-001`, `ICS-OT-MULTIVULN-PROBE-001` | **팀 구분 붕괴** | `threshold_group_by: src.ip`인데 모든 트래픽의 src.ip가 게이트웨이 IP(G2) → 전 팀이 단일 그룹키로 합쳐짐. 개별 팀은 임계 미달인데 합산으로 발화 |
| `SEQ-RECON-TO-EXPLOIT-001`, `ICS-*-KILLCHAIN-SEQ-001` | **거짓 킬체인** | `sequence_group_by: src.ip`(기본, `engine.py:72`) → G2로 인해 A팀의 step1과 B팀의 step2가 하나의 킬체인으로 합성됨 |

### 3-E. Sigma 로더 판정

| Sigma 스펙 요소 | 지원 여부 | 근거 |
|---|---|---|
| `detection.selection` | O | `sigma_loader.py:26,40` |
| `detection.condition` — `selection` 단독 | O | `:34` |
| condition — `and`/`or`/`not`/`1 of`/`all of`/`selection and not filter` | **X** (경고 후 selection만 사용) | `:34-38` |
| 다중 selection 블록(`selection1`, `filter`) | **X** (무시) | `:26` — `selection` 키만 읽음 |
| `timeframe` → threshold 변환 | **X** (경고 후 match로 격하) | `:48-53` |
| aggregation (`count() by X > N`, `near`) | **X** (파싱 시도조차 없음) | 전체 파일에 관련 코드 없음 |
| 필드 modifier (`\|contains`, `\|startswith`, `\|re`, `\|base64`) | **X** | `:40`이 키를 그대로 사용. 엔진의 `~` 접두 부분매치(`engine.py:97-99`)와 Sigma modifier 문법이 다름 |
| 필드명 매핑 | 4개만 | `:71-76` — `c-uri`, `cs-method`, `sc-status`, `EventID` |
| `logsource` 매핑 | 3 product + 3 category | `:80-89` |
| `level` → severity | O | `:15,45` |
| `tags` → MITRE | O (`attack.t*`만) | `:46` |

**결론**: 공개 SigmaHQ 룰의 대다수는 다중 selection + condition 표현식 + modifier를 쓴다. 이 로더는 그중 어느 것도 지원하지 않으며, 미지원을 `warnings.warn`으로 흘리고 **잘못 변환된 룰을 그대로 반환**한다(`:38` 주석 "최대한 변환"). 조용한 오탐/미탐의 원천이다. 게다가 **어떤 코드도 이 로더를 호출하지 않는다**(G11) — 룰 로더 `api/main.py:78-105`는 자체 YAML 포맷만 읽는다.

### 3-F. sequence / periodicity 상관 로직 실체

- `sequence`(`engine.py:267-285`): 그룹키별 단일 진행 인덱스만 유지(`_SequenceState.progress`, `:165-178`). 실체는 있으나 —
  - 한 그룹키당 **동시 진행 체인 1개**만 가능. 병렬 공격 시 서로의 진행을 덮어씀.
  - step 매칭 실패 이벤트는 무시되나, **step 순서가 어긋나면 영원히 전진 불가**(엄격 순서).
  - `advance`(`:169-178`)의 `first_ts` 갱신 로직이 `idx > 1` 분기(`:177`)에서 2번째 step 시각을 기준시각으로 재설정 → `within_sec` 창이 실제로는 "step2~stepN" 구간에만 적용된다. step1↔step2 간격은 무제한.
- `periodicity`(`engine.py:130-162`): 변동계수(σ/μ) 기반. 로직 자체는 정상. edge-trigger 재무장도 구현(`:156-161`). 결함은 G13(allowlist)과 G4(conn.log 기록 지연)로 **입력이 안 들어온다**는 데 있다.
- `threshold`(`engine.py:105-127, 253-265`): `distinct(field) >= N` 단일 형식만(`_parse_threshold_condition:181-186`의 정규식). `count()`, `sum()`, `<` 비교 미지원.

---

## 4. 엔드투엔드 지연 계산 (코드 상수 합산)

### 4-A. 구간별 상수 (근거)

| 구간 | 상수 | 근거 |
|---|---|---|
| S1 트윈 미들웨어 로깅 | 동기 flush | `shared/siem_access_log.py:86`(`logger.info`) → `logging.FileHandler` 기본 emit-flush. ≈0~5ms |
| S2 file_tailer 폴링 | **0.5s** | `services/siem/ingestion/file_tailer.py:17`(`poll_interval: float = 0.5`), `:66`(`tail_multiple`이 기본값 사용) |
| S3 파싱 + 탐지 평가 | 이벤트당 즉시 | `api/main.py:133`(`detection_engine.evaluate`) — **주기 배치가 아니라 per-event 동기 평가**. 52룰 순회 ≈1ms |
| S4 SQLite 인덱싱 | 1~10ms | `api/main.py:130` → `storage/sqlite_backend.py:68` (동기 sqlite3를 async 함수에서 직접 호출) |
| S5 WS 브로드캐스트 | ≈1ms | `api/main.py:137-140` |
| S6 SIEM 대시보드 알림목록 폴링 | **5,000ms** | `dashboards/siem/src/components/Alerts/AlertsView.tsx:74` |
| S6' SIEM 소스헬스 폴링 | **5,000ms** | `SourceHealth/SourceHealth.tsx:11` |
| S6'' SIEM ATT&CK 커버리지 폴링 | **15,000ms** | `AttackCoverage/AttackCoverageView.tsx:4` |
| S7 인시던트 승격 HTTP | ≈10ms (timeout 3s) | `api/main.py:159` |
| S8 control-tower 인시던트 폴링 | **7,000ms** | `dashboards/control-tower/index.html:477` |
| S8' control-tower 헬스/안전/플랫폼 | 5,000 / 6,000 / 6,000ms | `index.html:473,476,478` |
| S8'' control-tower 점수/매치 | 8,000 / 10,000ms | `index.html:474,475` |
| S9 EDR 에이전트 스냅샷 | **5,000ms** | `shared/edr_agent.py:30`(`_POLL_INTERVAL_SEC = 5`) |
| S10 EDR 콘솔 폴링 | **5,000ms** | `services/edr/console/src/App.tsx:13` |
| S11 NOC 헬스 폴링 | **5,000ms** + 자산당 timeout 3s 순차 | `services/noc_monitor/health_poller.py:20,107-113,71` |
| S12 livefire A/D 갱신 | 5,000ms (비가시 15,000) | `dashboards/livefire/src/attackDefense/AttackDefenseApp.tsx:88` |
| S13 livefire 레거시 뷰 | 3,000ms | `dashboards/livefire/src/LegacyExerciseApp.tsx:72` |
| S14 blueportal | 4,000ms | `dashboards/blueportal/src/App.tsx:264` |
| S15 incident 상관 루프 | 10,000ms | `services/incident/main.py:279` |

### 4-B. 경로별 합산

**경로 A — 트윈 앱레이어 공격 → SIEM WebSocket 알림**
```
하한 = S1(0) + S2(0)   + S3(0.001) + S4(0.001) + S5(0.001) ≈ 0.003초
상한 = S1(0.005) + S2(0.5) + S3(0.001) + S4(0.010) + S5(0.001) ≈ 0.52초
```
→ **0.003 ~ 0.52초**. WS 구독 클라이언트(`api/main.py:349-357`) 한정.

**경로 A' — 위 + SIEM 대시보드 알림 목록(폴링)**
```
상한 = 0.52 + S6(5.0) = 5.52초    하한 ≈ 0.003초
```
→ **0.003 ~ 5.52초**. ATT&CK 커버리지 패널은 `0.52 + 15.0 = ` **최대 15.52초**.

**경로 B — 트윈 공격 → 인시던트 → control-tower 카드**
```
상한 = 0.52 + S7(3.0 최악 timeout) + S8(7.0) = 10.52초
정상 = 0.52 + 0.01 + 7.0 = 7.53초
```
→ **최대 10.52초**. 단 severity ≥ 5인 11/52 룰만 이 경로를 탄다(G15).

**경로 C — 네트워크 공격 → Suricata → SIEM 알림**
```
상한 = eve.json write(UNVERIFIED, 보수적 1.0) + S2(0.5) + S3~S5(0.01) ≈ 1.51초
```
→ **~0 ~ 1.5초** (eve.json 버퍼링 상수는 미검증, §7 참조).

**경로 D — 네트워크 공격 → Zeek → SIEM 알림**
```
정상 케이스(단명 연결) = conn 종료시각 + ASCII writer flush(UNVERIFIED) + S2(0.5) ≈ 0.5~수 초
지속 연결        = tcp_inactivity_timeout(Zeek 기본 5분 = 300초) + 0.5 ≈ 300.5초
헤더 유실 시(G3)  = 다음 로그 로테이션(Zeek 기본 1시간 = 3600초) + 0.5 ≈ 3600.5초
```
→ **0.5초 ~ 3,600초**. 상한이 3자릿수 배 차이로 벌어지는 것이 이 시스템의 실질 관측 성능이다.

**경로 E — 악성 프로세스 생성 → EDR 콘솔**
```
하한 = S9(0) + ingest(0.01) + S10(0) ≈ 0.01초
상한 = S9(5.0) + ingest(0.01) + S10(5.0) = 10.01초
미탐 = 프로세스 수명 < 5초이고 두 스냅샷 사이에 생멸 → 영구 0건 (G20)
```
→ **0.01 ~ 10.01초, 또는 ∞(미탐)**.

**경로 F — 자산 다운 → NOC → 복구 판정**
```
헬스 반영 상한 = S11(5.0) + 자산 3개 순차 × timeout 3.0 = 14.0초
복구 판정      = 연속 3회 정상 필요(health_poller.py:102) → 최소 3 × (5 + 폴링시간) ≈ 15~42초
```
→ **자산 복구가 점수에 반영되기까지 최소 15초, 최대 42초**. 그리고 12개 트윈 중 3개만 대상(G24).

### 4-C. 종합

| 시나리오 | E2E 하한 | E2E 상한 | 비고 |
|---|---|---|---|
| 앱레이어 공격 → Blue가 화면에서 인지 | 0.003s | **5.5s** | 실용적 |
| 앱레이어 공격 → 화이트팀 상황판 인지 | 0.02s | **10.5s** | severity≥5 룰 11건만 |
| 네트워크 공격 → Blue 인지 (Suricata) | ~0s | **~1.5s + 5s(폴링)** | |
| 네트워크 공격 → Blue 인지 (Zeek) | 0.5s | **3,600s** | G3/G4 미해결 시 사실상 관측 불가 |
| 프로세스 실행 → Blue 인지 (EDR) | 0.01s | **10.0s 또는 ∞** | |
| 자산 다운 → 복구 인정 | 15s | **42s** | 12중 3자산만 |

---

## 5. 화이트팀 상황판 판정

### control-tower (`dashboards/control-tower/index.html`, 483 LOC 단일 파일)

**실데이터 기반이다** — 목업이 아니다. 근거:
- 서비스 헬스: 15개 서비스 `/health` 직접 fetch, 응답시간 측정(`:254-267`)
- 점수: `scoring/scores?scenario_id=default` (`:277`)
- 매치: `range/matches` (`:287`)
- 인시던트: `incident/incidents` + 상태전이 버튼(`:299,312`)
- 안전: `range/safety/status` (`:333`)
- 플랫폼: `observability/observability/summary` (`:324`)
- 실시간 피드: EventSource SSE + 지수 백오프 재연결(`:348-357`)

**그러나 결손:**

| 화이트팀이 필요로 하는 것 | 존재? | 근거 |
|---|---|---|
| 서비스 가동 상황 | O | `:193-208` 15개 서비스 |
| 전역 점수 | O | `:275-284` |
| 인시던트 큐 + 상태전이 | O | `:297-321` |
| 안전 상태(격리·긴급정지) | O | `:331-345` |
| ICS 자산 상태 | 부분 | `:380-400` — **SSE 이벤트 스트림에서만 in-memory 누적**(`icsState = {}` `:389`). 새로고침 시 전부 소실. 백엔드 조회 API 없음(코드 주석이 "백엔드 추가 없음"이라 명시) |
| **SIEM 알림** | **X** | `SVC.siem`은 `/health` 칩 하나뿐(`:197`). `/alerts` 호출 0건 |
| **EDR 알림/호스트** | **X** | `SVC.edr`도 `/health`만(`:205`) |
| **NOC 자산 헬스** | **X** | `SVC.noc`는 `gw:null`이라 게이트웨이 모드에서 `n/a` 표시(`:206`, `:257`). `/noc/status` 호출 0건 |
| **팀별 진척(문제 해결률, 패치율, 탐지 성공률)** | **X** | 폴링 대상에 `scoring/scores`만. 팀별 세부 진척 뷰 없음 |
| 빌드 파이프라인 | **X** | `package.json`/`vite.config` 없음. 순수 정적 HTML. 배포는 `infra/gateway/Dockerfile` 참조 |

**판정: 화이트팀은 이 화면으로 "탐지가 되고 있는지"를 볼 수 없다.** 관제 축의 핵심 산출물(SIEM 알림, EDR 알림)이 화이트팀 상황판에 연결돼 있지 않다.

### InstructorConsole / RangeControlPanel

- `InstructorConsole.tsx:37-160`: 토큰 입력, 시나리오 시작/종료, 점수 수동조정, 감사로그(5초 폴링 `:14`). **조작 패널이며 상황판이 아니다.**
- `RangeControlPanel.tsx:173-277`: safety(4초), matches(6초), 긴급정지, 스냅샷/리셋/베이스라인 검증, 매치 생성. 전부 `range_control:8055` 실호출(`api/rangeControl.ts`).
- **양쪽 어디에도 팀별 진척·인프라 헬스 뷰가 없다.**

### services/noc_monitor (4파일 284 LOC)

- `health_poller.py`: 5초 주기 `/health` 폴링, sqlite 이력, uptime%(1h)·error_rate(5m)·history 계산(`:129-163`). **실구현**.
- `api/main.py:186-190`: **대상 자산 3개 하드코딩**(ground_station/power_plant/defense_network). ICS 8종 + cloud_native 미등록 → G24.
- `api/main.py:212-230`: event_collector WS 구독으로 `asset_compromised` 수신 → RecoveryWatcher 연동. 실구현.
- 소비자 대시보드 없음: `/noc/status`·`/noc/history`·`/noc/ws`를 호출하는 프런트엔드 코드 0건.

### services/observability (3파일 187 LOC)

- `main.py:389-403`: 13개 서비스 `/health` 스크레이프.
- `metrics.py:321-336`: Prometheus 텍스트 형식 **손수 렌더**. `render_prometheus`는 HELP/TYPE 중복 제거까지 구현.
- `metrics.py:339-358`: health payload의 숫자 필드를 자동 gauge화 → SIEM의 `rules_loaded`(`api/main.py:269`), incident의 `incidents`(`incident/main.py:125`)가 자동 노출됨.
- **prometheus_client / OpenTelemetry 미도입**: 저장소 전체에서 두 패키지 참조 0건, `requirements.txt`에도 없음. 모든 지표가 `gauge`이며 카운터·히스토그램·트레이스 시맨틱이 없다. 스크레이프 시점 계산이라 **`/metrics`를 호출하지 않으면 시계열이 존재하지 않는다**(Prometheus 서버 자체도 compose에 없음).
- 테스트는 `tests/unit/test_observability_metrics.py` 존재.

---

## 6. 목업 / 하드코딩 탐지 결과

`dashboards/{siem,livefire,control-tower,blueportal,redportal,start-here}` 및 `services/edr/console/src` 전수 검색 결과:

| 항목 | 판정 |
|---|---|
| 하드코딩 샘플 알림/이벤트/호스트 배열 | **발견되지 않음.** 모든 뷰가 실 API 호출(`fetch`/WebSocket/EventSource) 결과를 렌더 |
| SIEM 대시보드 | 실데이터. `dashboards/siem/src/api/client.ts:6`(`VITE_SIEM_API_URL ?? http://{host}:8040`), WS `:11-12`, 폴링 `:114-131` |
| EDR 콘솔 | 실데이터. `services/edr/console/src/App.tsx:13-21` 3개 폴링 + `useEdrAlertStream` |
| livefire AssetMap | 실데이터. 상태는 `useRangeStore`(이벤트 스트림 구동). **좌표만 하드코딩**(`AssetMap.tsx:19-32`) — 레이아웃이므로 결함 아님 |

**단, "목업은 아니지만 휘발성"인 지점:**

| 파일:라인 | 내용 |
|---|---|
| `dashboards/control-tower/index.html:389` | `const icsState = {};` — ICS 자산 상태를 브라우저 메모리에만 누적. 새로고침/탭 교체 시 전 자산 상태 소실. 백엔드 조회 경로 없음(`:380` 주석이 "백엔드 추가 없음"으로 명시) |
| `dashboards/livefire/src/store/rangeStore.ts` | 동일 패턴(이벤트 스트림 누적형 인메모리 상태) |
| `services/noc_monitor/api/main.py:186-190` | 자산 목록 하드코딩 — config/registry 조회가 아님 |
| `services/observability/main.py:389-403` | 대상 서비스 하드코딩(`OBS_TARGETS` env로 override 가능) |
| `services/siem/api/main.py:42-48` | `TWIN_ASSETS` 하드코딩 — 트윈 추가 시 SIEM 코드 수정 필요 |
| `services/siem/detection/noise_generator.py:30-34` | `_NORMAL_ENDPOINTS`가 레거시 3종 트윈만. ICS 8종 노이즈 없음 |

---

## 7. 결함 목록 (심각도 순)

### CRITICAL-1 — 게이트웨이가 공격자 IP를 지운다 (G2)
**근거**: `infra/twin_gateway/gs.conf:9-12` (동일 패턴 `ref/fac/wtr/lng/rwy/air/dcx/hsp/pp/dn.conf`) — `proxy_set_header Host $host`만 있고 `X-Forwarded-For` 없음. `shared/siem_access_log.py:78`은 `request.client.host`를 그대로 기록. `parsers/twin.py:64,70`이 이를 `source_ip`/`src.ip`로 승격.
**발생 시나리오**: Red 팀 A가 `refinery_plant`의 OPC-UA 익명 접근을 시도하고, 동시에 팀 B가 SIS 우회를 시도한다. SIEM에는 두 요청 모두 `src.ip = <ref_gateway 컨테이너 IP>`로 기록된다. Blue가 "어느 팀이 무엇을 했나"를 SIEM에서 판별할 수 없고, `ICS-REFINERY-KILLCHAIN-SEQ-001`은 A의 REF-001과 B의 REF-002를 **한 팀의 킬체인으로 합성해 오탐 알림**을 낸다. AAR에서 공격 귀속이 불가능해진다.
**영향 범위**: src.ip를 그룹키로 쓰는 룰 8건(threshold 2 + sequence 4 + periodicity 1 + hostscan 계열).

### CRITICAL-2 — Zeek 로그가 첫 로테이션(1시간)까지 통째로 유실될 수 있다 (G3)
**근거**: `file_tailer.py:34-43` — 최초 오픈 시 `is_first_open`이면 `f.seek(0, os.SEEK_END)`. Zeek는 `conn.log`를 첫 연결 기록 시점에 생성하며 `#separator`~`#fields` 헤더와 첫 데이터 행을 함께 쓴다. tailer는 0.5초 주기로 파일 존재를 확인하므로(`:29-31`), 파일 생성과 tailer의 다음 폴링 사이에 헤더가 쓰이면 `seek(END)`로 건너뛴다. `parsers/zeek.py:61-63`은 `_field_cache`가 비면 **모든 데이터 행에 None을 반환**하고, 코드 주석 자체가 "다음 로테이션에서 헤더부터 다시 옴"이라고 인정한다. Zeek 기본 로그 로테이션 주기는 1시간.
**발생 시나리오**: 4시간 CCE형 훈련을 시작한다. 첫 1시간 동안 Zeek 기반 룰(`NET-PORTSCAN-001`, `NET-HOSTSCAN-001`, `NET-DNS-TUNNEL-001`, `NET-C2-BEACON-001`) 전부가 입력 0건이다. `/sources/health`(`api/main.py:313-325`)는 `zeek:*` 키가 아예 생성되지 않으므로(`_touch_source_health`는 이벤트가 있어야 호출됨 `:203`) **"소스 다운"으로도 표시되지 않는다** — 조용한 전면 실명.
**수정 방향**: zeek 소스에 한해 최초 오픈도 `seek(0)`, 또는 `#fields` 헤더 미확보 상태를 소스 헬스에 노출.

### CRITICAL-3 — A/D 모드 전체가 SIEM·EDR 사각지대 (G6, G21)
**근거**: `docker-compose.yml:223-250` attack_defense 서비스에 `siem_logs` 볼륨·`SIEM_LOG_DIR` env 없음. `services/attack_defense/*.py`에 `siem` 참조 0건. A/D 대상 Suricata/Zeek 사이드카 0건(사이드카 22개는 전부 트윈 대상 `:773-1040`). `shared/edr_agent.start_edr_agent` 호출부에도 A/D 없음.
**발생 시나리오**: DEF CON형 A/D 라운드에서 팀이 상대 취약서비스를 익스플로잇해 플래그를 탈취한다. SIEM에 로그 0건, EDR 알림 0건. Blue 팀이 관제 도구로 방어를 수행할 대상 자체가 없고, 점수는 `attack_defense` 자체 checker/flag 경로로만 산출된다. **A/D 모드에서 "관제"라는 훈련 목표가 성립하지 않는다.**

### HIGH-4 — 시나리오 ↔ 탐지룰 매핑 부재 (G9)
**근거**: rules YAML 6개 전체 키 집합에 시나리오 식별자 0건(§3-C). `engine.py:59-80` `Rule`에도 필드 없음.
**발생 시나리오**: 교관이 새 ICS 시나리오를 편성한다. 이 시나리오의 각 단계가 탐지 가능한지 확인하려면 52개 룰을 사람이 눈으로 대조해야 한다. 훈련 당일 Blue가 아무 알림도 못 받고 나서야 커버리지 공백이 드러난다. 사후 AAR에서 "탐지 실패가 Blue 역량 문제인지 룰 부재인지" 구분 불가.

### HIGH-5 — 인시던트 자동 승격이 41/52 룰을 배제 (G15)
**근거**: `docker-compose.yml:98` `INCIDENT_MIN_SEVERITY=5`, `api/main.py:143`(`alert.severity >= INCIDENT_MIN_SEVERITY`). app_layer.yaml 27건의 최고 severity는 4.
**발생 시나리오**: `TWIN-CMDI-001`(명령 주입, sev 4), `TWIN-DESERIAL-001`(역직렬화 RCE, sev 4), `TWIN-PLC-WRITE-001`(무단 PLC 쓰기, sev 4)이 발화한다. 알림은 SIEM에 뜨지만 인시던트로 승격되지 않아 **화이트팀 상황판(control-tower 인시던트 카드)에 나타나지 않는다**. 즉 원격코드실행과 PLC 조작이 화이트팀 눈에 안 보인다.

### HIGH-6 — Sigma 로더가 데드코드이며 스펙 미지원 (G10, G11)
**근거**: 호출부 0건. condition/multi-selection/modifier/aggregation 전부 미지원(§3-E).
**발생 시나리오**: "Sigma 룰을 임포트해 탐지 확장" 요구가 들어온다. SigmaHQ 룰 파일을 넣어도 로더가 호출되지 않아 아무 일도 일어나지 않고, 강제로 호출해도 `condition: selection and not filter` 룰이 filter 무시된 채 변환돼 **정상 트래픽을 공격으로 오탐**한다.

### HIGH-7 — NOC 자산 헬스가 12개 중 3개만 (G24)
**근거**: `services/noc_monitor/api/main.py:186-190`.
**발생 시나리오**: Red가 `hospital_ot` 인퓨전 펌프 트윈을 다운시킨다. NOC는 이 자산을 폴링하지 않으므로 다운을 인지하지 못하고, `RecoveryWatcher`도 복구 조건을 평가하지 않아 **Blue의 복구 작업이 점수에 반영되지 않는다**(`health_poller.py:102-105` 콜백 미발화). ICS 트윈 8종 + cloud_native가 모두 이 상태다.

### HIGH-8 — 화이트팀 상황판에 탐지 정보가 없다 (G22)
**근거**: `dashboards/control-tower/index.html:197,205`(siem·edr은 헬스 칩만), `/alerts`·`/edr/alerts`·`/noc/status` 호출 0건.
**발생 시나리오**: 훈련 중 화이트팀이 "지금 Blue가 탐지에 성공하고 있나"를 판단해야 한다. 상황판은 점수 숫자와 인시던트(severity 5 한정)만 보여준다. 탐지 알림 흐름을 보려면 별도 SIEM 대시보드(Vite dev 서버, 별도 기동 필요 — `docker-compose.yml:528` 주석)를 띄워야 한다.

### MEDIUM-9 — periodicity allowlist가 IP와 서비스명을 비교 (G13)
**근거**: `periodicity_rules.yaml` `periodicity_allowlist_dst: [event_collector, scoring_engine, config_service, edr_backend]` vs `engine.py:235,238` — `dst`는 `_get_path(event, "dst.ip")`로 얻은 IP 문자열.
**발생 시나리오**: 트윈의 EDR 에이전트가 5초 주기(`edr_agent.py:30`)로 `edr_backend`에 POST한다. 지터 ≈0이므로 `_PeriodicityState`가 5회 관측 후 **"C2 비콘"으로 판정**한다. `beacon_detection_note.md:21-22`가 방지하려 한 정확히 그 오탐이 방지되지 않는다. Blue가 자기 EDR 에이전트를 C2로 오인해 차단하면 훈련이 망가진다.

### MEDIUM-10 — EDR 5초 스냅샷의 단명 프로세스 미탐 (G20)
**근거**: `shared/edr_agent.py:30,134-143`, `services/edr/api/main.py:199-220`(`if pid not in prev_pids`만 평가).
**발생 시나리오**: 공격자가 `sh -c 'cat /flag; exit'`를 실행한다. 프로세스가 50ms 만에 종료돼 어떤 스냅샷에도 잡히지 않는다. EDR-001(웹서버→쉘 자식)·EDR-002(리버스쉘 패턴)가 설계상 잡아야 할 행위가 통과된다. eBPF/ptrace 같은 이벤트 기반 수집이 없어 구조적으로 해결 불가.

### MEDIUM-11 — Zeek conn.log 지연이 비콘 탐지를 무력화 (G4)
**근거**: `infra/zeek/local.zeek:6-10`(표준 conn만 로드). Zeek conn 레코드는 연결 종료 또는 inactivity timeout(기본 5분) 시 기록.
**발생 시나리오**: C2 비콘이 keep-alive 세션 하나로 10초 주기 통신을 한다. conn.log에는 세션 종료 전까지 아무것도 안 남는다. `NET-C2-BEACON-001`은 `min_observations: 5`를 요구하므로(`periodicity_rules.yaml`) **5개 세션이 각각 종료되어야** 판정이 시작된다. `beacon_detection_note.md:35-37`은 이 한계를 "min_observations를 낮춰라"로만 기록하고 conn.log 기록 시점 문제는 다루지 않는다.

### MEDIUM-12 — `NET-DNS-TUNNEL-001` 구조적 오탐 (§3-D)
**근거**: `network_layer.yaml` `distinct(message) >= 20`, `source_type: zeek`, window 30초. `zeek.py:84-85`의 conn message에 duration·bytes 포함 → 매 이벤트 유일.
**발생 시나리오**: Red가 웹 취약점을 반복 시도해 30초에 20개 이상 연결을 만들면 "DNS 터널링" 알림이 뜬다. Blue가 DNS 조사에 시간을 쓰는 동안 실제 웹 공격이 진행된다. 훈련 목표(정확한 트리아지) 왜곡.

### MEDIUM-13 — `SEQ-KILLCHAIN-001` 영구 미발화 (G12)
**근거**: step3 `{event_type: flag_exfiltrated}` vs `shared/siem_schema.py:25-53`에 `event_type` 필드 부재.
**발생 시나리오**: "정찰→익스플로잇→유출" 킬체인 완주가 최고 가치 탐지인데, 이 룰이 절대 발화하지 않는다. 룰 개수 집계(52)에는 포함돼 커버리지를 과대 보고한다.

### MEDIUM-14 — 인시던트 승격 인증의 시한폭탄 (G16)
**근거**: `api/main.py:56,157`(`INCIDENT_TOKEN` 미설정 시 헤더 없음), `docker-compose.yml:91-104`(siem_api에 `INCIDENT_TOKEN` env 없음), `:192-202`(incident에 토큰/JWT env 없음 → `shared/rbac.py:92-94` dev_mode). 예외 처리는 `httpx.HTTPError`만 잡고(`api/main.py:161`) 4xx 응답은 `raise_for_status` 없이 무시된다.
**발생 시나리오 A(현재)**: incident 서비스가 **전면 무인증**이다. 누구나 `/incidents/{id}/transition`으로 인시던트를 임의 종결할 수 있다.
**발생 시나리오 B(강화 후)**: 운영자가 incident에 `INSTRUCTOR_TOKEN`을 추가한다. SIEM의 승격 요청이 401을 받지만 코드가 응답을 검사하지 않아 **로그 한 줄 없이 전부 실패**한다. 화이트팀은 "인시던트가 안 생긴다"만 관찰하고 원인을 못 찾는다.

### MEDIUM-15 — SIEM/EDR 테스트 공백 (G27, G28)
**근거**: `tests/unit/test_siem_engine.py`(52 LOC)는 `_event_epoch`만. 파서 4종·`SqliteBackend`·`AlertStore`·`sigma_loader`·`NoiseGenerator`·threshold/sequence/periodicity 평가 경로에 대한 테스트 파일 0건. `tests/unit/test_ics_detection.py`가 twin 파서+match 룰 경로 1건을 커버하는 유일한 통합 지점.
**발생 시나리오**: Zeek 파서의 컬럼 매핑을 수정한다. 회귀 테스트가 없으므로 잘못된 필드 시프트가 배포되고, 훈련 당일에야 "탐지가 안 된다"로 발현된다.

### LOW-16 — severity 스케일 3자 불일치 (G-3B)
`shared/siem_schema.py:33`(0~4) ↔ ics/cloud 룰(5) ↔ `api/main.py:57` `_SEV_MAP`(3~5). Sigma 로더도 0~4 매핑(`sigma_loader.py:15`). Sigma로 임포트한 critical 룰은 severity 4가 되어 인시던트 승격 임계(5) 미달.

### LOW-17 — 룰 로더에 스키마 검증 없음
`api/main.py:86` `d["id"], d["title"], d["severity"]`가 직접 인덱싱. YAML에 키 하나 빠지면 모듈 import 시점 `KeyError`로 **SIEM 서비스 전체가 기동 실패**한다. 룰 파일 편집은 훈련 준비 중 흔한 작업이다.

### LOW-18 — 저장소 위생 (G30)
- `dashboards/siem/src/{api,components/Discover,components/`, `dashboards/livefire/src/{api,store,components/AssetMap,components/` — brace-expansion 미전개 오타로 생성된 실제 디렉토리.
- `services/siem/api/siem.db`, `siem_alerts.db`, `services/edr/api/edr.db`, `services/incident/incidents.db` — 런타임 SQLite가 커밋돼 있다. 컨테이너는 볼륨 경로(`DATA_DIR`)를 쓰므로 무해하나, 로컬 실행 시 이전 훈련 데이터가 섞인다.

### LOW-19 — 노이즈 생성기 미사용 + 커버리지 편중 (G29)
`docker-compose.yml:99` `SIEM_NOISE_ENABLED=false`. 활성화해도 `noise_generator.py:30-34`가 레거시 3종 트윈 엔드포인트만 생성해 ICS 8종·cloud_native 노이즈가 없다. `is_noise` ground-truth 라벨(`:27`)은 파이프라인 어디서도 이벤트에 실리지 않는다(`api/main.py:220-222`가 JSON을 재구성할 때 누락) → 오탐 트리아지 채점 불가.

### LOW-20 — tail 태스크 낭비
`api/main.py:256-260`이 TWIN_ASSETS 12종 × zeek 5종 = 60개 + suricata 12개 태스크를 생성하나 실제 사이드카는 11개 자산분(cloud_native 없음). 6개 태스크가 영구히 0.5초마다 `Path.exists()`를 호출한다. 규모 확장 시(§F축) 태스크 수가 자산수×6으로 선형 증가.

---

## 8. UNVERIFIED 목록

| # | 미확인 사항 | 확인 방법 |
|---|---|---|
| U1 | Suricata `eve.json`의 실제 flush 지연. `infra/suricata/suricata.yaml:16-25`에 `buffer-size`/`flush` 지정이 없어 이미지 기본값에 의존 | `docker compose up gs_suricata` 후 컨테이너 내에서 `suricata --dump-config \| grep -i 'eve\|buffer'` 실행. 또는 트래픽 주입 후 `stat -c %Y eve.json` 변화 시각 측정 |
| U2 | Zeek ASCII writer의 버퍼 flush 간격 및 실제 로그 로테이션 주기 | `docker exec gs_zeek zeek -e 'print Log::default_rotation_interval; print LogAscii::…'`, 또는 `zeekctl config` |
| U3 | **G3(Zeek 헤더 레이스)의 실제 발생 확률.** 코드상 레이스는 확정이나, Zeek의 파일 생성-헤더기록 타이밍과 tailer 0.5초 폴링의 상호작용은 실측 필요 | siem_api와 사이드카를 함께 기동 후 `curl :8040/search?source_type=zeek` 로 이벤트 수 확인. 0건이면 G3 확정 |
| U4 | Zeek `tcp_inactivity_timeout` 기본값(5분 가정)이 이 이미지에서 유효한지 | `docker exec gs_zeek zeek -e 'print tcp_inactivity_timeout;'` |
| U5 | `network_mode: service:<twin>` 사이드카가 트윈의 `internal: true` 네트워크에서 실제로 어떤 트래픽을 보는지(게이트웨이 경유분만인지, Modbus 502 포함인지) | 사이드카 내부에서 `tcpdump -i eth0 -c 50` 후 SIEM `/sources/health`의 `suricata:*` 카운터 대조 |
| U6 | `docker-compose.yml:106` siem_logs가 siem_api에 `:ro`로 마운트 — 읽기만 하므로 문제없어 보이나, `LOG_DIR`에 대한 쓰기 시도(예: 자산 서브디렉토리 생성)가 없는지 | 코드상 쓰기 호출은 발견되지 않았으나 런타임 EACCES 여부는 기동 확인 필요 |
| U7 | dashboards/siem·edr 콘솔의 실제 배포 경로. compose에 서비스가 없고 `docker-compose.yml:528` 주석이 "Node 개발서버로 별도 기동 권장"이라고만 함 | `Makefile`·`scripts/training_environment.py`에서 dev 서버 기동 명령 확인 |
| U8 | `services/incident/model.py:find_resolvable`의 상관 정확도(호스트명 매칭 방식) | `tests/unit/test_incident_correlate.py` 내용 확인 및 실행 |
| U9 | SIEM `/search` FTS5 쿼리의 인젝션/성능 특성(`sqlite_backend.py:165-186`) | 부하 테스트 및 `text` 파라미터에 FTS5 특수문자 주입 |
| U10 | Modbus TCP(502) 트래픽이 Suricata sid:1000005로 실제 탐지되는지. 룰이 `content:"\|00 00 00 00 00 06\|"; offset:2; depth:6`로 MBAP 헤더를 노리는데 오프셋 계산 검증 필요 | Modbus write 요청 발생 후 `eve.json`에서 sid 1000005 검색 |

---

## 9. 검증된 것 (반박용 기록)

칭찬이 아니라, "미구현"으로 오판하지 않기 위한 확정 사실이다.

- EDR 텔레메트리는 실제다: `shared/edr_agent.py:43-67` psutil 프로세스+inet 연결 수집, `requirements.txt:9` psutil==6.0.0.
- EDR kill은 실제 프로세스를 죽인다: `edr_agent.py:112-119` SIGTERM→SIGKILL 승격. 큐-폴링 구조(`edr/api/main.py:432-437` → `edr_agent.py:128-131`)와 server_pid 보호(`edr/api/main.py:422-424`)도 구현됨.
- periodicity(비콘) 엔진은 노트가 주장하는 대로 실존한다: `engine.py:66, 130-162, 233-251`.
- 대시보드에 하드코딩 목업 데이터는 없다(§6).
- `observability`의 Prometheus 텍스트 렌더는 손수 구현이지만 형식상 정확하다(`metrics.py:321-336`).
- ICS Modbus 탐지 경로는 테스트로 계약 고정돼 있다: `tests/unit/test_ics_detection.py:9-30`.
