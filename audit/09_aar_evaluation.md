# I축 감사 — AAR·평가 (After-Action Review / Assessment)

감사 방식: 정적 분석 전용(도커·make·training 미실행). 모든 판정은 `경로:라인` 근거를 가진다.
문서에 서술된 기능은 근거로 채택하지 않았다.

---

## 1. 요약 판정 테이블

| # | 항목 | 판정 | 근거 (path:line) | 실전 영향 |
|---|---|---|---|---|
| 1 | 다중 저장소 통합 타임라인 | **없음** | `services/aar_report/main.py:51` 이 유일한 이벤트 소스(event_collector `/replay/events`). attack_defense audit_events(`services/attack_defense/evidence.py:56`), challenge_portal submissions(`services/challenge_portal/anticheat.py:95`), siem 원시 이벤트(`services/siem/storage/sqlite_backend.py:35`)를 읽는 코드 없음 | 사고 재구성 시 A/D 플래그 제출·챌린지 제출·네트워크 로그가 타임라인에서 통째로 빠진다 |
| 2 | 시계 동기(NTP/단일 시계원) | **없음** | 전 저장소 grep에서 ntp/chrony/시계원 설정 0건. 타임스탬프는 각 프로세스 `datetime.now()`(`shared/event_schema.py:63-64`) | 컨테이너/호스트 시계 편차만큼 MTTD/MTTR이 왜곡. 음수 MTTD도 가능 |
| 3 | 이벤트 순서 보장(단조 증가 ID) | **없음** | events 테이블에 시퀀스 컬럼 없음(`services/event_collector/main.py:85-101`), 정렬은 `ORDER BY timestamp ASC` 단일 키(`:271`) — 동일 timestamp 타이브레이크 없음. python-ulid는 SIEM 파서에서 로그라인 id로만 사용(`services/siem/parsers/twin.py:13`) | 동시각 이벤트(공격↔탐지)의 선후가 매 조회마다 달라질 수 있어 "누가 먼저였나" 판정 불가 |
| 4 | 개인(개인별) 역량 추적 | **불가** | `Event`에 사용자 식별자 필드 없음 — actor는 red/blue/system 3값 enum(`shared/event_schema.py:50-53`), 최소 단위가 `team_id`(`:72`). scoring_engine도 team 단위(`services/scoring_engine/main.py:71-76`) | 개인 수료·개인 성적표 발급 불가. 팀 총점만 산출 |
| 5 | NICE Framework / KSA / 학습목표 매핑 | **미구현** | `NICE`·`KSA`·`learning_objective`·`competency`·`work_role` 전수 grep 0건(py/ts/tsx/json/yml/yaml) | AAR은 "점수 집계"이지 "역량 평가"가 아니다. 교육기관 인증·NICE 매핑 요구를 충족 못 함 |
| 6 | PCAP 자동 캡처 | **없음** | Suricata 설정 outputs에 eve-log만 존재, `pcap-log` 없음(`infra/suricata/suricata.yaml:16-27`). tcpdump 컨테이너/사이드카 0건. PCAP은 **운영자 수동 업로드만**(`services/attack_defense/api.py:1040-1043`) | 훈련 중 트래픽 원본은 남지 않는다. 운영자가 별도 수단으로 뜬 파일을 업로드해야만 PCAP 증거 존재 |
| 7 | 원시(무가공) PCAP 보존 | **없음(설계상 폐기)** | `CaptureService.ingest`는 sanitize 결과만 디스크에 기록(`services/attack_defense/pcap_privacy.py:610`, `_write_atomic`), 원본은 `raw_sha256`만 DB에 남김(`:617`) | 익명화 버그가 나중에 발견돼도 원본 재처리 불가. 법적 증거로서의 원본 부재 |
| 8 | 보존기간·용량 산정·롤오버 | **없음** | pcap_privacy에 삭제/만료 경로 0건(`unlink`는 임시파일 정리 `:781`뿐). siem_logs·events.db·captures 어디에도 retention/rotate 코드 없음 | 장기 운용 시 볼륨 무한 증가 → 디스크 고갈로 훈련 중단 |
| 9 | AAR 산출물(PDF) 영속성 | **소실됨** | `PDF_OUTPUT_DIR=/tmp/aar_reports`(`services/aar_report/main.py:36`), compose의 aar_report 서비스에 volumes 절 자체가 없음(`docker-compose.yml:140-152`) | 컨테이너 재생성 즉시 생성된 AAR PDF 전량 소실 |
| 10 | 리포트 replay(재생) 기능 | **부분(데이터만)** | 백엔드 `/replay/events` 존재(`services/event_collector/main.py:255`), 프론트 함수 `fetchReplayEvents` 정의(`dashboards/livefire/src/api/client.ts:38`)되나 **호출처 0건**(grep 결과 정의 라인만 매치) | 타임라인 재생 UI 없음. 사후 검토는 JSON 수동 조회로만 가능 |
| 11 | writeups(ANSWER-KEY) 노출 | **노출 없음** | `docs/writeups/` 를 참조하는 Dockerfile COPY·nginx location 0건. gateway는 `/usr/share/nginx/html` 하위만 서빙(`infra/gateway/nginx.conf:34-43`) | 정답지 유출 경로는 리포지토리 접근 통제에만 의존 |
| 12 | AAR API 인증 | **없음** | `services/aar_report/main.py` 전체에 `require_role`/`require_read` 호출 0건. 호스트에 8090 직접 공개(`docker-compose.yml:143`), gateway에는 AAR 라우트 없음(`infra/gateway/nginx.conf:46-59`) | 훈련 중 참가자가 8090에서 상대 점수·미탐지 기술 목록(정답 힌트)을 무인증 열람 가능 |

---

## 2. 증거 소스 × 저장소 × 볼륨 × 보존정책 매트릭스

| 증거 종류 | 생성 주체 | 저장소 | 볼륨 | 컨테이너 삭제 시 | 보존정책 | AAR이 읽는가 |
|---|---|---|---|---|---|---|
| Range 이벤트 | 트윈/시나리오엔진 → event_collector | SQLite `/data/events.db` (`services/event_collector/main.py:28`) | `ec_data:/data` (`docker-compose.yml:27`) | 보존 | 없음(무한 증가) | **예** (`main.py:51`) |
| 점수/achievements | scoring_engine | SQLite (`services/scoring_engine/main.py:61-76`) | `sc_data` (`docker-compose.yml:1068`) | 보존 | 없음 | 예(단, prod에서 401 — §5-2) |
| SIEM 정규화 로그 | siem 파서 | SQLite events (`services/siem/storage/sqlite_backend.py:35`) | `si_data:/data` (`docker-compose.yml:105`) | 보존 | 없음 | **아니오** — 가장 필드가 풍부한(source_ip/host/trace_id) 저장소를 AAR이 전혀 조회하지 않음 |
| SIEM 알림 | detection engine | SQLite alerts (`services/siem/storage/alert_store.py:29`) | `si_data` | 보존 | 없음 | 예(최근 100건 한정 — §5-3) |
| Suricata/Zeek 원시 로그 | 사이드카 | 파일 `/var/log/siem/<asset>/` (`docker-compose.yml:782,794`) | `siem_logs` (`docker-compose.yml:780`) | 보존 | **없음** — logrotate 미설정, tailer는 rotate 대응만(`services/siem/ingestion/file_tailer.py:48`) | 아니오 |
| PCAP(sanitized) | 운영자 수동 업로드 | 파일 `/data/captures` (`docker-compose.yml:268`) | `ad_data:/data` (`:235`) | 보존 | 없음 | 아니오 |
| PCAP(raw) | — | **저장 안 함** (`services/attack_defense/pcap_privacy.py:610`) | — | — | — | 아니오 |
| A/D 감사이벤트 | attack_defense | audit_events (SQLite/Postgres) (`services/attack_defense/evidence.py:56`) | `ad_data`/`ad_postgres_data` | 보존 | 없음 | **아니오** |
| 챌린지 제출 이력 | challenge_portal | SQLite submissions (`services/challenge_portal/anticheat.py:95`) | `cp_data:/data` (`docker-compose.yml:502`) | 보존 | 없음 | 담합 플래그 집계분만(`main.py:81`), 원 제출 이력은 아님 |
| AAR PDF | aar_report | 파일 `/tmp/aar_reports` (`main.py:36`) | **없음** | **전량 소실** | — | (산출물) |

---

## 3. AAR 리포트 섹션별 데이터 출처

| 리포트 섹션 | 코드 위치 | 데이터 출처 | 실데이터 / 하드코딩 / 조용한 fallback |
|---|---|---|---|
| `summary.teams`, `final_scores` | `main.py:100-101` | scoring_engine `/scores` | **fallback `{"teams": {}}`** — HTTP 실패 시 예외 없이 빈 dict(`main.py:61-62`). PDF는 "점수 데이터 없음" 출력(`pdf/render.py:77`) |
| `summary.generated_at` | `main.py:102` | `time.time()` | 실데이터(생성시각) |
| `red_performance.stages_completed` | `main.py:94,105` | event_collector stage_completed 개수 | 실데이터 |
| `red_performance.flags_obtained` | `main.py:95,106` | flag_exfiltrated 개수 | 실데이터 |
| `red_performance.stealth_bonus_total` | `metrics.py:106-110` | red_stealth_bonus 이벤트 | **항상 0** — 해당 이벤트를 발행하는 코드가 저장소에 없다(전수 grep: enum 정의 `event_schema.py:38`, 소비처 `scoring_engine/main.py:205`, 집계 `metrics.py:109` 3곳뿐). 또한 `metadata.get(...,10)`의 **하드코딩 기본점수 10**(`metrics.py:108`)이며, 여기만 `_metadata()` 정규화를 안 써서 metadata가 JSON 문자열이면 `AttributeError` |
| `blue_performance.mttd_sec` | `metrics.py:40-59` | 이벤트 상관 | 실데이터. 매칭 0건이면 `None` → PDF "N/A"(`pdf/render.py:93`) |
| `blue_performance.mttr_sec` | `metrics.py:62-72` | `metadata.dwell_sec` (recovery_watcher가 기록, `services/core/recovery_watcher.py:84`) | 실데이터 |
| `blue_performance.detection_rate` | `metrics.py:78-93` | 이벤트 상관 | 실데이터 |
| `blue_performance.false_positive_rate` | `metrics.py:96-103` | SIEM alerts의 `source_event_id` | **구조적으로 항상 0.0** — alerts 테이블에 `source_event_id` 컬럼이 없다(`services/siem/storage/alert_store.py:29-37`). 저장소 전체에서 alert에 이 키를 넣는 코드 0건. `None`이 아니라 0을 반환하므로 리포트에 "오탐률 0%"가 실린다 |
| `attack_heatmap` / `uncovered_techniques` | `attack_heatmap.py:42-72` | 이벤트 `metadata.mitre` + alert `mitre` | **이벤트 측 입력이 항상 비어 있음** — 어떤 서비스도 이벤트 metadata에 `mitre`를 넣지 않는다(twin 파서는 명시적으로 `mitre=[]`, "다음 확장"으로 유예: `services/siem/parsers/twin.py:73`; scenario_engine stage 메타는 stage/name/points만: `services/scenario_engine/runner.py:80`). 결과적으로 `occurred=True`가 서지 않아 `uncovered_techniques`는 **항상 빈 리스트** |
| `recommendations` | `recommendations.py:5-22` | 위 지표 | **하드코딩 임계값** MTTD>180초(`:8`), FP>0.3(`:13`), 그리고 갭 미검출 시 **"특별한 개선 권고 사항 없음 — 탐지 성능이 양호합니다."**(`:21`) |
| `incident_management` | `main.py:79,119` | incident `/incidents` | **prod에서 조용히 빈 값** — 해당 엔드포인트는 `require_read` 게이트(`services/incident/main.py:154`)이고 prod는 `OBSERVER_READ_ENFORCE=true`(`docker-compose.prod.yml:49`), 그런데 AAR은 Authorization 헤더를 보내지 않는다(`main.py:75-78`) → 401 → `_get_json`이 예외를 삼키고 `[]` 반환 → `total:0, breached:0` |
| `crisis_comms` | `main.py:80,120` | injects `/injects/scoreboard` | 동일(`services/injects/main.py:267`, `docker-compose.prod.yml:51`) → `teams:0` |
| `integrity` | `main.py:81,121` | challenge_portal `/portal/anticheat/flagged` | 실데이터(해당 엔드포인트는 인증 없음, `services/challenge_portal/main.py:386`). 다만 **scenario/match 필터 없음** — 전 훈련 누적 담합 사례가 이번 AAR에 실림 |
| `ics_protocol_attacks` | `integrations.py:128-142` | 이벤트 `metadata.protocol` | 실데이터(트윈이 기록, `shared/ics/twin_modbus.py:77` 계열) |
| `ics_lifecycle` | `integrations.py:78-125` | 이벤트 | 실데이터. 단 MTTR은 "첫 침해→첫 복구" 1쌍만 사용(`:110-112`) — 반복 침해/복구는 무시 |
| PDF "ATT&CK 커버리지 갭" 문구 | `pdf/render.py:107-108` | `uncovered_techniques` | **거짓 긍정 문구** — 위 사유로 갭이 항상 비어 "전 기술 탐지 커버리지 확보"가 무조건 인쇄된다 |

### 테스트 커버리지 판정
`tests/unit/test_aar_metrics.py`(100), `test_aar_integrations.py`(73), `test_aar_heatmap.py`(59), `test_aar_ics_lifecycle.py`(56) 4개 파일 모두 **순수함수에 합성 dict를 직접 주입**한다(예: `tests/unit/test_aar_ics_lifecycle.py:8-12`의 `_ev()` 팩토리). httpx/respx/TestClient/mock 사용 0건 — 즉 `main.py`의 실제 데이터 수집 경로, PDF 렌더 경로, 인증 헤더 누락, alert 스키마 불일치는 **어떤 테스트도 커버하지 않는다**. `services/aar_report/main.py`·`pdf/render.py`를 import 하는 테스트는 존재하지 않는다(전수 grep). 유일한 종단 검증은 런타임 스모크(`scripts/smoke_test.sh:200-215`)이며 이는 값의 정확성이 아니라 응답 여부·PDF 매직바이트만 확인한다.

---

## 4. 타임라인 재구성 가능성 판정

**판정: 부분 가능 — "특정 시각 특정 팀"까지만. "특정 인원"과 "다중 소스 통합"은 불가.**

가능한 것
- 시각 정밀도: `timestamp`는 float epoch(`shared/event_schema.py:63-64`) — 마이크로초급 표현 가능. 정밀도 자체는 충분.
- 팀 축: `team_id`(`:72`)·`scenario_id`(`:73`) 존재, `/replay/events`가 scenario_id + 시간범위 + team_id 필터를 제공(`services/event_collector/main.py:255-274`).
- 공격↔탐지 상관: `trace_id`/`matched_event_id`(`:78-79`)와 두 키를 모두 해석하는 조인(`services/aar_report/metrics.py:25-37`).

불가능한 것
1. **행위자 해상도 부족.** actor는 red/blue/system 3값 enum(`shared/event_schema.py:50-53`). 어느 사람이, 어느 워크스테이션에서 했는지 필드가 없다. 소스 IP/호스트 필드도 Event에 없다(SIEM 정규화 이벤트에는 `source_ip`/`host`가 있으나 `services/siem/storage/sqlite_backend.py:39-41` — AAR은 이 테이블을 조회하지 않는다).
2. **통합 타임라인 코드 부재.** 4개 저장소(event_collector SQLite / siem SQLite / attack_defense SQLite·Postgres / challenge_portal SQLite)를 하나의 정렬된 스트림으로 병합하는 함수·엔드포인트가 저장소에 없다. `services/aar_report/main.py:51-81`은 6개 서비스를 호출하지만 결과를 **섹션별 요약값**으로만 쓰고, 시간순 병합을 하지 않는다. A/D 매치의 플래그 제출·패치 시각(`services/attack_defense/evidence.py:56`의 audit_events)은 AAR 어디에도 들어오지 않는다.
3. **시계원 단일화 없음.** NTP/chrony 설정 0건. 유일한 시계 방어는 attack_defense 내부 DB 시계 편차 상한(`services/attack_defense/config.py:29`, `docker-compose.yml:337`)으로, 다른 서비스에는 적용되지 않는다. 저장소가 다르면 서로 다른 시계로 찍힌 타임스탬프를 그대로 비교하게 된다.
4. **동시각 순서 미정의.** 정렬 키가 timestamp 단일(`services/event_collector/main.py:271`)이고 단조 증가 시퀀스가 없다. `received_at`(`:100`)은 초 단위(`strftime('%s','now')`)라 타이브레이크로도 부족하다.

---

## 5. 결함 목록 (심각도 순)

### C1 (치명) — 오탐률이 구조적으로 항상 0%로 보고된다
`services/aar_report/metrics.py:102`는 alert의 `source_event_id`로 노이즈 여부를 판정하는데, alerts 스키마에 그 컬럼이 없고(`services/siem/storage/alert_store.py:29-37`) 저장 시에도 넣지 않는다(`:46-52`). alerts가 1건이라도 있으면 `fp_count=0`, 반환값 `0.0`. `None`이 아니므로 "데이터 없음"으로 표시되지도 않는다.
**발생 시나리오:** 노이즈 생성기(`services/siem/detection/noise_generator.py:57`, team_id="noise")로 Blue를 오탐 트리아지 훈련시킨 뒤 AAR을 뽑으면, 실제로 Blue가 노이즈에 수십 번 낚였어도 리포트에는 "오탐률 0%"와 함께 "탐지 성능이 양호합니다"(`recommendations.py:21`)가 인쇄된다. 평가 결과가 사실과 반대로 나간다.

### C2 (치명) — ATT&CK 커버리지 갭이 항상 "갭 없음"으로 보고된다
히트맵의 `occurred`는 이벤트 `metadata.mitre`에서만 세워지는데(`services/aar_report/attack_heatmap.py:53-56`), 이벤트에 mitre를 채우는 생산자가 없다. twin 파서는 주석으로 미구현을 명시한다: `services/siem/parsers/twin.py:73` `mitre=[],  # vuln_catalog.json과 조인해서 채우는 건 enrich 단계(다음 확장)`. 따라서 `uncovered_techniques`(`attack_heatmap.py:70-72`)는 항상 `[]`.
**발생 시나리오:** Red가 룰이 없는 기술로 침투해 목표를 달성해도, AAR PDF는 "전 기술 탐지 커버리지 확보"(`services/aar_report/pdf/render.py:108`)를 출력한다. 탐지 공백을 찾아내는 것이 AAR의 1차 목적인데 그 기능이 무력화되어 있다.

### C3 (높음) — 프로덕션에서 인시던트·위기커뮤니케이션·점수 섹션이 조용히 비워진다
AAR은 다른 서비스를 호출할 때 Authorization을 붙이지 않는다(`services/aar_report/main.py:58, 75-81`). prod 프로파일은 scoring_engine·incident·injects에 `OBSERVER_READ_ENFORCE=true`를 건다(`docker-compose.prod.yml:30,49,51`). 401은 `httpx.HTTPError`로 잡혀 각각 `{"teams":{}}`(`main.py:61-62`)과 `[]`(`main.py:76-78`)로 대체된다. aar_report는 prod 오버레이에 항목 자체가 없어 토큰을 받을 경로도 없다.
**발생 시나리오:** dev에서 잘 나오던 AAR이 실제 훈련(prod)에서는 최종점수 "데이터 없음", 인시던트 0건, 인젝트 대응률 0으로 출력된다. 아무 에러도 남지 않아 운영자는 "이번 훈련은 인시던트가 없었다"고 오독한다.

### C4 (높음) — AAR PDF가 볼륨 없는 `/tmp`에 쓰인다
`PDF_OUTPUT_DIR = /tmp/aar_reports`(`services/aar_report/main.py:36`), compose의 aar_report 정의에 volumes 절 없음(`docker-compose.yml:140-152`).
**발생 시나리오:** 훈련 종료 후 PDF를 생성하고 `docker compose down`/재배포하면 산출물이 전부 사라진다. 다운로드 응답(`main.py:136`)을 받아 각자 저장한 사람만 사본을 갖는다.

### C5 (높음) — AAR API가 무인증으로 호스트에 공개된다
`ports: ["8090:8090"]`(`docker-compose.yml:143`), main.py에 RBAC 호출 0건, gateway에 AAR 라우트 없음(`infra/gateway/nginx.conf:46-59` 목록에 부재).
**발생 시나리오:** 훈련 진행 중 참가자가 `http://<range-host>:8090/report/aar`를 호출해 상대 팀 점수, ICS 자산별 침해/복구 현황, 미탐지 기술 목록을 실시간으로 열람한다. 관전자 지연(`OBSERVER_DELAY_SEC`, `services/event_collector/main.py:30`) 통제를 그대로 우회한다.

### C6 (높음) — PCAP이 자동 캡처되지 않는다
Suricata 사이드카는 eve-log만 출력(`infra/suricata/suricata.yaml:16-27`), pcap-log 섹션 없음. tcpdump 실행 주체 0건. PCAP은 운영자가 파일을 POST해야만 생긴다(`services/attack_defense/api.py:1040-1043`, CLI 경로 `services/attack_defense/cli.py:257`).
**발생 시나리오:** 사후에 "그 순간 실제로 어떤 패킷이 오갔나"를 물으면 답할 소스가 없다. 798 LOC의 정교한 스크럽·워터마크 파이프라인(`services/attack_defense/pcap_privacy.py`)은 입력이 공급되지 않는 한 사실상 미가동이다.

### C7 (중간) — 보존기간·용량 계획이 전무하다
`siem_logs`(Suricata/Zeek 원시 로그, 15개+ 트윈이 동시 기록: `docker-compose.yml:780~854`), `ec_data`(events.db), `ad_data`(captures) 어디에도 만료/롤오버/용량 상한 코드가 없다. `/admin/reset`(`services/event_collector/main.py:349`)은 전량 삭제이지 보존정책이 아니다.
**발생 시나리오:** 다회차 운용 시 볼륨이 단조 증가하다 호스트 디스크가 차고, SQLite 쓰기 실패로 훈련 중 이벤트 수집이 멈춘다.

### C8 (중간) — SIEM alerts를 최근 100건·전 시나리오로 긁어온다
AAR은 `/alerts`를 파라미터 없이 호출하고(`services/aar_report/main.py:66`), 서버 기본 limit은 100이며 scenario 필터는 존재하지도 않는다(`services/siem/api/main.py:292`, `services/siem/storage/alert_store.py:58-72`).
**발생 시나리오:** 알림이 100건을 넘는 정상적인 훈련에서 초반 알림이 통째로 누락되어 히트맵과 오탐률의 분모가 조용히 잘린다. 동시에 직전 훈련의 알림이 이번 AAR에 섞여 들어온다. 동일한 스코프 누락이 `integrity` 섹션에도 있다(`main.py:81` — 담합 집계에 match/scenario 필터 없음, `services/challenge_portal/main.py:390-394`).

### C9 (중간) — 은신 보너스 지표가 죽은 코드이며 크래시 가능
`red_stealth_bonus` 이벤트를 **발행하는 코드가 없다**(전수 grep: 정의 `shared/event_schema.py:38`, 소비 `services/scoring_engine/main.py:205`, 집계 `services/aar_report/metrics.py:109`). 항상 0이 인쇄된다(`services/aar_report/pdf/render.py:85`). 또한 `metrics.py:108`은 같은 파일의 `_metadata()` 정규화를 쓰지 않아, metadata가 SQLite에서 온 JSON 문자열이면 `str.get` → `AttributeError` → `/report/aar` 500. 같은 계열 버그를 다른 함수들은 이미 방어하고 있다(`metrics.py:12-22`, `integrations.py:17-27`).

### C10 (중간) — 개인 단위 평가 불가·NICE 매핑 부재
§1-4, §1-5 참조. AAR이 산출하는 지표 전체 목록은 MTTD/MTTR/탐지율/오탐률/은신보너스/단계수/플래그수/ICS 라이프사이클/인시던트 SLA/인젝트 응답률 — 전부 **팀 단위 사건 집계**다. 개인의 지식·기술·능력을 관찰 가능한 행위에 매핑하는 구조(rubric, KSA 태그, 목표별 달성 판정)는 코드에 없다.

### C11 (낮음) — replay UI 미연결
`fetchReplayEvents`가 정의만 되어 있고 호출처가 없다(`dashboards/livefire/src/api/client.ts:38`). 타임라인 컴포넌트는 라이브 스토어만 읽는다(`dashboards/livefire/src/components/Timeline/EventTimeline.tsx:2`, `useRangeStore`). 시간 스크럽/재생 컨트롤 코드 0건.

### C12 (낮음) — 원시 PCAP 미보존
`services/attack_defense/pcap_privacy.py:610`이 sanitize 결과만 기록. 익명화 로직에 결함이 발견돼도 재처리할 원본이 없고, 원본 대조 검증도 `raw_sha256`(`:617`) 비교 외에는 불가능.

---

## 6. UNVERIFIED 목록

| # | 미확인 사항 | 사유 | 확인 방법 |
|---|---|---|---|
| U1 | 런타임에서 실제로 `/report/aar`가 어떤 값을 뱉는지 | 도커 실행 금지 | `docker compose up` 후 `curl :8090/report/aar` — 특히 `false_positive_rate`가 0.0인지, `uncovered_techniques`가 []인지 확인 |
| U2 | prod 프로파일에서 AAR의 incident/injects 호출이 실제 401을 받는지 | 정적 추론(RBAC 코드 + prod env)만 수행 | `docker compose -f docker-compose.yml -f docker-compose.prod.yml up` 후 incident 컨테이너 액세스 로그의 상태코드 확인 |
| U3 | Zeek `local.zeek`이 pcap을 남기는지 | `infra/zeek/local.zeek` 미정독 | 해당 파일에서 `PacketFilter`/`Log::` 설정 확인. 단 Zeek 기본은 conn.log 등 텍스트 로그이며 pcap 아님 |
| U4 | 컨테이너 간 실제 시계 편차 크기 | 실행 필요 | 각 컨테이너에서 `date +%s.%N` 동시 채취 비교 |
| U5 | events.db / siem_logs의 실제 증가율(용량 산정) | 실행 필요 | 1시간 훈련 후 `docker system df -v`로 볼륨 크기 측정 |
| U6 | `reportlab` CID 폰트(HYSMyeongJo-Medium)가 실제 뷰어에서 한글을 정상 렌더링하는지 | PDF 생성 불가 | 생성된 PDF를 pdffonts/뷰어로 확인 (`services/aar_report/pdf/render.py:21-22`) |
| U7 | 8090 포트가 참가자 네트워크에서 실제 도달 가능한지 | 네트워크 토폴로지 실측 필요 | 참가자 대역에서 `curl <host>:8090/health` |
