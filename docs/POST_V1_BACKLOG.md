# POST-V1 백로그 & v1.0 위험 수용 기록

- 작성일: 2026-09-30
- 근거: `audit/101_reaudit.md`(Phase 1 재감사) + 릴리스 책임자 결정(Phase 2 = Showstopper 잔여만 마감, 나머지는 백로그+위험 수용).
- 스코프 동결(마감 규칙 3): v1.0 에서는 신규 챌린지·트윈·기능을 추가하지 않는다. 아래는 v1.0 이후 개선 후보와, v1.0 출시에 한해 위험을 수용하는 항목의 사유를 명시한다.

---

## 1. v1.0 위험 수용 (Showstopper 잔여 — 코드 완결 불가/운영 경로 한정)

| ID | 잔여 | 위험 수용 사유 | 후속 |
|---|---|---|---|
| S-10 | 팀 롤백 시 prod k8s PVC 에 공격자 웹셸 데이터 잔존 가능 | sandbox(emptyDir) 경로는 롤아웃 시 소거되어 안전. prod PVC 경로만 해당하며, v1.0 표준 배포는 docker-compose/sandbox. 리셋 계통(RESET_TARGETS 8종)·다운타임 보정은 FIXED. | prod k8s 롤백 시 PVC purge 옵션(런타임 k8s 검증 필요) |
| S-11 | 48~72h 다일 내구성 → **SIEM 저장소 rollover/retention 코드 완비(feat/multiday-durability)** + RSS 기울기 **서빙계층 귀속 확정**(바운디드 소크, py_objects 평탄·§3.1(b)). 잔여: 48~72h 실소크 내구성 실측(환경 바운드, §3.1(c) UNVERIFIED) | mem_limit(70개)·하드닝 오버레이 3경로 로드·event_collector retention 은 코드상 완비. SIEM SQLite(events+FTS, alerts) age-retention + 트윈 access 로그 크기 rotation 신규(아래 §3.1). RSS +13.28 MiB/h 는 fail 임계 20 미만(파국 아님). | 48~72h 실소크(RSS 기울기/디스크 상한 실측) — 환경 바운드 |
| S-3 (잔여) | (a) 담합 탐지가 `passed` 를 뒤집지 않음 (b) 비-스코프(dev) 제출이 body team_id 신뢰 | (a) 담합은 신호만 방출하고 교관이 판정 = 의도된 SOC 주체성 설계. (b) 실경쟁(`range_scope.is_team()`)에서는 identity 로 override 되어 무력화. dev 모드에서만 신뢰. | 담합 정책의 자동 무효화 옵션(교관 설정), 비-스코프 제출 하드닝 |
| S-7 (잔여) | 막힌 stage 교관 강제 unlock/skip 엔드포인트 없음 | 크로스오버 정답 제출→해금 경로는 FIXED(완주 가능). 강제 override 는 운영 편의 기능. | 교관 force-advance API |
| R-1 | ~~`/replay/events` 무한 fetchall 이 대용량 events.db 에서 event_collector OOM~~ → **v1.1.0 에서 FIXED(PR #115)** | Phase 3 리허설 발견(audit/102 §3). | **해소**: reconcile·AAR 을 커서 페이지네이션 `/replay/page` 배치 소비로 전환(`shared/replay_client.py`). 라이브 검증(2500 이벤트 2페이지·OOM 없음). |

> **핵심 Showstopper 잔여 3건(S-3 배포 시크릿·S-8 유실 가시성·S-9 A/D XFF)은 Phase 2 에서 코드로 FIXED.** 위 잔여는 설계 결정이거나 런타임/운영 경로 한정.

---

## 2. 2차 결함(§2) 백로그 — v1.0 위험 수용

`audit/101_reaudit.md §2` 재판정에서 OPEN/PARTIAL 로 남은 항목. 릴리스 책임자 결정에 따라
v1.0 에서는 위험 수용하고 아래에 개선 후보로 이관한다(신규 기능 = 스코프 동결).

### 2.1 신규 기능성(스코프 동결 대상)
| T-# | 내용 | v1.0 영향 | 후속 |
|---|---|---|---|
| T-13 | Lateral Movement 문제 1건뿐 | IT→OT 피벗 훈련 폭 제한(치명 아님) | 피벗 챌린지 추가 |
| T-14 | Sigma 로더 데드코드(호출부 0) | 자체 규칙 66종은 동작. 공개 Sigma 룰셋 미사용 | 로더 배선 또는 제거 |
| T-17 | EDR 5초 미만 프로세스 미탐지 | 폴링 5s 간격의 구조적 한계 | eBPF/감사서브시스템 기반 즉시 포착 |
| T-18 | EDR isolate 가 앱레이어(503), L3 아님 | 격리 시연은 가능, 실 L3 차단 아님 | iptables/네트워크 정책 기반 격리 |
| T-19 | NOC 자산 3종만 헬스 등록 | 트윈 다수의 헬스/복구 자동판정 부재 | TWIN_HEALTH_URLS 확장 |
| T-23 | PCAP 자동 캡처 없음(sanitize본만) | 원시 패킷 증거 부재 | suricata pcap-log + 보존 정책 |

### 2.2 채점/품질(위험 수용, 후속 검토)
| T-# | 내용 | 사유 | 후속 |
|---|---|---|---|
| T-1 | `asset_compromised` 물리 파국이 점수 미연결 | ICS 침해는 이벤트/AAR 에 기록되나 직접 배점 없음 | 물리 피해 배점 연동 |
| T-7 | 부분점수 미부여(`got` 계산·보고만, 만점 부여) | 정답 판정은 정확, 부분점수는 설계 확장 | grader `got` 비율 배점 |
| T-30 | 체커 시크릿 전팀 공유(팀별 파생 K8s만) | docker-compose 데모 한정. K8s 경로는 팀별 파생 | compose 경로 팀별 파생 |
| T-8 | 광고 배점 상한 불일치(FOR-003/ICS-006/NET-001/NET-003) | 광고 상한 소스 미확정(UNVERIFIED) | 상한 소스 대조·정정 |
| T-24 | Event.actor enum(red/blue/system) | 개인 귀속은 portal 계층(assessment.py, by=subject)에서 제공 | 이벤트 레벨 개인 actor |
| T-27 | 탐지형 챌린지 타임스탬프 비결정성(seed는 고정) | 데이터 내용은 결정적, 타임스탬프만 상대 | t0 고정 옵션 |
| T-28 | restart/healthcheck 정책 소수 | 컨트롤 플레인 자동복귀 부분 적용 | 전 서비스 healthcheck/restart |
| T-29 | 아티팩트 공용경로 동시요청 레이스 | per-team 복합키 생성, 고정 파일명 write→read 창 | per-request 임시 경로 |
| T-2/T-5/T-6/T-9/T-22 | Modbus 배포 도달·인젝트 studio 통합·힌트 차감·Blue 배점·NTP | PARTIAL(핵심은 동작) | 각 항목 완결 |

---

## 3. 런타임 확정 위임(Phase 3/4)

코드/CI 로는 FIXED 이나 실기동으로만 최종 확정되는 항목(샌드박스 제약상 별도 세션/환경):
- Phase 3 리허설: U-1(Modbus 502)·U-4(격리 egress)·U-8(체커 실 HTTP)·U-9(prod 프로파일)
- Phase 4 소크: U-3(포화점)·U-6(8h OOM)·S-11(rollover)
- U-2(공격→SIEM 지연): 측정 하네스 신규(Phase 3에서 간단 계측)

### 실측 결과(Phase 3/4)
- **Phase 3 무인 리허설 — PASS (13/0)** · 산출물 `loadtest/results/rehearsal_latest.json`.
  Live Fire 킬체인 5/5 200·원장 완전성(발행=원장)·dlq_drop 0·점수-원장 일치·SIEM 경보 src_ip
  귀속·AAR PDF 200(한글 폰트)·A/D 2라운드 수락.
- **Phase 4 8h 정식 소크(2026-10-02~03) — 부하 CLEAN, RSS WARN** · 산출물
  `loadtest/soak/results/*20261002T231634Z*`, `soak_report.json`.
  - 부하: 28,825s 동안 1,120,816 전송 / 1,120,814 2xx(fail 2, rate 1.8e-6), 38.9/40 req/s. 재시작·OOM 0.
  - RSS 기울기: config_service·scoring_engine·siem_api **PASS**(평탄~하락). **event_collector WARN**
    (76→157 MiB, +13.28 MiB/h; warn 임계 5 초과·fail 임계 20 미만) → S-11 관찰 지속.
  - R-1 종료 게이트: 기록상 FAIL 이었으나 **원인은 하네스 결함**(부하 `scenario_id='soak-exercise'`
    vs 게이트 조회 `'soak'` 불일치 → 빈 시나리오 reconcile/AAR). event_collector 는 무거운 replay
    후에도 health 200(= R-1 OOM 회귀 아님). **수정**: `run_soak.sh` 가 `SOAK_SCENARIO_ID` 를 단일
    소스로 export(부하·게이트 동일값). 정렬된 scenario_id 로 게이트 로직 재실측 → **PASS**
    (health 200·reconcile checked=true·AAR PDF 200 %PDF·health 200). 회귀:
    `tests/unit/test_soak_gate_scenario_id.py`. 단, 8h 성장 DB 에서의 AAR HTTPError 원인은
    미니 재현(클린 DB)에서 재현되지 않아 **UNVERIFIED** — 정식 재소크에서 최종 확인 필요.

### 3.1 다일(48~72h) 내구성 작업 (`feat/multiday-durability`, 2026-10-20)

**(a) SIEM 저장소 rollover/retention — FIXED(코드), 다일 실측 UNVERIFIED**
그동안 SIEM 에는 rollover/retention 이 전무했다(grep 결과 0). event_collector 의
`_prune_old_events()` + 백그라운드 루프 패턴을 두 종류의 SIEM 저장소로 확장했다. **커버 범위
정직 표기**:
  - **SIEM SQLite(age-retention)** — `SqliteBackend.prune_older_than()`(events + 외부콘텐츠
    FTS5 `events_fts` 를 `'rebuild'` 로 재동기화) + `AlertStore.prune_older_than()`(alerts).
    `siem/api/main.py` 에 `_prune_siem_stores()` + `_retention_loop()`(startup 기동). 임계:
    `SIEM_RETENTION_DAYS`(기본 **0=비활성**, event_collector `EVENTS_RETENTION_DAYS` 와 동일
    안전 기본값 — 운영자 명시 opt-in), `SIEM_RETENTION_INTERVAL_SEC`(기본 3600).
  - **트윈 access 로그(size-rotation)** — `shared/siem_access_log.py` 의 `FileHandler` →
    `RotatingFileHandler`. 임계: `SIEM_LOG_MAX_BYTES`(기본 **50MiB, 비활성 아님**),
    `SIEM_LOG_BACKUP_COUNT`(기본 5) → 자산당 ~300MiB 상한. file_tailer 는 inode 교체 재오픈
    설계라 rotation 호환. `SIEM_LOG_MAX_BYTES=0` 이면 기존 FileHandler(하위호환). 이것이
    §S-11 에 적힌 `siem_logs ~169MB` 무한 누적의 직접 수정이다.
  - **커버 안 함(정직)**: syslog/suricata/zeek 등 트윈 외부가 /var/log/siem 에 쓰는 로그는
    그 생성자(사이드카)의 logrotate 책임 — SIEM 코드가 쓰지 않으므로 여기선 손대지 않았다.
  - 회귀: `tests/unit/test_siem_retention.py`(age 프루닝·FTS 정합·비활성 기본값),
    `tests/unit/test_siem_log_rotation.py`(크기 롤오버·maxBytes=0 비활성).

**(b) event_collector RSS 기울기 근본원인 — 범위 축소(write 경로 무죄 입증), 최종 귀속 UNVERIFIED**
  - **실측(로컬, `python3` 단일 스레드로 real `_persist_batch` 20만건 구동)**: events.db 가
    **259MiB 까지 성장해도 프로세스 RSS 는 평탄(±1MiB), 파이썬 객체수 평탄, WAL ~6MiB 로 bounded**
    (autocheckpoint). → **수집·저장·저널 경로(소크 부하의 80% POST /events 의 DB 부분)는 RSS 를
    누수하지 않음이 증명됨.** 가장 유력했던 가설("SQLite 워킹셋이 무한 성장 DB 와 함께 증가")은
    이 write 경로에 대해 **반증**됨.
  - **결론(정직)**: +13.28 MiB/h 는 DB/저널 on-disk 성장이 아니라 **비동기 서빙 계층**
    (이벤트당 httpx scoring 포워드 태스크 + asyncio/starlette 요청 객체 + 지속 동시성 하의
    glibc malloc arena 단편화)에서 발생할 가능성이 높다. 이는 단일 스레드 미니 재현으로는
    복제 불가(실 uvicorn 루프 + 장시간 필요) → **INCONCLUSIVE, 환경 바운드**.
  - **조치(추측 대신 계측)**: `/metrics` 에 `memory` 키 추가 — `rss_bytes`·`py_objects`·
    `gc_counts`·`sse_buffer_len`·`sse_subscribers`·`checkpoint_counters`·
    `forward_tasks_inflight`·`ws_clients`·`db_bytes`/`wal_bytes`/`shm_bytes`. 다음 장시간 소크가
    RSS 상승 시 **어느 카운터가 같이 오르는지**로 (a)파이썬 힙 누수 vs (b)on-disk 성장을 데이터로
    지목한다(py_objects 평탄 + db 성장 = 서빙계층/할당자; py_objects 선형 = 파이썬 누수).
  - 회귀: `tests/unit/test_event_collector_memory.py`(계측 키 존재·경계 구조 상한).
  - **귀속 확정(2026-10-20, 바운디드 소크 실측)**: 위 `/metrics.memory` 계측으로 서빙 경로를
    10분(rate 60·SSE 구독자 3) 소크하며 20s 간격 샘플. **정상상태(t=60~601s)에서 RSS +13.3 MiB/h**
    (문서화된 +13.28 과 일치)인데 **py_objects 는 평탄**(~86.5k, 추세 없음), `sse_buffer_len` 은
    2000 cap 에 고정, `forward_tasks_inflight` 0~1. 초기 t=0~60s 급증은 워밍업(SSE/워커풀 1회 할당).
    → **판정: 파이썬 객체 누수 아님(py_objects 평탄). 서빙계층/glibc-allocator RSS 리텐션으로 귀속**
    (gap4 가설 데이터로 확증). 남은 미확인은 "그 기울기가 48~72h 에 OOM 까지 가는가 / 고원에서
    멈추는가"의 **내구성**뿐(아래 (c), 환경 바운드).

**(c) 48~72h 내구성 증명 — UNVERIFIED(환경 바운드).** 실 48~72h 소크는 여기서 불가.
  정식 실행 명령:
  ```bash
  # 72h 소크. SIEM retention 도 켜서 다일 디스크 상한을 함께 검증:
  SOAK_DURATION_SEC=259200 SIEM_RETENTION_DAYS=2 EVENTS_RETENTION_DAYS=2 \
      bash loadtest/soak/run_soak.sh
  ```
  **watch 게이트**: (1) `loadtest/soak/results/mem_samples.*.csv` 의 event_collector RSS 기울기
  (fail 임계 20 MiB/h, warn 5) — 이번에 추가한 `/metrics` `memory` 를 병행 샘플링해 귀속;
  (2) OOM/재시작 0; (3) events.db/siem.db/access 로그가 retention·rotation 상한 아래로 묶이는지
  디스크 실측; (4) R-1 종료 게이트 PASS.

---

## 4. 일반 개선 아이디어(비결함)
- pydantic `register` 필드 shadow 경고·JWT 짧은 키 경고 정리(테스트 위생).
- docker-compose `version` obsolete 속성 제거.
- HANDOFF/문서의 라인 번호 참조를 심볼 기반으로 전환(코드 확장 시 stale 방지).
