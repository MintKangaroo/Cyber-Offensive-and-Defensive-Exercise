# 마스터 흐름 개요 — Cyber Range 전체 그림

> 지금까지 만든 모든 문서/코드를 하나의 그림으로 정리한 캡스톤 문서.
> 처음 보는 사람도 이 문서 하나로 전체 구조와 데이터 흐름, 완성도를 파악할 수 있게 작성.

---

## 1. 한 장 아키텍처

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DIGITAL TWINS (취약 모의 인프라)                      │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐                │
│  │Ground Station│    │ Power Plant  │    │ Defense Network   │                │
│  │  GS-001~005  │    │  PP-001~005  │    │   DN-001~004      │                │
│  │  + EDR Agent │    │  + EDR Agent │    │   + EDR Agent      │                │
│  └──────┬───────┘    └──────┬───────┘    └─────────┬─────────┘                │
│         │  emit_event(trace_id, ...)                │                        │
└─────────┼──────────────────┼───────────────────────┼────────────────────────┘
          │                  │                        │
          ▼                  ▼                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          EVENT / SCORING 파이프라인                           │
│  Event Collector(8010) ──dedup+저장+WS브로드캐스트──▶ Scoring Engine(8020)     │
│       │  (matched_event_id로 dwell time enrichment)      │ 멱등 채점+reconcile │
│       └─▶ /replay/events (리플레이용)                     └─▶ /scores/history  │
└─────────┬─────────────────────────────────────────────────┬─────────────────┘
          │                                                 │
          ▼                                                 ▼
┌───────────────────────────┐               ┌───────────────────────────────┐
│   시나리오 엔진 (M3)         │               │   Instructor API (구현 완료)     │
│ 단일킬체인 stage 순서판정    │◀─────────────▶│ 시나리오 시작/종료, 이벤트주입,   │
│ 크로스오버 phase 잠금해제    │  scenario_id  │ 점수조정, 통합 audit            │
└───────────────────────────┘               └───────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                     BLUE TEAM 운영 도구 (전부 구현 완료)                        │
│  ┌────────────────┐  ┌───────────────┐  ┌──────────────────────────────┐    │
│  │ Config Service  │  │ Ansible 패치  │  │  EDR (에이전트+백엔드+콘솔)     │    │
│  │ (8030)          │◀─┤ 콘솔          │  │  프로세스 트리, 행위기반 탐지,   │    │
│  │ 패치/격리/킬스위치│  │ (화이트리스트) │  │  Isolate/Kill(실제 종료 검증됨) │    │
│  └────────┬────────┘  └───────────────┘  └──────────────┬───────────────┘    │
│           │                                             │                    │
│           └──────────────┬──────────────────────────────┘                    │
│                          ▼                                                   │
│              ┌────────────────────────┐                                     │
│              │  NOC 모니터링 + Recovery │                                     │
│              │  Watcher (health 3연속   │                                     │
│              │  + 패치확인 + 다운이력)   │──▶ asset_recovered(+50) 이벤트 발행  │
│              └────────────────────────┘                                     │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                    SIEM (대부분 구현 완료 — M5.0~M5.6)                         │
│  Ingestion(syslog UDP/TCP+file_tailer) → Parsers(twin/suricata/zeek/pfsense) │
│    → Storage(SQLite+FTS5) → Detection Engine(17종 룰, match/threshold/      │
│    sequence) → API(/search /alerts /stats /detection/attack-coverage)       │
│    → blue_detection_success로 Live Fire 점수 연동 + 노이즈 생성기             │
│  Suricata/Zeek 사이드카 실제 배치는 26번 문서(M-Net)에서 진행 예정             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│              대시보드 2종 + AAR                                               │
│  Live Fire Dashboard(구현 완료)      SIEM Dashboard(계획)   AAR(계획, MTTD/    │
│  AssetMap/Timeline/Score/            (Discover/Alerts/       MTTR,ATT&CK히트맵)│
│  Patch/Flag/Instructor 연동          SourceHealth)           PDF)             │
│  Replay/백엔드역할스코프는 미완                                                 │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│         콘텐츠 (문제 12개 구현 + 20개 계획, C-QA 파이프라인 계획)                │
│  6개 분야(웹/포렌식/탐지/AI/리버싱/네트워크) × easy~insane                      │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│   안전장치 (전부 구현+검증 완료): 시크릿스캔 / 격리테스트 / 하드닝 / 배포체크리스트│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. 데이터가 실제로 흐르는 순서 (End-to-End 시나리오 하나로 추적)

**"Red가 위성 지상국을 공격하고 Blue가 막는" 전체 여정**:

1. **공격**: Red가 `curl .../api/telemetry?sensor_id=x' UNION...` → 트윈이 SQLi 취약 분기 실행
2. **이벤트 발행**: 트윈이 `emit_event(trace_id=session_trace_id(team,asset), ...)` 호출
3. **수집**: Event Collector가 event_id로 dedup → SQLite 저장 → WS 브로드캐스트(Live Fire
   Dashboard가 이제 실제로 구독해서 AssetMap 상태 전환·타임라인 갱신) → Scoring Engine에 비동기 전달
4. **채점**: Scoring Engine이 achievement_key로 멱등 채점(+20), reconcile로 정합성 보증 가능
5. **탐지**: SIEM Detection Engine이 트윈 구조화 로그(또는 Suricata/Zeek/pfsense 연동 시
   그 소스)에서 같은 공격을 잡아 알림 생성 → `blue_detection_success` 이벤트를
   `matched_event_id`(trace_id)와 함께 발행(실제로 동작함, M5.4/M5.5 구현 완료)
6. **dwell 보너스**: Event Collector가 matched_event_id로 원 공격 timestamp를 조회해 enrichment
   → Scoring Engine이 dwell time 계산(`max(0, 20 - dwell초//30)`) → Blue 탐지 점수에 보너스
7. **EDR 교차 확인**: 만약 이 공격이 커맨드인젝션(PP-003)까지 이어졌다면 EDR Agent가 프로세스
   레벨에서 EDR-001/002 규칙으로도 잡아 알림 — SIEM(로그기반)과 EDR(프로세스기반) 이중 탐지
8. **대응**: Blue가 patch_console에서 "GS-001 패치" 클릭 → 화이트리스트 검증된 Ansible
   플레이북 실행 → Config Service의 patched=true 반영(무중단, 트윈이 4초 내 폴링해 인식)
9. **검증**: safe_probe가 patched 확인 → `blue_patch_verified` 이벤트(+50)
10. **복구 판정**: NOC의 Health Poller가 이 자산이 (a) 이전에 compromised 이력 있고 (b) patched
    확인되고 (c) health 3회 연속 정상이면 → Recovery Watcher가 `asset_recovered`(+50) 발행
11. **정합성 감사**: 훈련 종료 후 `/scores/reconcile`로 achievements 합계와 team_scores가
    일치하는지 자동 검증
12. **리플레이/AAR(계획)**: Event Collector의 `/replay/events`로 전체 시퀀스를 배속 재생,
    AAR 리포트가 MTTD(공격~탐지 시간)와 이 사례를 자동 집계

이 12단계 중 **1~4, 8~11번은 실제 코드로 동작**하고, **5~7, 12번은 스펙만 있고 코드가
없다**(SIEM·EDR탐지 일부·AAR).

---

## 3. 완성도 매트릭스

| 레이어 | 컴포넌트 | 상태 | 비고 |
|---|---|---|---|
| 트윈 | ground_station/power_plant/defense_network | ✅ 구현+검증 | 취약점 14종, Config Service·EDR 연결 완료 |
| 이벤트/점수 | Event Collector, Scoring Engine | ✅ 구현+검증 | v1.1(dwell time, reconcile) |
| 패치 관리 | Config Service | ✅ 구현+검증 | 무중단 토글, 킬스위치, 격리, audit |
| 패치 UX | Ansible 패치 콘솔 | ✅ 구현+검증 | 화이트리스트 경로탈출 방어 확인 |
| 모니터링 | NOC + Recovery Watcher | ✅ 구현+검증 | 3조건 판정 로직 실행 검증 |
| 엔드포인트 보안 | EDR(에이전트+백엔드+콘솔) | ✅ 구현+검증 | Kill 실제종료(SIGTERM→SIGKILL) 검증 |
| 시나리오 | scenario_engine(loader/runner) | ✅ 로직 구현+검증 | FastAPI 래퍼(Instructor 연동)는 계획만 |
| 안전장치 | secret_scan/isolation_test/hardening/checklist | ✅ 구현+검증 | |
| 계약 | contracts/shared/* | ✅ 구현+검증 | v1.1 스키마 |
| **SIEM** | ingestion/parsers/detection/storage/API | 🟢 **완료** | M5.0~M5.6 전부 구현+검증. **C2 비콘(periodicity kind) 추가 완료**(실제 지터계산 검증) + **Suricata/Zeek 사이드카 실배치**(트윈당 2개×3=6개, netns 공유 방식) |
| **대시보드** | Live Fire, SIEM Dashboard | 🟢 **둘 다 구현 완료** | Live Fire(23번), **SIEM Dashboard(신규)**: Discover/Alerts/SourceHealth/AttackCoverage, 클래식 SOC 톤으로 Live Fire·EDR과 차별화 |
| C-QA 파이프라인 | 챌린지 자동검수 8스크립트 | ✅ **구현+검증 완료** | 25번 문서. 8개 스크립트 전부 작성, 실제 챌린지로 통과/실패 케이스 둘 다 검증(깨진 챌린지 6개 오류 정확히 탐지) |
| 챌린지 콘텐츠 | 12개 계획 + 20개 확장 계획 | 🟢 **12개 완전 패키지 구현(6개 분야 × 2개씩)** | WEB-002/000, DET-000/001, FOR-000/002, REV-000/001, NET-000/002, AI-000/001. 전부 실제 실행 검증: REV-001은 키젠↔원본 알고리즘 일치, AI-001은 sklearn 블랙박스 추출로 400쿼리 내 held-out 100% 일치율, DET-001은 노이즈 속 임계튜닝. 나머지 8개는 25번 문서 목록대로 확장하면 분야당 6~7개 목표 도달 |
| Instructor API | 시나리오시작/이벤트주입/점수조정 | ✅ **완료** | 24번 문서 백엔드 + Live Fire Dashboard의 InstructorConsole.tsx가 실제로 연동(scenarioStart/scenarioEnd/scoreAdjust/fetchAudit 전부 API 호출 확인) |
| AAR/사운드/ATT&CK뷰 | 리포트+대시보드 확장 | ⬜ 계획만 | 27번 문서(단, SIEM 대시보드의 AttackCoverage 뷰는 구현됨) |
| AAR/사운드/ATT&CK뷰 | 리포트+대시보드 확장 | 🟢 **완료** | metrics.py/attack_heatmap.py/recommendations.py 전부 실제 실행 검증. **PDF 렌더링도 완료**(WeasyPrint 대신 reportlab, 한글 깨짐 버그를 실제로 발견하고 CID폰트로 수정 후 pypdf로 재검증). Live Fire 사운드 훅, SIEM Dashboard의 AttackCoverage 뷰 전부 연결 완료 |
| 부하테스트 | k6 시나리오 + syslog 플러딩 | 🟢 **구현+검증 완료** | 28번 문서. syslog UDP 플러딩을 실제로 81만건 전송해 큐 오버플로우 시 드롭카운터가 정확히 동작하는 것까지 확인 |
| 운영 매뉴얼 | 교관 런북 | ✅ 문서화 완료(운영 절차이므로 "코드"는 없음) | 29번 문서 |

---

## 4. 빌드 의존성 그래프 (다음 주 세션 순서, 21번 문서와 동일 논리)

```
[리포 통합] → [계약 검증(M0)]
      │
      ├─▶ [M1 코어 기동] ─┬─▶ [M2 EDR 연동 확인]
      │                  ├─▶ [M-Instr: Instructor API] ─▶ [M6 대시보드]
      │                  └─▶ [M3 시나리오 엔진]
      │
      ├─▶ [M5.0 트윈 구조화 로그] ─▶ [M5 SIEM 전체] ─▶ [M-Net: Suricata/Zeek]
      │
      └─▶ [부하테스트 1차] ────────────────────────────▶ [부하테스트 2차(SIEM 이후)]

[C-QA 파이프라인] ─▶ [나머지 챌린지 20개] (플랫폼과 독립적으로 병행 가능)

[전체 완성] ─▶ [교관 리허설(29번 문서 1.5절)] ─▶ [실제 훈련 운영]
```

---

## 5. 지금 상태를 한 문장으로

**"공격하면 점수가 나고, 패치하면 반영되고, 복구하면 또 점수가 나는 핵심 루프가 실제로
돌아간다. Live Fire와 SIEM 두 대시보드가 그 과정을 실시간(+사운드 알람)으로 보여주고,
SIEM이 앱계층·네트워크계층·C2 비콘까지 탐지해서 Blue 점수로 연결한다. 훈련이 끝나면
AAR이 MTTD/MTTR/ATT&CK 갭을 PDF까지 자동 생성하고, 6개 분야에 2개씩 총 12개의 실제
챌린지가 C-QA 검수와 손 검증 가이드(31번 문서)까지 갖추고 있다."**

다음 주 첫 세션(M0: 리포 통합)부터 시작하면 된다. **핵심 플랫폼은 완성**됐고, 챌린지도
분야당 2개씩 균형 있게 있다. 남은 건 (1) 챌린지를 25번 문서 목록대로 분야당 6~7개까지
추가 확장 (2) 실제 GCP 환경에서 npm install/Docker 전체 통합 테스트 — 이 두 가지뿐이다.

### 다음 세션 진행 방식 (합의된 방향)

이 시점부터는 반복적인 패턴 적용(같은 11번 문서 표준 구조를 분야별로 계속 찍어내는 것)
이라, **09번 문서의 콘텐츠 에이전트(C1~C6)를 병렬로 돌리는 게 이 대화에서 순차적으로
더 만드는 것보다 효율적**이다. 실행 순서:

1. M0(리포 통합) 먼저 — `contracts/`와 `cyber-range/`를 17번 문서 구조로 합친다.
2. C0(출제 총괄)가 25번 문서의 남은 8개 목록을 C1~C6에 분야별로 배정.
3. C1~C6을 **각각 별도 Claude Code 세션으로 병렬 실행** — 12번(WEB-002)·13번(FOR-002)을
   템플릿 삼아 동일 구조(challenge.yaml+deploy+solution+grader+writeup)로 생산.
4. 각 세션 종료 시 `infra/challenge_qa/run_all.py --challenge <ID> --skip-docker`로
   자체 검증 후 커밋 — 이번 세션에서 12개 전부 이 방식으로 검증했으므로 패턴이 이미 증명됨.
5. 전부 모이면 `infra/challenge_qa/run_all.py`를 Docker 환경에서 전체 재실행(deploy_up
   부터 teardown까지)해 최종 확정.
