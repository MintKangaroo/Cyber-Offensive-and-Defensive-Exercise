# POST-V1 백로그 & v1.0 위험 수용 기록

- 작성일: 2026-09-30
- 근거: `audit/101_reaudit.md`(Phase 1 재감사) + 릴리스 책임자 결정(Phase 2 = Showstopper 잔여만 마감, 나머지는 백로그+위험 수용).
- 스코프 동결(마감 규칙 3): v1.0 에서는 신규 챌린지·트윈·기능을 추가하지 않는다. 아래는 v1.0 이후 개선 후보와, v1.0 출시에 한해 위험을 수용하는 항목의 사유를 명시한다.

---

## 1. v1.0 위험 수용 (Showstopper 잔여 — 코드 완결 불가/운영 경로 한정)

| ID | 잔여 | 위험 수용 사유 | 후속 |
|---|---|---|---|
| S-10 | 팀 롤백 시 prod k8s PVC 에 공격자 웹셸 데이터 잔존 가능 | sandbox(emptyDir) 경로는 롤아웃 시 소거되어 안전. prod PVC 경로만 해당하며, v1.0 표준 배포는 docker-compose/sandbox. 리셋 계통(RESET_TARGETS 8종)·다운타임 보정은 FIXED. | prod k8s 롤백 시 PVC purge 옵션(런타임 k8s 검증 필요) |
| S-11 | 8h 실 OOM 방지·SIEM 저장소 rollover 실측 미완 | mem_limit(70개)·하드닝 오버레이 3경로 로드·event_collector retention 은 코드상 완비. 실 OOM 은 장시간 런타임(Phase 4 소크)에서만 확정 가능 — 샌드박스 RAM 제약으로 이 환경에서 코드 완결 불가. | Phase 4 8h 정식 소크(`run_soak.sh`)에서 RSS 기울기 판정 |
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

---

## 4. 일반 개선 아이디어(비결함)
- pydantic `register` 필드 shadow 경고·JWT 짧은 키 경고 정리(테스트 위생).
- docker-compose `version` obsolete 속성 제거.
- HANDOFF/문서의 라인 번호 참조를 심볼 기반으로 전환(코드 확장 시 stale 방지).
