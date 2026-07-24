# 탐지 콘텐츠 스펙 — Claude Code 빌드 프롬프트

> 로드맵 ★★★ "초기 룰셋" + ★★ "Sigma 호환/ATT&CK 커버리지/C2 비콘/노이즈 생성기" 구현 사양.
> SIEM Detection Engine(SIEM 프롬프트 Agent 3)이 로드하는 규칙 세트와 지원 도구.

---

## 1. 초기 탐지 룰셋 20종

각 규칙은 Sigma-lite YAML(SIEM 프롬프트 6절 포맷). 아래는 목록 + 핵심 로직.

### 애플리케이션 계층 (트윈 access 로그 기반)
1. **TWIN-SQLI-001** SQLi 시도 — `/api/telemetry` query에 `' UNION -- OR 1=1` 패턴 · T1190 · sev3
2. **TWIN-TRAVERSAL-001** 경로순회 — `file=` 파라미터에 `../` 또는 절대경로 · T1005 · sev3
3. **TWIN-IDOR-001** IDOR 스캔 — 동일 src가 `/api/mission-plan/{id}`를 순차 id로 5회+ · T1213 · sev2
4. **TWIN-AUTH-BRUTE-001** 브루트포스 — 동일 src의 `/api/login|/api/hmi/login` 401 연속 10회/60초 · T1110 · sev2
5. **TWIN-DEFAULT-CRED-001** 기본계정 로그인 성공 — admin/admin123, operator/operator · T1078.001 · sev3
6. **TWIN-CMDI-001** 커맨드 인젝션 — `host` 파라미터에 `; | & $() backtick` · T1059 · sev4
7. **TWIN-DESERIAL-001** 역직렬화 시도 — `/api/historian/export`에 pickle opcode 시그니처 · T1059.006 · sev4
8. **TWIN-PLC-WRITE-001** 미인증 PLC 쓰기 — `/api/plc/write` 인증헤더 없음 · T0836 · sev4
9. **TWIN-SAFETY-001** 세이프티 우회 — `/api/safety/override override=true` 승인토큰 없음 · T0800 · sev4(critical)
10. **TWIN-DEBUG-001** 디버그 엔드포인트 접근 — `/api/debug/config` 외부 접근 · T1592 · sev2

### 네트워크 계층 (Suricata/Zeek/pfSense)
11. **NET-PORTSCAN-001** 수평 포트스캔 — 동일 src가 distinct dst.port ≥ 15 / 60초 · T1046 · sev2
12. **NET-HOSTSCAN-001** 수직 호스트스캔 — 동일 src가 distinct dst.ip ≥ 20 / 60초 · T1018 · sev2
13. **NET-C2-BEACON-001** C2 비콘 주기성 — 동일 src→dst outbound가 균일 간격(지터 <10%)으로 5회+ (아래 4절) · T1071 · sev3
14. **NET-EXFIL-VOLUME-001** 대용량 반출 — 단일 flow outbound bytes가 임계 초과 · T1041 · sev3
15. **NET-DNS-TUNNEL-001** DNS 터널링 의심 — 비정상적으로 긴 서브도메인/높은 TXT 쿼리 빈도 · T1071.004 · sev3
16. **NET-SURICATA-ALERT** Suricata 시그니처 알림 패스스루 — eve.json alert를 severity 매핑해 승격 · 다양 · sev=map
17. **FW-BLOCK-SPIKE-001** 방화벽 차단 급증 — pfSense block 이벤트가 baseline 대비 3배 · T1595 · sev2
18. **FW-RELAY-ABUSE-001** 메일 릴레이 악용 — `/api/mail/relay` 미인증 외부 발신 · T1583.007 · sev3

### 상관/시퀀스
19. **SEQ-KILLCHAIN-001** 다단계 침해 — 스캔→앱공격(200)→flag_exfiltrated가 300초 내 동일 src · T1046,T1190,T1041 · sev4
20. **SEQ-RECON-TO-EXPLOIT-001** 정찰 후 즉시 익스플로잇 — debug/config 접근 후 60초 내 같은 src가 인증우회 · sev3

---

## 2. Sigma 호환

- 규칙 포맷을 **Sigma 표준 서브셋**으로 작성해 커뮤니티 룰 임포트 가능하게.
- `sigma_loader.py`: Sigma YAML → 내부 규칙 객체 변환기. 지원 필드: `detection`, `condition`, `timeframe`, `logsource`.
- 미지원 Sigma 기능(정규식 백레퍼런스 등)은 로드 시 경고 + 스킵(무시하지 말고 명시).
- 내부 필드 매핑표: Sigma의 `logsource.product` → 내부 `source_type`, 필드명 매핑(`c-uri` → `raw.uri` 등).

---

## 3. ATT&CK 커버리지 뷰

- 모든 규칙의 `mitre` 태그를 집계해 **어떤 전술/기술을 탐지 가능한지** 매트릭스 생성.
- `GET /detection/attack-coverage` → `{tactic: {technique_id: {rules: [...], covered: true}}}`.
- 대시보드에서 ATT&CK 매트릭스 히트맵으로 렌더(탐지 가능=색, 빈틈=회색) → 룰셋 갭 분석.
- **활용**: 훈련 설계 시 "이 시나리오의 공격 기술을 우리 룰이 커버하는가" 사전 점검.

---

## 4. C2 비콘 탐지 로직 (상세)

Reverse Connection Simulator(제안서 8장)의 heartbeat를 탐지하는 규칙.
- Zeek conn 로그에서 동일 (src, dst) 쌍의 연결 시각을 수집.
- 연속 연결 간격의 표준편차/평균(변동계수)이 임계 미만이면 "주기적 비콘" 판정:
  - `intervals = diff(connection_times)`
  - `jitter = std(intervals) / mean(intervals)`
  - `jitter < 0.1` 이고 관측 5회+ → 비콘 의심 알림.
- 정상 폴링(대시보드 등)과 구분: 알려진 정상 목적지는 allowlist로 제외.
- **훈련 효과**: Blue가 "일정한 간격의 outbound"를 노이즈 속에서 찾아내는 실전 스킬 훈련.

---

## 5. 배경 노이즈 생성기 (★★)

**목적**: 공격 신호를 정상 트래픽 잡음 속에 숨겨 탐지 난이도를 현실화. 노이즈 없으면 탐지가 너무 쉬움.

**구현 — `noise_generator.py`**:
- 정상 사용자 행동 시뮬레이션: 로그인 성공, 정상 텔레메트리 조회, 정기 헬스체크, 일반 웹 요청.
- 정상 네트워크 흐름: 내부 DNS, HTTP, 주기적 백업 트래픽.
- 파라미터: `normal_traffic_eps`(초당 이벤트), 시간대별 변동(업무시간 패턴), 소스 IP 풀.
- 시나리오 YAML의 `noise.enabled`/`normal_traffic_eps`로 제어(시나리오 스펙 2절).
- **오탐 훈련 연계**: 가끔 "애매한" 이벤트(정상인데 의심스러운 UA, 드문 포트)를 섞어 Blue 트리아지 평가.

---

## 6. 오탐(False Positive) 트리아지 훈련 (★)

- 노이즈 중 일부를 "의심스럽지만 정상"으로 라벨링(ground truth 보유).
- Blue가 알림을 close할 때 true positive/false positive 분류 → 정확도 점수화.
- AAR에서 팀별 트리아지 정확도(정탐률/오탐률) 리포트.

---

## 7. 개발 순서 & DoD

- **M1**: 규칙 1~10(앱 계층) + Detection Engine 단순/임계 평가 → 트윈 공격에서 알림.
- **M2**: 규칙 11~18(네트워크) + Suricata/Zeek 파서 연동.
- **M3**: 시퀀스 규칙 19~20 + C2 비콘 로직.
- **M4**: Sigma 로더 + ATT&CK 커버리지 API/뷰.
- **M5**: 노이즈 생성기 + 오탐 트리아지.

**DoD**: 20종 규칙 로드, 각 규칙이 대응 공격에서 알림 발생, ATT&CK 커버리지 매트릭스 렌더, 노이즈 on일 때 탐지 난이도 체감 상승.
