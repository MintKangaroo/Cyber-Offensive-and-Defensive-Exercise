# 추가 레퍼런스 문제 세트 (분야별 2번째 문제)

> 12~15번에서 각 분야 1문제씩 정식화했다. 이 문서는 각 분야의 두 번째 대표 문제를 추가해
> 난이도/기법 커버리지를 넓힌다. 모두 11번 출제표준 구조를 따른다(요약 형태).

---

# WEB-004 (hard) — SSRF → 내부 피벗 → 자격증명 탈취

```yaml
challenge:
  id: "WEB-004"
  title: "안에서 문을 열다 - SSRF Pivot"
  category: "web"
  difficulty: "hard"
  points: { red: 250, blue: 200 }
  asset: "defense_network"
  mitre: [T1190, T1552.001]
  description: |
    국방망 파일서버에 URL 미리보기(웹훅/썸네일) 기능이 있다. SSRF로 내부
    메타데이터/관리 엔드포인트에 접근해 백업 설정의 평문 자격증명을 획득하라.
  red_task:
    goal: "SSRF로 내부 전용 /internal/backup-config 에 도달해 자격증명 유출"
    flag_format: "flag{ssrf_reached_internal_creds}"
    hints:
      - { cost: 25, text: "미리보기 URL이 내부 대역(169.254/10.x)으로 향하면?" }
      - { cost: 40, text: "리다이렉트/DNS rebinding으로 필터를 우회하라." }
  blue_task:
    goal: "egress allowlist + 내부대역 차단 + SSRF 탐지룰"
    success_criteria: "내부대역 요청 차단 & SIEM에 SSRF 시도 알림"
    points_breakdown: { egress_control: 120, detection: 80 }
  scoring: { red_verify: "flag_match", blue_verify: ["block","alert"] }
  safety: { profile: "standard" }
```
**핵심**: 08 안전장치의 egress 격리와 직접 연결되는 교육형 문제. 취약: 미리보기 fetcher가 목적지 검증 없음. 방어: 목적지 allowlist + 내부대역 거부 + 리다이렉트 재검증.

---

# FOR-003 (medium) — 메모리 포렌식: 인젝션된 C2

```yaml
challenge:
  id: "FOR-003"
  title: "기억 속의 유령 - Memory Forensics"
  category: "forensics"
  difficulty: "medium"
  points: { red: 200, blue: 100 }
  asset: "power_plant"
  mitre: [T1055, T1071]
  description: |
    엔지니어링 워크스테이션 메모리 덤프에서 악성 프로세스와 C2를 찾아라.
  red_task:
    goal: "덤프 분석으로 3항목 특정"
    submit_fields: [malicious_pid, c2_address, injection_technique]
    hints:
      - { cost: 20, text: "부모-자식 프로세스 트리에서 벗어난 프로세스를 보라." }
      - { cost: 30, text: "네트워크 연결 아티팩트에서 비정상 목적지를 찾아라." }
  blue_task:
    goal: "이 C2 비콘을 잡는 탐지룰(주기성 기반) 작성"
    success_criteria: "Zeek conn 로그 재현 데이터에 비콘 알림, 정상엔 오탐 없음"
  scoring: { red_verify: "field_match", blue_verify: "alert" }
  artifacts: [ "ews_memory.dmp (합성 덤프 or Volatility 호환 샘플)" ]
  safety: { profile: "standard" }
```
**핵심**: 06 탐지의 C2 비콘 로직(지터<0.1)과 크로스오버. 메모리 아티팩트는 합성 또는 공개 교육용 샘플로 결정론 확보.

---

# DET-002 (medium) — 포트스캔 임계 룰 (노이즈 내성)

```yaml
challenge:
  id: "DET-002"
  title: "잡음 속의 스캔 - Threshold Tuning"
  category: "detection"
  difficulty: "medium"
  points: { red: 0, blue: 180 }
  mitre: [T1046]
  description: |
    수평 포트스캔을 탐지하되, 정상 트래픽 노이즈에서 오탐이 나지 않게 임계를 튜닝하라.
  blue_task:
    goal: "distinct(dst.port) 임계 룰 작성 + 임계값 튜닝"
    success_criteria: |
      (1) 스캔 로그셋에 알림  (2) 노이즈 로그셋 오탐 0  (3) 경계 케이스(느린 스캔) 처리 서술
    points_breakdown: { detect: 100, no_fp: 50, slow_scan_note: 30 }
  scoring: { blue_verify: "alert" }
  artifacts: [ "scan.jsonl", "noise.jsonl", "slow_scan.jsonl" ]
  safety: { profile: "standard" }
```
**핵심**: 순수 Blue 튜닝 문제. "탐지되지만 오탐 안 남"의 균형점을 찾는 실전 스킬. 노이즈 생성기(06) 산출물 재사용.

---

# AI-005 (hard) — 간접 프롬프트 인젝션 (LLM 통합 지점)

```yaml
challenge:
  id: "AI-005"
  title: "설명을 조종하다 - Indirect Prompt Injection"
  category: "ai"
  difficulty: "hard"
  points: { red: 250, blue: 250 }
  asset: null
  mitre: [T1059]
  description: |
    대시보드의 'AI 평가' 기능은 이벤트 로그를 LLM에 요약시킨다. 로그 필드에
    주입한 지시로 시스템 프롬프트를 우회해, 숨겨진 값을 출력하게 만들어라.
  red_task:
    goal: "로그 필드를 통한 간접 인젝션으로 LLM이 시스템 컨텍스트의 비밀 토큰을 노출"
    flag_on_success: "flag{indirect_injection_leak}"
    hints:
      - { cost: 30, text: "요약 대상 데이터 자체에 지시를 심어라." }
      - { cost: 50, text: "구분자/역할 경계를 무너뜨리는 페이로드를 시도하라." }
  blue_task:
    goal: "인젝션 방어: 입력 격리/구분자 강화/출력 필터/권한 최소화"
    success_criteria: "제출된 인젝션 페이로드들이 비밀을 노출하지 못함 + 정상 요약 기능 유지"
    points_breakdown: { injection_blocked: 150, utility_kept: 100 }
  scoring: { red_verify: "detector_query", blue_verify: "holdout_eval" }
  safety:
    profile: "hardened"
    notes: |
      훈련용 격리 LLM 엔드포인트 사용. 실제 운영 키/데이터 절대 미연결.
      비밀 토큰은 훈련용 더미. 이 문제는 방어 훈련 목적이며 격리 환경에서만 배포.
```
**핵심**: LLM 통합의 현실적 위협. Blue의 utility_kept 조건으로 "과방어로 기능 파괴" 방지. 반드시 격리 LLM·더미 비밀.

---

# REV-003 (hard) — 스택 오버플로우 + 완화기법 공방

```yaml
challenge:
  id: "REV-003"
  title: "넘치는 스택 - BOF & Mitigations"
  category: "reversing"
  difficulty: "hard"
  points: { red: 250, blue: 150 }
  mitre: [T1203]
  description: |
    지상국 진단 데몬(취약 C 바이너리)에 스택 버퍼 오버플로우가 있다. 제어흐름을
    탈취해 플래그를 읽어라.
  red_task:
    goal: "BOF 익스플로잇으로 win 함수 실행/셸 획득 → 플래그"
    flag_format: "flag{...}"
    hints:
      - { cost: 30, text: "오프셋을 정확히 구하라(패턴 생성)." }
      - { cost: 50, text: "NX가 켜져 있으면 ret2win/ROP를 고려." }
  blue_task:
    goal: "완화기법 적용 효과 분석 + 안전한 코드로 패치"
    success_criteria: "스택카나리/NX/ASLR 적용 후 기존 익스플로잇 무력화 + 경계검사 패치"
  scoring: { red_verify: "flag_match", blue_verify: "patch_check" }
  artifacts: [ "diag_daemon (취약 ELF + 소스)", "libc (필요시)" ]
  safety:
    profile: "hardened"
    notes: "강격리 컨테이너. 익스플로잇은 컨테이너 내부로 제한(08)."
```
**핵심**: Red 익스플로잇 vs Blue 완화. 단계적으로 카나리→NX→ASLR을 켜며 난이도 상승. 강격리 필수.

---

# NET-002 (medium) — 세그멘테이션 우회 피벗팅

```yaml
challenge:
  id: "NET-002"
  title: "경계를 넘어 - Lateral Pivot"
  category: "network"
  difficulty: "medium"
  points: { red: 200, blue: 200 }
  asset: "defense_network"
  mitre: [T1021, T1090]
  description: |
    DMZ의 취약 호스트를 발판으로 내부 세그먼트의 목표 자산에 도달하라.
  red_task:
    goal: "DMZ 침투 → 내부 피벗 → 목표 자산의 플래그 접근"
    flag_format: "flag{pivoted_to_internal}"
    hints:
      - { cost: 25, text: "DMZ 호스트의 신뢰관계/열린 포트를 조사하라." }
      - { cost: 40, text: "포트포워딩/프록시로 내부에 접근하라." }
  blue_task:
    goal: "세그멘테이션 강화 + 측면이동 탐지"
    success_criteria: "내부 도달 차단 & 피벗 트래픽 SIEM 알림"
    points_breakdown: { segmentation: 120, detection: 80 }
  scoring: { red_verify: "event", blue_verify: ["block","alert"] }
  artifacts: [ "network_topology.md" ]
  safety: { profile: "standard" }
```
**핵심**: 네트워크 격리(08)를 공격 관점에서 훈련. Blue는 세그먼트 간 최소권한 + 측면이동(비정상 내부 연결) 탐지.

---

## 현재 문제 커버리지 요약

| 분야 | 문제 | 난이도 범위 |
|---|---|---|
| Web | WEB-002(JWT), WEB-004(SSRF) | medium~hard |
| Forensics | FOR-002(pcap), FOR-003(memory) | medium |
| Detection | DET-004(sequence), DET-002(threshold) | medium~hard |
| AI | AI-002(evasion), AI-005(prompt injection) | medium~hard |
| Reversing | REV-001(XOR), REV-003(BOF) | easy~hard |
| Network/OT | NET-003(modbus), NET-002(pivot) | medium |

각 분야 2문제 확보. C0가 easy·insane을 보강해 난이도 곡선을 완성하고, C1~C6이 이 템플릿으로 분야별 5~8문제까지 확장한다.

## 다음 확장 제안

- 각 분야 **easy 도입문제**(개념 확인용) + **insane 1문제**(비의도 방지된 정교한 문제) 추가.
- 크로스오버 시나리오(웹 침해→포렌식 재구성→탐지룰)를 05 시나리오 as-code로 엮어 3분야 연계 출제.
