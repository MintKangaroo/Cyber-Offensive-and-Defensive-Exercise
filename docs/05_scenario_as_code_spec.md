# 시나리오 as-code 스키마 — Claude Code 빌드 프롬프트

> 로드맵 ★★★ "다단계 Kill Chain 시나리오" + ★★ "시나리오 as-code" 구현 사양.
> 시나리오를 YAML로 정의해 재현·공유 가능하게 하고, Exploit Manager가 로드해 오케스트레이션.

---

## 1. 왜 필요한가

현재는 취약점 하나하나가 독립적. 실제 침해는 **정찰→침투→권한상승→측면이동→목표달성**의 연쇄.
시나리오 as-code로 이 연쇄를 정의하면: 재현 가능한 훈련, 단계별 채점, 자동 진행 판정, 난이도 조절이 가능해짐.

---

## 2. 시나리오 YAML 스키마

```yaml
scenario:
  id: "SAT-KILLCHAIN-01"
  name: "위성 지상국 임무계획 탈취 작전"
  description: "정찰부터 임무계획 유출까지의 다단계 침해 시나리오"
  target_asset: "ground_station"
  difficulty: "medium"          # easy | medium | hard
  time_limit_sec: 1800          # 30분

  # 초기 상태: 어떤 취약점을 열어둘지
  initial_vuln_state:
    GS-001: vulnerable
    GS-002: vulnerable
    GS-003: vulnerable
    GS-004: patched            # 이 시나리오에선 경로순회는 막아둠
    GS-005: vulnerable

  # 킬체인 단계 정의 (순서가 점수/보너스에 반영)
  stages:
    - stage: 1
      name: "정찰 - 디버그 설정 노출"
      objective_event: red_attack_started
      match: { vuln_id: "GS-005" }
      points: 20
      mitre: [T1592]
    - stage: 2
      name: "초기 침투 - 하드코딩 계정 로그인"
      objective_event: red_attack_started
      match: { vuln_id: "GS-002" }
      points: 20
      requires_stage: 1          # 1단계 이후에만 인정(순서 강제)
      mitre: [T1078]
    - stage: 3
      name: "정보 수집 - SQLi로 사용자 테이블 추출"
      objective_event: red_attack_started
      match: { vuln_id: "GS-001" }
      points: 30
      requires_stage: 2
      mitre: [T1190]
    - stage: 4
      name: "목표 달성 - IDOR로 기밀 임무계획 유출"
      objective_event: flag_exfiltrated
      match: { vuln_id: "GS-003" }
      points: 50
      requires_stage: 3
      mitre: [T1213]
      is_final: true

  # 순서대로 전부 달성 시 보너스
  chain_bonus:
    all_stages_in_order: 50
    within_sec: 600              # 10분 내 완주 시에만 보너스

  # Blue 측 목표
  blue_objectives:
    - name: "SQLi 탐지"
      match_alert: "TWIN-SQLI-001"
      points: 20
    - name: "임무계획 유출 차단"
      description: "GS-003 패치로 유출 방지"
      match_event: blue_patch_verified
      match: { vuln_id: "GS-003" }
      points: 50
      time_bonus: true          # 빠르게 막을수록 보너스(백엔드 3절)

  # 배경 노이즈(선택) — 탐지 난이도 조절
  noise:
    enabled: true
    normal_traffic_eps: 5       # 초당 정상 이벤트 5건 배경 생성
```

---

## 3. 진행 판정 로직 (Scenario Runner)

- Scenario Runner가 Event Collector 스트림을 구독하며 각 stage의 `match`를 평가.
- `requires_stage`가 있으면 선행 단계 완료 후의 이벤트만 인정(순서 위반은 무시하거나 감점 옵션).
- 모든 stage 완료 + 순서 + 시간조건 → `chain_bonus` 적립, `red_objective_success`(is_final) 발행.
- stage 상태(pending/active/completed)를 대시보드에 실시간 노출 → Red팀은 다음 목표를, 관전자는 진행도를 봄.

---

## 4. 초기 제공 시나리오 3종

1. **SAT-KILLCHAIN-01** (위 예시): 위성 지상국, 정찰→계정→SQLi→IDOR 유출.
2. **SCADA-SABOTAGE-01**: 발전소. PP-002(HMI 기본계정)→PP-001(PLC 미인증 쓰기, 측면이동)→PP-005(세이프티 우회, 목표). Blue는 PP-003 커맨드인젝션 탐지 + PLC 쓰기 차단.
3. **DEFENSE-EXFIL-01**: 국방망. DN-001(SMB 익명)→DN-002(Kerberoast 권한상승)→DN-003(백업 자격증명 유출)→DN-004(오픈릴레이로 데이터 반출, 목표).

각 시나리오는 난이도별로 initial_vuln_state와 noise를 조절한 easy/hard 변형 제공.

---

## 5. Definition of Done

- YAML 하나 로드 → 초기 취약점 상태가 Config Service에 반영(백엔드 5절).
- Red가 순서대로 공격하면 stage가 순차 completed, 순서 어기면 미인정.
- 완주 시 chain_bonus 적립, 대시보드에 킬체인 진행바 표시.
- 3종 시나리오가 각각 재현 가능(같은 YAML → 같은 초기조건).
