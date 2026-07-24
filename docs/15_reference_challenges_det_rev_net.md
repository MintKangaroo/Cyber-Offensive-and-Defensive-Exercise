# 레퍼런스 문제 패키지 — DET-004 / REV-001 / NET-003

> 탐지·리버싱·네트워크(OT) 분야 레퍼런스. WEB-002/FOR-002/AI-002와 동일 구조를 압축 형태로.
> 각 분야 에이전트는 여기서 확장한다.

---

# DET-004 (hard) — 킬체인 시퀀스 탐지

## challenge.yaml (요약)
```yaml
challenge:
  id: "DET-004"
  title: "점들을 잇다 - Multi-stage Correlation"
  category: "detection"
  difficulty: "hard"
  points: { red: 0, blue: 250 }     # 순수 방어 문제(Blue 전용)
  mitre: [T1046, T1190, T1041]
  description: |
    스캔 → 앱 익스플로잇 → 유출로 이어지는 다단계 공격이 개별 알림으로만 잡히고 있다.
    이를 하나의 상관 알림으로 묶는 시퀀스 룰을 작성하라.
  blue_task:
    goal: "3단계(scan→exploit→exfil)를 300초 내 동일 src로 묶어 단일 critical 알림 생성"
    success_criteria: |
      (1) 제공된 공격 로그셋에 정확히 1개의 시퀀스 알림 발생
      (2) 개별 단계만 있는 로그셋(부분 공격)엔 시퀀스 알림 미발생
      (3) 정상+노이즈 로그셋에 오탐 없음
    points_breakdown: { correct_alert: 150, no_partial_fp: 50, no_noise_fp: 50 }
  scoring: { blue_verify: "alert_exact_count" }
  artifacts:
    - "logs_full_attack.jsonl"      # 완전한 킬체인
    - "logs_partial.jsonl"          # 일부 단계만
    - "logs_benign_noise.jsonl"     # 정상+노이즈
```

## 정답 룰 (solution/)
```yaml
id: SEQ-KILLCHAIN-STUDENT
sequence:
  - match: { category: "network", signature_contains: "scan" }
  - match: { asset: "ground_station", raw.status: 200, endpoint_contains: "/api/" }
  - match: { event_type: "flag_exfiltrated" }
within_sec: 300
group_by: src.ip
action_on_match: alert_critical
```

## 채점 (grader/blue_grader.py 요약)
```python
def grade_blue(context):
    a_full  = run_rule(context["rule"], "logs_full_attack.jsonl")     # 정확히 1개 기대
    a_part  = run_rule(context["rule"], "logs_partial.jsonl")         # 0개 기대
    a_noise = run_rule(context["rule"], "logs_benign_noise.jsonl")    # 0개 기대
    pts = (150 if len(a_full)==1 else 0) + (50 if len(a_part)==0 else 0) + (50 if len(a_noise)==0 else 0)
    return GradeResult(len(a_full)==1 and not a_part and not a_noise, pts, ...)
```
**포인트**: 탐지 문제는 "정탐 1 + 부분공격 미발화 + 노이즈 오탐0"의 3중 데이터셋으로 룰 품질을 강제. (06 탐지 콘텐츠 + 노이즈 생성기 연계)

---

# REV-001 (easy) — XOR 플래그 추출

## challenge.yaml (요약)
```yaml
challenge:
  id: "REV-001"
  title: "가려진 신호 - XOR Decode"
  category: "reversing"
  difficulty: "easy"
  points: { red: 100, blue: 50 }
  mitre: [T1027]
  description: |
    지상국 진단 도구 바이너리(또는 JS 번들)에 플래그 검증 로직이 있다.
    XOR로 가려진 플래그를 복원하라.
  red_task:
    goal: "바이너리 내 XOR 인코딩된 플래그를 정적/동적 분석으로 복원"
    flag_format: "flag{...}"
    flag_type: "dynamic"            # 팀 시드로 인코딩 키/플래그 유니크
    hints:
      - { cost: 10, text: "문자열 테이블과 상수 키를 찾아라." }
      - { cost: 20, text: "키는 단일 바이트 XOR이다." }
  blue_task:
    goal: "이런 약한 난독화의 문제를 설명하고 안전한 비밀 보관 방식 제시(서술+구현)"
    success_criteria: "하드코딩 시크릿 제거 + 외부 볼트/서버검증 방식 적용"
  scoring:
    red_verify: "flag_match"
    blue_verify: "patch_check"
  artifacts: [ "diag_tool  (ELF 또는 JS 번들)" ]
  safety: { profile: "standard" }
```

## 아티팩트 생성 (deploy/build_challenge.py 요약)
```python
# 팀 시드로 플래그 생성 후 단일바이트 XOR로 인코딩해 바이너리/번들에 삽입
def make(team_id):
    flag = dynamic_flag(team_id)          # flag{xor_<hmac>}
    key = 0x5A
    enc = bytes(b ^ key for b in flag.encode())
    # enc 를 소스에 상수 배열로 심고 컴파일/번들
```

## 채점: red=flag_match(동적). blue=하드코딩 제거 확인(정적 스캔 + 서버검증 호출 여부).
**리버싱 공통**: 동적 플래그를 아티팩트에 팀 시드로 주입 → 공유 방지. 난이도는 인코딩 복잡도(단일XOR→다중키→커스텀VM)로 조절.

---

# NET-003 (medium) — Modbus 레지스터 조작 (OT)

## challenge.yaml (요약)
```yaml
challenge:
  id: "NET-003"
  title: "임계를 넘어서 - Unauthenticated Modbus Write"
  category: "network"
  difficulty: "medium"
  points: { red: 180, blue: 200 }
  asset: "power_plant"
  mitre: [T0836, T0800]            # ICS: unauthorized command, activate safety override
  description: |
    발전소 PLC가 Modbus/TCP로 노출되어 있다. 인증 없이 안전 임계 레지스터를
    조작해 세이프티 인터록을 무력화하라. (실제 장비 아님, pymodbus 시뮬레이터)
  red_task:
    goal: "Modbus write로 SAFETY_INTERLOCK 레지스터를 0으로 만들고 목표 상태 도달"
    flag_on_success: "flag{modbus_interlock_bypassed}"
    hints:
      - { cost: 20, text: "Function Code 6(Write Single Register)을 살펴보라." }
      - { cost: 30, text: "레지스터 맵에서 인터록 주소를 찾아라." }
  blue_task:
    goal: "OT 이상 탐지 + 접근제어로 미인증 쓰기 차단"
    success_criteria: |
      (1) Zeek modbus 로그 기반으로 미인증 write 탐지 알림
      (2) 접근제어 적용 후 Red 재시도가 거부됨
    points_breakdown: { detection: 80, access_control: 120 }
  scoring:
    red_verify: "event"            # PLC 시뮬레이터 상태 변화 이벤트
    blue_verify: ["alert", "block"]
  artifacts: [ "plc_simulator/ (pymodbus)", "network_topology.md" ]
  safety:
    profile: "hardened"
    notes: "OT 시뮬레이터 격리. 실제 산업장비/프로토콜 게이트웨이와 미연결."
```

## 취약 PLC 시뮬레이터 (deploy/plc_simulator/ 요약)
```python
# pymodbus 기반 서버. 인증 개념이 없는 순정 Modbus의 취약성을 그대로 재현.
# 레지스터 맵: 40001=TURBINE_RPM, 40002=COOLANT_FLOW, 40003=SAFETY_INTERLOCK(1=on)
# 패치 버전: write 요청 전 소스IP allowlist(엔지니어링 워크스테이션)만 허용 + 감사로그.
```

## 채점: red=인터록 레지스터가 0이 되는 상태 이벤트. blue=Zeek modbus 로그에 미인증 write 알림 + 재시도 차단.
**OT 공통**: 실제 프로토콜(Modbus/S7)은 pymodbus/snap7 시뮬레이터로, 반드시 격리. Zeek의 프로토콜 파서로 탐지 훈련. 실장비 연결 절대 금지(08).

---

# 세 문제의 분야별 채점 축 요약

| 분야 | Red 채점 | Blue 채점 | 특이 패턴 |
|---|---|---|---|
| Detection | (없음/방어전용) | alert_exact_count | 3중 데이터셋(정탐/부분/노이즈) |
| Reversing | flag_match(동적) | patch_check | 아티팩트에 팀시드 주입 |
| Network/OT | event(상태변화) | alert + block | 프로토콜 시뮬레이터 강격리 |

모든 문제가 11번 출제표준 구조(challenge.yaml + deploy + solution + grader + writeup)를 따르며,
RCE/OT/AI류는 `safety.profile: hardened`를 강제한다.
```
