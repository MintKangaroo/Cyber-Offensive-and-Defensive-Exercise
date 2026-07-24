# 레퍼런스 문제 패키지 — FOR-002 (pcap 침해 재구성)

> 포렌식 분야 레퍼런스. WEB-002(12번)와 동일 구조. 조사형 문제라 Red 과제가 "공격 재현"이 아니라
> "증거 분석"이며, Blue 과제는 "탐지 룰로 같은 공격을 잡기"로 균형을 맞춘다.

---

## 1. challenge.yaml

```yaml
challenge:
  id: "FOR-002"
  title: "침묵하는 지상국 - 침해 재구성"
  category: "forensics"
  difficulty: "medium"
  points: { red: 200, blue: 150 }
  asset: "ground_station"
  mitre: [T1190, T1046, T1041]

  description: |
    위성 지상국에서 이상 트래픽이 포착되어 패킷을 캡처했다.
    제공된 pcap을 분석해 공격자의 행위를 재구성하라.

  red_task:                        # 조사형: 분석 결과 제출
    goal: "공격 세션을 분석해 4개 항목 특정"
    submit_fields:
      - attacker_ip                # 공격자 IP
      - exploited_endpoint         # 익스플로잇된 엔드포인트
      - exfiltrated_flag           # pcap에서 복원한 유출 플래그
      - attack_technique           # ATT&CK 기술 ID
    flag_format: "여러 필드 정답 매칭(부분점수)"
    hints:
      - { cost: 20, text: "HTTP 스트림을 따라가며 응답 본문을 확인하라." }
      - { cost: 30, text: "유출 데이터는 base64로 인코딩되어 응답에 실려있다." }

  blue_task:
    goal: "이 공격을 탐지하는 Suricata/Sigma 룰 작성 + SIEM에서 재현 트래픽에 알림"
    success_criteria: "제공된 재현 트래픽에 알림 발생, 정상 트래픽엔 오탐 없음"
    points_breakdown: { detection_rule: 100, no_false_positive: 50 }

  scoring:
    red_verify: "field_match"      # 필드별 채점(부분점수)
    blue_verify: "alert"

  artifacts:
    - "incident_capture.pcap"      # 생성물(아래 3절 생성기로 제작)
  safety:
    profile: "standard"
    notes: "pcap 내 모든 IP는 사설/더미, 플래그는 합성."
```

---

## 2. 정답 (solution/answers.json — 비공개)

```json
{
  "attacker_ip": "10.13.37.66",
  "exploited_endpoint": "/api/telemetry",
  "exfiltrated_flag": "flag{pcap_carved_telemetry_leak}",
  "attack_technique": "T1190"
}
```

---

## 3. 아티팩트 생성기 (deploy/generate_pcap.py)

> C-QA 재현성을 위해 pcap을 **결정론적으로 생성**. 실제 트래픽 캡처 대신 스크립트로 합성해
> 매 배포마다 동일 산출물이 나오게 한다(팀별 유니크가 필요하면 team seed로 플래그만 교체).

```python
"""
scapy로 공격 세션 pcap을 합성 생성.
시나리오: 공격자(10.13.37.66)가 지상국(10.0.0.10:8001)에
  1) 포트스캔(여러 dst 포트 SYN)
  2) /api/telemetry 에 SQLi UNION 페이로드
  3) 응답으로 base64 인코딩된 flag 유출
을 수행하는 흐름을 재현.
"""
from scapy.all import IP, TCP, Raw, wrpcap
import base64

ATTACKER = "10.13.37.66"
TARGET = "10.0.0.10"
FLAG = "flag{pcap_carved_telemetry_leak}"
pkts = []

# 1) 포트스캔 (수평 스캔 흔적)
for port in [21, 22, 23, 80, 443, 3306, 5432, 8000, 8001, 8080, 9200]:
    pkts.append(IP(src=ATTACKER, dst=TARGET)/TCP(sport=40000, dport=port, flags="S"))

# 2) SQLi 요청 (HTTP GET)
sqli = ("GET /api/telemetry?sensor_id=x' UNION SELECT id,username,password,1 FROM users -- "
        "HTTP/1.1\r\nHost: groundstation\r\nUser-Agent: curl/8.4\r\n\r\n")
pkts.append(IP(src=ATTACKER, dst=TARGET)/TCP(sport=40001, dport=8001, flags="PA")/Raw(load=sqli))

# 3) 유출 응답 (base64로 인코딩된 flag 포함)
leak = base64.b64encode(FLAG.encode()).decode()
resp = (f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
        f'{{"results":[{{"secret":"{leak}"}}]}}')
pkts.append(IP(src=TARGET, dst=ATTACKER)/TCP(sport=8001, dport=40001, flags="PA")/Raw(load=resp))

wrpcap("incident_capture.pcap", pkts)
print("generated incident_capture.pcap")
```

---

## 4. 자동 채점기 (grader/red_grader.py)

```python
import json

def grade_red(submission, context):
    ans = json.load(open("solution/answers.json"))
    fields = ["attacker_ip", "exploited_endpoint", "exfiltrated_flag", "attack_technique"]
    per_field = 50   # 4필드 x 50 = 200
    score = 0
    detail = {}
    for f in fields:
        ok = str(submission.get(f, "")).strip().lower() == ans[f].lower()
        detail[f] = ok
        if ok:
            score += per_field
    return GradeResult(score > 0, score, str(detail))
```

부분점수 방식이라 4개 중 일부만 맞혀도 점수. 조사형 문제의 표준 채점 패턴.

---

## 5. Blue 정답 룰 (solution/detection.yaml)

```yaml
id: FOR-002-SQLI-EXFIL
title: Telemetry SQLi with base64 exfil in response
severity: 3
mitre: [T1190, T1041]
source_type: [suricata, twin]
any:
  - { endpoint: "/api/telemetry", raw.query_contains: ["UNION", "--"] }
  - { http.response_body_matches: "base64-like blob in secret field" }
action_on_match: alert
```

---

## 6. writeup.md (훈련 후)

- 공격 체인: 포트스캔 → SQLi(UNION) → 응답에 유출 데이터 은닉(base64).
- 분석 포인트: HTTP 스트림 팔로우, 응답 본문 디코딩, 스캔 흔적으로 공격자 IP 특정.
- 방어: 파라미터 바인딩(원천 차단) + 아웃바운드 응답의 이상 패턴 탐지.

---

## 7. 포렌식 분야 공통 패턴 (다른 포렌식 문제에 적용)

- **아티팩트 결정론 생성**: pcap/디스크/메모리 이미지를 스크립트로 합성 → C-QA 재현성.
- **조사형 채점**: 단일 플래그가 아니라 필드별 부분점수(attacker/vector/impact).
- **Red=분석, Blue=탐지**로 균형: 같은 사건을 "재구성"과 "탐지룰"의 두 관점으로.
- **SIEM 교차검증**: 같은 사건 데이터를 SIEM Discover에도 넣어 포렌식↔탐지 크로스오버 가능.
```
