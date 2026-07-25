# DET-012 — MQTT Sparkplug B 무단 액추에이터 DCMD 탐지 라이트업

- 분야: detection / 난이도: medium / MITRE: T0855, T0831

## 의도된 규칙
message_type=DCMD AND metric~Pump/Control 동시 매칭 match 규칙. attack 탐지 + normal 무오탐.

## 검증
- C-QA detection_solve: 데이터셋 생성 → 실제 SIEM DetectionEngine 채점 + no-op 거부.
