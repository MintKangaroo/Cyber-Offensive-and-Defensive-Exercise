# DET-010 — EtherNet/IP CIP 안전 어셈블리 무단 SetAttribute 탐지 라이트업

- 분야: detection / 난이도: medium / MITRE: T0836, T0855

## 의도된 규칙
cip_service=16(SetAttributeSingle) AND cip_class=4 AND cip_instance=101 동시 매칭 match 규칙. attack 탐지 + normal 무오탐.

## 검증
- C-QA detection_solve: 데이터셋 생성 → 실제 SIEM DetectionEngine 채점 + no-op 거부.
