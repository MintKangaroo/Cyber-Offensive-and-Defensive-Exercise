# DET-007 — BACnet 무단 WriteProperty 탐지 라이트업

- 분야: detection / 난이도: medium / MITRE: T0855, T0836

## 의도된 규칙
`bacnet_service=15`(WriteProperty) **AND** `object_type=analog-output`(냉방 제어) 을 AND 결합한
match 규칙. attack_log(냉방 write 2건)에 알림, normal_log(read/조명 write)에는 무오탐.

## 검증
- C-QA `run_all.py --challenge DET-007`(detection_solve): 데이터셋 생성 → 제출규칙을 실제 SIEM
  DetectionEngine에 태워 attack 탐지 + normal 무오탐 채점. no-op 규칙은 거부.
