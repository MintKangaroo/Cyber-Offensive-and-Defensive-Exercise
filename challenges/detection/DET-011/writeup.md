# DET-011 — S7comm 안전 DB(62) 무단 WRITE_VAR 탐지 라이트업

- 분야: detection / 난이도: medium / MITRE: T0836, T0855

## 의도된 규칙
s7_function=WRITE_VAR AND area=DB AND db_number=62 동시 매칭 match 규칙. attack 탐지 + normal 무오탐.

## 검증
- C-QA detection_solve: 데이터셋 생성 → 실제 SIEM DetectionEngine 채점 + no-op 거부.
