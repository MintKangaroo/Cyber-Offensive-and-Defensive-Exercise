# DET-008 — Foundation Fieldbus MODE_BLK O/S 탐지 라이트업

- 분야: detection / 난이도: hard / MITRE: T0836, T0855, T0831

## 의도된 규칙
`param=MODE_BLK` **AND** `op=write` **AND** `value=OOS` 세 조건을 AND 결합한 match 규칙.
attack_log(MODE_BLK=OOS write 2건)에 알림, normal_log(SP write / MODE_BLK=AUTO·MAN 전환 /
MODE_BLK read)에는 무오탐. O/S 값이 정지(사보타주)와 정상 모드전환을 가르는 핵심 판별자.

## 검증
- C-QA `run_all.py --challenge DET-008`(detection_solve): 데이터셋 생성 → 제출규칙을 실제 SIEM
  DetectionEngine에 태워 attack 탐지 + normal 무오탐 채점. no-op 규칙은 거부.
