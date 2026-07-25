# ICS-011 — S7comm 안전 DB 무단 쓰기 분석 - Safety DB Write 라이트업

- 분야: ics / 난이도: hard / MITRE: T0836, T0855

## 의도된 해법
1. `s7_traffic.jsonl` 파싱 → 판별자 부합 & 정상 출발지(10.85.0.5) 아님 = 무단 프레임.
2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → flag.

## 검증
- C-QA artifact_solve: 생성→solve→grade + 빈제출 거부. 팀별 유니크.
