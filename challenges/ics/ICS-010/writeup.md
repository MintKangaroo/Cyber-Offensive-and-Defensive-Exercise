# ICS-010 — EtherNet/IP CIP 무단 제어 분석 - Safety Assembly Tamper 라이트업

- 분야: ics / 난이도: hard / MITRE: T0836, T0855, T0831

## 의도된 해법
1. `enip_traffic.jsonl` 파싱 → 판별자 부합 & 정상 출발지(10.80.0.5) 아님 = 무단 프레임.
2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → flag.

## 검증
- C-QA artifact_solve: 생성→solve→grade + 빈제출 거부. 팀별 유니크.
