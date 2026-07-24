# ICS-007 — HART 명령 주입 분석 라이트업

- 분야: ics / 난이도: medium / MITRE: T0836, T0855

## 의도된 해법
1. `hart_traffic.jsonl` 파싱 → hart_cmd∈{34,35,45,46}(write)이고 tag=PT-101(안전 트랜스미터)이며
   src≠정상 AMS(10.60.0.5)인 레코드 = 무단 마스터.
2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → `flag{hart_command_injection_<hmac12>}`.

## 검증
- C-QA `run_all.py --challenge ICS-007`(artifact_solve): 생성→solve→grade + 빈제출 거부. 팀별 유니크.
