# ICS-002 — Modbus 사보타주 분석 라이트업

- 분야: ics / 난이도: medium / MITRE: T0836, T0855

## 의도된 해법
1. `modbus_traffic.jsonl` 파싱 → func∈{5,6,16}(write)이고 addr=40001(안전 레지스터)이며 src≠HMI(10.20.0.5)인
   레코드를 찾는다 = 무단 마스터.
2. 그 src가 공격자 IP. 레코드 note(base64)를 공격자 IP로 반복 XOR → `flag{modbus_sabotage_<hmac12>}`.

## 검증
- C-QA `run_all.py --challenge ICS-002`(artifact_solve): 생성→solve→grade_red PASS + 빈제출 거부.
  팀별 HMAC으로 공격자 IP/토큰/플래그 유니크.
