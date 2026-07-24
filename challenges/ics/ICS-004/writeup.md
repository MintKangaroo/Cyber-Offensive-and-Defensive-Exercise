# ICS-004 — IEC 104 ASDU 조작 추적 라이트업

- 분야: ics / 난이도: medium / MITRE: T0855(Unauthorized Command Message)

## 의도된 해법
1. `iec104_log.jsonl` 파싱 → asdu_type∈{45..51}(제어)이고 ioa=7(보호 차단기)이며
   src≠정상 마스터(10.40.0.3)인 레코드 = 무단 제어국.
2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → `flag{iec104_command_injection_<hmac12>}`.

## 검증
- C-QA `run_all.py --challenge ICS-004`(artifact_solve): 생성→solve→grade + 빈제출 거부. 팀별 유니크.
