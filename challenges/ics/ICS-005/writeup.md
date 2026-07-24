# ICS-005 — Profinet DCP 스푸핑 분석 라이트업

- 분야: ics / 난이도: medium / MITRE: T0842, T0830

## 의도된 해법
1. `profinet_dcp.jsonl` 파싱 → station_name=plc-line-a 이고 dcp_service에 "Set" 포함이며
   src_mac≠정상 MAC(00:0e:cf:11:22:33)인 레코드 = 신원 스푸핑.
2. 그 src_mac이 공격자 MAC. note(base64)를 공격자 MAC으로 XOR → `flag{profinet_dcp_spoof_<hmac12>}`.

## 검증
- C-QA `run_all.py --challenge ICS-005`(artifact_solve): 생성→solve→grade + 빈제출 거부. 팀별 유니크.
