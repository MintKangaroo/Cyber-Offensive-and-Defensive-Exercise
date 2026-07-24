# ICS-003 — DNP3 무단 제어 명령 탐지 라이트업

- 분야: ics / 난이도: medium / MITRE: T0855(Unauthorized Command Message)

## 의도된 해법
1. `dnp3_log.jsonl` 파싱 → func∈{4,5}(OPERATE/DIRECT_OPERATE)이고 point=7(보호 차단기)이며
   src≠정상 마스터(10.30.0.4)인 레코드 = 무단 마스터.
2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → `flag{dnp3_unsolicited_control_<hmac12>}`.

## 검증
- C-QA `run_all.py --challenge ICS-003`(artifact_solve): 생성→solve→grade + 빈제출 거부. 팀별 유니크.
