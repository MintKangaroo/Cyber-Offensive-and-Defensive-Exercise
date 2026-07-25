# ICS-008 — BACnet 무단 WriteProperty 분석 라이트업

- 분야: ics / 난이도: medium / MITRE: T0855, T0836

## 의도된 해법
1. `bacnet_traffic.jsonl` 파싱 → bacnet_service=15(WriteProperty)이고 object_type=analog-output
   (CRAC 냉방 setpoint)이며 src≠정상 BMS(10.70.0.10)인 레코드 = 무단 장치.
2. 그 src가 공격자 IP. note(base64)를 공격자 IP로 XOR → `flag{bacnet_priority_override_<hmac12>}`.

## 함정
- 정상 BMS도 조명(binary-output)에 WriteProperty를 하지만 object_type/src로 걸러진다.
- priority 8(수동 오버라이드)이 사보타주 시그널이나, 판별 키는 object_type+src.

## 검증
- C-QA `run_all.py --challenge ICS-008`(artifact_solve): 생성→solve→grade + 빈제출 거부. 팀별 유니크.
