# ICS-001 — OPC UA 익명 태그 열람 라이트업

- 분야: ics / 난이도: easy / MITRE: T0886(Remote Services)

## 의도된 해법
1. `GET /opcua/browse` → 주소공간 열거, 진단 노드 `ns=4;s=Diag.Maint_<hmac8>` 발견.
2. `GET /opcua/read?node=<진단노드>` → 익명 세션으로 읽어 `flag{opcua_anon_read_<hmac12>}` 획득.

## 검증
- C-QA `run_all.py --challenge ICS-001`(full docker): deploy_up → intended_solve → blank_submit →
  flag_determinism → teardown. 팀별 HMAC으로 노드/플래그가 유니크.
