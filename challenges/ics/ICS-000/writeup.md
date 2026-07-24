# ICS-000 — 안전 인터록 우회 라이트업

- 분야: ics / 난이도: medium / MITRE: T0836(Modify Parameter), T0858(Change Operating Mode)

## 의도된 해법
1. `GET /modbus/registers` → 40100(SAFETY_KEY) 값 추출(정보 노출 취약점).
2. `POST /modbus/write {addr:40001, value:0, key:<SAFETY_KEY>}` → 인터록 해제 → 서버가
   `flag{modbus_interlock_bypass_<hmac12>}` 발급.

## 검증
- C-QA `run_all.py --challenge ICS-000`(full docker): deploy_up → intended_solve → blank_submit →
  flag_determinism(재배포 일관성) → teardown. 팀별 HMAC으로 키/플래그가 유니크.
