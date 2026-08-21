# ICS-000 방어 노트 (Blue) — 실 Modbus/TCP

## 취약점
- **Modbus 무인증**: 포트(5020)에 도달한 누구나 FC5/FC16 으로 안전 인터록(coil0)과
  RPM 명령(holding0)을 쓸 수 있다. 프로토콜 차원의 인증·무결성이 존재하지 않는다.
- 인터록(SIS)을 FC5 로 해제한 뒤 과속 명령을 쓰면 물리 사보타주(자산 손상)가 실현된다.

## 권장 방어 (프로토콜 자체를 못 고치므로 주변에서 보완)
1. **네트워크 세그먼테이션**: SIS/제어망을 IT·참가자망과 L3 분리. Modbus 포트는
   허가된 엔지니어링 워크스테이션 IP 화이트리스트에서만 도달 가능하게.
2. **쓰기 차단/승인**: 안전 임계 레지스터·인터록 코일 쓰기는 일방향 게이트웨이 또는
   변경관리 승인(4-eyes) 뒤로. read-only 프록시로 참가자망엔 읽기만 노출.
3. **인증 계층 도입**: Modbus/TCP 앞단에 인증 프록시(또는 Modbus/TLS·secure gateway)를
   두어 무인증 쓰기를 거부.
4. **탐지**: 인터록 코일 쓰기(FC5 coil0)·과속 setpoint 쓰기를 SIEM 룰로 경보
   (플랫폼 `services/siem/detection/rules/ics_layer.yaml` 참조 — raw.protocol=modbus).

핵심 키워드: **인증 / 세그먼테이션 / 쓰기 차단**.
