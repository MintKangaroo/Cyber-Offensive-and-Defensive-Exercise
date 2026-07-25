# DET-007 방어 노트 — BACnet 무단 WriteProperty 탐지

## 핵심
BACnet WriteProperty(service 15)는 조명 스케줄 등 정상 운용에도 쓰인다. 사보타주 시그널은
**"냉방 제어 객체(analog-output)에 대한 write"** 라는 조합이다. 따라서 단일 조건이 아니라
`bacnet_service=15 AND object_type=analog-output` 을 AND로 결합해야 한다.

## 함정
- `bacnet_service=15` 만 보면 조명(binary-output) 정상 write에 오탐.
- `object_type=analog-output` 만 보면 냉방 setpoint read(service 12)에 오탐.

## 심화(운영)
- priority ≥ 8(수동 오버라이드)와 src가 정상 BMS 워크스테이션이 아닌 경우를 결합하면 정밀도↑.
- 실제 환경에선 WritePropertyMultiple(service 16)도 함께 감시.
