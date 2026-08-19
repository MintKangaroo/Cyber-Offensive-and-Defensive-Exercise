# DET-013 방어 노트 — 위성 TT&C 무단 자세제어 안전해제 탐지 (CCSDS)

## 핵심
`raw.protocol=ccsds` **AND** `raw.command=DISABLE_ATTITUDE_SAFETY` 동시 매칭.

## 왜 단일 조건은 안 되나
- `protocol=ccsds` 만: 정상 업링크(PING·SET_ATTITUDE·ENABLE_ATTITUDE_SAFETY·하우스키핑 TM)에
  모두 오탐 → 위성 링크가 항상 시끄러워 알림 무의미.
- `command=DISABLE_ATTITUDE_SAFETY` 만: 지상 변경관리 감사 로그(예약 정비 창, 이중승인)처럼
  '커맨드 이름'만 같은 정상 기록에 오탐.

두 조건을 AND 로 묶어야 "지상국 업링크로 실제 전송된, 위성 자세제어 SIS 를 끄는 텔레커맨드"만
정확히 걸린다.

## 배경 (왜 위험한가)
CCSDS Space Packet TT&C 는 인증이 약한 우주 링크다. 자세제어 안전장치(attitude SIS)를 끄면
추력기 과조작·태양지향 상실로 위성 자세를 잃을 수 있다(T0855 Unauthorized Command Message,
T0814 Denial of Service). 트윈(ground_station:1234)이 실제 CCSDS 를 말하므로 표준 도구가
그대로 붙고, 무단 커맨드는 `raw.protocol=ccsds` SIEM access 로그로 흘러 이 규칙에 걸린다.

## 대응
- 업링크 커맨드 인증/서명(가능하면) + 위험 커맨드(안전해제류)에 이중승인 게이트.
- 이 탐지 규칙을 상시 가동해 안전해제 업링크를 즉시 인시던트로 승격.
