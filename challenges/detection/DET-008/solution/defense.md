# DET-008 방어 노트 — Foundation Fieldbus MODE_BLK O/S 탐지

## 핵심
MODE_BLK 파라미터 write 자체는 정상 운전(AUTO/MAN 전환)에도 발생한다. 사보타주 시그널은
**"안전 블록의 MODE_BLK를 O/S(Out of Service)로 write"** — O/S는 함수블록을 정지시켜 PID
제어 루프를 무력화한다(T0831 Manipulation of Control). 따라서 `param=MODE_BLK AND op=write
AND value=OOS` 세 조건을 AND로 결합해야 한다.

## 함정
- `param=MODE_BLK` 만 보면 MODE_BLK read / AUTO·MAN 전환에 오탐.
- `op=write` 만 보면 SP/OUT write에 오탐.
- `value=OOS` 조건이 정지(사보타주)와 정상 모드전환(AUTO/MAN)을 가른다.

## 심화(운영)
- src_addr가 정상 LAS/DCS(0x10/0x11)가 아닌 링크주소면 심각도 상향.
- 안전 관련 블록(FIC/PIC/LIC 등 인터록 연동) 화이트리스트로 대상 블록을 좁히면 정밀도↑.
