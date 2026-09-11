# PWN-008 방어 — 스택 오버플로우 ROP 인자 제어

## 취약점
`read(0, buf, 256)` 으로 64바이트 스택 버퍼에 256바이트를 읽어 복귀주소를 덮을 수 있다.
바이너리는 no-PIE·no-canary·static 이라 주소가 고정이고, 숨은 `admin_shell(key)` 은
`rdi == 0xC0DEC0DE` 일 때만 flag 를 낸다. 공격자는 `pop rdi; ret` 가젯으로 rdi 를 세팅하는
ROP 체인을 구성해 인자를 제어한다(단순 ret2win 으로는 불가).

## 탐지 (Blue)
- 64바이트 버퍼에 256바이트를 읽는 경계 없는 입력 경로, 스택 카나리 부재를 코드/빌드 점검.
- 복귀주소 영역에 `.text` 범위(0x40xxxx)의 고정 주소들이 연속으로 들어오는 입력 관측.

## 패치
스택 카나리를 켜서 재빌드한다.

```bash
gcc -no-pie -fstack-protector-all -O0 -o gasctl gasctl.c
```

카나리가 있으면 버퍼를 넘겨 복귀주소를 덮는 순간 `__stack_chk_fail` 로 프로그램이 중단되어
ROP 체인이 실행되지 않는다(서비스는 정상 응답 유지). 근본적으로는 경계 있는 입력
(`read(0, buf, sizeof buf)`)과 no-execute·PIE·RELRO 등 표준 완화를 함께 적용한다.
