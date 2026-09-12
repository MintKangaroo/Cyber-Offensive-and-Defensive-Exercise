# PWN-011 방어 — ROP execve 시스콜 체인

## 취약점
`read(0, buf, 512)` 으로 64바이트 스택 버퍼에 512바이트를 읽어 복귀주소를 덮는다. ret2win
함수는 없지만, 정적·no-PIE 바이너리에는 execve 시스콜을 구성할 가젯(`pop rdi/rsi/rax; ret`,
`pop rdx; pop rbx; ret`, `syscall; ret`)과 `"/bin/sh"` 문자열이 모두 고정 주소로 존재한다.
공격자는 이를 체인해 `execve("/bin/sh", NULL, NULL)` 로 셸을 띄우고 `/flag` 를 읽는다.

## 탐지 (Blue)
- 버퍼 크기보다 큰 고정 길이(64 버퍼에 512) read 하는 경계 없는 입력, no-canary·no-PIE 빌드 점검.
- 복귀주소 영역에 `.text` 범위(0x40xxxx~) 고정 주소가 여러 개 연속으로 들어오는 입력(ROP 체인) 관측.

## 패치
경계 있는 입력 + 표준 완화 재빌드.

```bash
gcc -fstack-protector-all -pie -fPIE -Wl,-z,relro,-z,now -o relayctl relayctl.c
# 그리고 read(0, buf, sizeof buf)
```

- **카나리**: 복귀주소 덮기 전에 `__stack_chk_fail` 로 중단.
- **PIE/ASLR**: 가젯·문자열 주소가 매 실행 랜덤화되어 고정주소 체인이 무력화.
- **경계 있는 read**: 애초에 오버플로우가 발생하지 않음.
