# PWN-012 방어 — SROP(Sigreturn-Oriented Programming)

## 취약점
`read(0, buf, 1024)` 으로 64바이트 버퍼에 1024바이트를 읽어 복귀주소를 덮는다. 개별 pop 가젯이
부족해도, `pop rax; ret` 로 rax=15(rt_sigreturn)를 넣고 `syscall` 을 실행하면 커널이 스택에 놓인
위조 `sigcontext` 로 **모든 레지스터를 한 번에** 복원한다(SROP). 공격자는 프레임에
rax=59·rdi=&"/bin/sh"·rsi=rdx=0·rip=syscall 을 넣어 `execve("/bin/sh",0,0)` 로 셸을 얻는다.
no-PIE·static 이라 가젯·문자열 주소가 고정이라 결정적이다.

## 탐지 (Blue)
- 버퍼(64)보다 큰 read(1024), no-canary·no-PIE 빌드 점검.
- 복귀주소 직후에 `15`(rt_sigreturn)와 syscall 주소, 그리고 ~248바이트의 구조화된 데이터
  (sigcontext 프레임)가 오는 입력 관측.

## 패치
경계 있는 입력 + 표준 완화 재빌드.

```bash
gcc -fstack-protector-all -pie -fPIE -Wl,-z,relro,-z,now -o plcsafe plcsafe.c
# 그리고 read(0, buf, sizeof buf)
```

- **카나리**: 복귀주소 덮기 전에 abort → SROP 트리거 불가.
- **PIE/ASLR**: syscall·"/bin/sh" 주소가 랜덤화되어 고정 프레임이 무력화.
- **경계 있는 read**: 오버플로우 자체가 발생하지 않음.
- (심층방어) seccomp 로 rt_sigreturn·execve 를 제한하면 SROP 자체를 봉쇄.
