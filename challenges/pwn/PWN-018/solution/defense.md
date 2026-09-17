# PWN-018 방어 — ret2csu(csu 범용 가젯으로 인자 제어)

## 취약점
`vuln()` 의 `read(0, buf, 512)` 가 64바이트 버퍼를 넘겨 반환주소(offset 72)를 덮는다. 카나리·PIE 가
없어 ROP 가 성립하고, `pop rsi/rdx` 같은 개별 가젯이 없어도 **`__libc_csu_init` 의 범용 가젯 2개**로
세 인자를 제어할 수 있다.

```
gadget1: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret
gadget2: mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]; add rbx,1; cmp rbx,rbp; jne ...
```

`rbx=0, rbp=1, r12=edi(a), r13=rsi(b), r14=rdx(c), r15=&fnptr` 로 두면 `win(a,b,c)` 가 매직값과
일치해 `system("cat /flag")` 를 실행한다. `system` 직전 `movaps` 정렬을 위해 `ret` 가젯을 하나 끼운다.

## 탐지 (Blue)
- 고정 버퍼에 크기 검증 없는 `read`(오버플로우)와 카나리/PIE 부재를 `checksec` 로 감사.
- `__libc_csu_init` 범용 가젯 존재 여부(glibc/gcc 버전) 인지 — 최신 toolchain 은 csu 가젯이 없어질 수 있다.

## 패치
경계 검증 + 카나리 + PIE 로 오버플로우와 고정 주소 가젯을 동시에 차단한다.

```c
// 취약: 버퍼(64)보다 큰 512 읽기
read(0, buf, 512);
// 안전: 버퍼 크기로 제한
read(0, buf, sizeof buf - 1);
```

```
gcc -pie -fPIE -fstack-protector-all -Wl,-z,relro,-z,now -O2 ...
```

- **스택 카나리**: 반환주소 덮어쓰기 시 `__stack_chk_fail` 로 즉시 중단.
- **PIE/ASLR**: csu 가젯·`fnptr`·`win` 주소가 무작위화되어 고정 주소 ROP 불가.
- **경계 검증**: 오버플로우 자체를 제거.
