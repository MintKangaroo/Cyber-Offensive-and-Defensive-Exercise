# PWN-022 방어 — 스택 피벗(leave;ret 스택 이주)

## 취약점
`activate()` 의 `read(0, buf, 0x100)` 이 `char buf[64]` 크기를 검증하지 않아 저장된 rbp 와 반환주소를
덮는다. 오버플로우 범위가 반환주소(ret 슬롯 하나)까지만 닿아 그 자리에 완전한 ROP 체인을 쌓을 수는
없지만, 공격자는 **스택 피벗**으로 이를 우회한다:

```
1) load_config 로 고정 주소 .bss(g_config, 512B)에 완전한 ROP 체인 + 문자열을 미리 적재
2) activate 오버플로우로 저장된 rbp = &g_config, 반환주소 = `leave; ret` 가젯
3) activate 의 leave;ret → rbp=&g_config, 두 번째 leave;ret 가 rsp 를 g_config 로 이주
4) g_config 에 적재된 체인 실행: pop rdi; &"cat /flag"; system → system("cat /flag")
```

`leave = mov rsp,rbp; pop rbp` 이므로, 저장된 rbp 를 조작하면 다음 `leave;ret` 에서 rsp 가 공격자
버퍼로 옮겨가는 것이 핵심이다. no-PIE 라 g_config·가젯·system 주소가 고정이다.

## 탐지 (Blue)
- 고정 크기 스택 버퍼에 대해 크기를 검증하지 않는 `read/recv/gets` 사용 여부 감사.
- 반환주소가 `leave;ret` 가젯이나 .bss/.data 영역을 가리키는 비정상 제어흐름(스택 피벗) 탐지.

## 패치
읽기 길이를 버퍼 크기로 제한해 저장된 rbp·반환주소 침범 자체를 차단한다.

```c
// 취약: 버퍼 크기를 넘어 저장 rbp/반환주소까지 침범
read(0, buf, 0x100);           // buf[64] 인데 256B 읽음

// 안전: 버퍼 크기로 제한
ssize_t n = read(0, buf, sizeof(buf) - 1);
if (n > 0) buf[n] = 0;
```

- **경계 검증**: 스택 버퍼에는 항상 `sizeof(buf)` 이하로만 읽기.
- **스택 카나리**(`-fstack-protector-strong`): 저장된 rbp/반환주소 손상을 실행 전에 탐지.
- **PIE + Full RELRO**(`-fpie -pie -Wl,-z,now`): 가젯/전역 버퍼 주소 무작위화로 고정 주소 피벗 무력화.
- **Non-executable + 최소 .bss 노출**: 공격자 제어 고정 주소 버퍼(g_config)를 두지 않기.
