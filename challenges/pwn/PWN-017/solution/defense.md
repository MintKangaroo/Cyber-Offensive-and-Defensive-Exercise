# PWN-017 방어 — ret2dlresolve(동적 심볼 해석 악용)

## 취약점
`vuln()` 의 `read(0, buf, 512)` 가 64바이트 버퍼를 넘겨 반환주소(offset 72)를 덮는다. 카나리·PIE 가
없고 **partial RELRO(lazy binding)** 라, libc 주소 누출 없이 동적 링커의 지연 해석을 악용할 수 있다.

1. ROP 로 `read` 를 호출해 `.bss` 에 가짜 `Elf64_Rela`/`Elf64_Sym`/심볼 문자열("system")과 "/bin/sh" 를 심는다.
2. 조작한 reloc 인덱스로 `PLT0`(_dl_runtime_resolve 트램폴린)을 호출하면, 링커가 가짜 구조체를 따라
   `system` 을 즉석 해석해 GOT 에 채우고 곧바로 호출한다. `system("/bin/sh")` 로 셸.

`system` 호출 직전 스택이 16바이트 정렬되어야(`movaps`) 하므로 정렬용 `ret` 가젯을 하나 끼운다.

## 탐지 (Blue)
- 고정 버퍼에 크기 검증 없는 `read`(오버플로우)와 **partial RELRO/lazy binding** 여부(`checksec`)를 감사.
- `.bss`/데이터 영역에 임의 쓰기가 가능한 ROP 경로가 있는지 점검.

## 패치
Full RELRO 로 지연 해석을 없애고(GOT 읽기전용), 경계 검증·카나리·PIE 를 병행한다.

```
# 취약: partial RELRO(lazy) → ret2dlresolve 가능
gcc -no-pie -fno-stack-protector -Wl,-z,relro,-z,lazy ...
# 안전: Full RELRO(즉시 바인딩) + 카나리 + PIE + 경계 검증
gcc -pie -fPIE -fstack-protector-all -Wl,-z,relro,-z,now ...
read(0, buf, sizeof buf - 1);
```

- **Full RELRO(`-z now`)**: 시작 시 모든 심볼을 해석하고 GOT 를 읽기전용으로 → `_dl_runtime_resolve`
  경로 자체가 사라져 ret2dlresolve 불가.
- **PIE/ASLR**: PLT0·가젯·`.bss` 주소가 무작위화되어 고정 주소 기반 ROP 불가.
- **스택 카나리·경계 검증**: 최초 오버플로우로 반환주소를 덮는 것 자체를 차단.
