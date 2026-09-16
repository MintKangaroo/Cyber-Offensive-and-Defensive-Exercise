# PWN-013 방어 — 포맷 스트링 GOT 덮어쓰기

## 취약점
사용자 입력을 `printf(buf)` 로 **서식 문자열 자리에 직접** 넣는다. 공격자가 `%p`/`%x` 로 스택을
누출하고 `%n`/`%hn` 으로 임의 주소에 임의 값을 쓸 수 있다. 여기서는 `printf` 의 GOT 엔트리를
`win()`(=`system("/bin/sh")`) 주소로 덮어 다음 `printf` 호출이 셸로 흐른다.

- no-PIE → `win`·GOT 주소 고정, partial-RELRO → `.got.plt` 쓰기 가능(lazy binding).
- 큰 주소는 `%hn`(2바이트) 두 번으로 나눠 쓰고, 지시부 뒤에 타깃 주소를 8정렬 배치.

## 탐지 (Blue)
- 사용자 입력이 `printf`/`fprintf`/`syslog` 등의 **첫 인자(서식)** 로 들어가는 코드 감사
  (`-Wformat-security` 경고, `%n` 사용 여부).
- `checksec`: RELRO 수준, PIE 여부 확인. partial-RELRO + no-PIE 는 GOT 덮어쓰기에 취약.

## 패치
서식 문자열을 **고정**하고 GOT 를 읽기전용으로 만든다.

```c
// 취약: 사용자 입력이 서식 문자열
printf(buf);
// 안전: 서식 고정 — 입력은 데이터로만
printf("%s", buf);
```

빌드 옵션:
```
gcc -pie -fstack-protector-all -Wl,-z,relro,-z,now -o hmicon hmicon.c   # Full RELRO + PIE
```

- **`printf("%s", buf)`**: `%n` 지시자가 입력에서 해석되지 않아 임의쓰기 불가.
- **Full RELRO(`-z relro -z now`)**: 로더가 GOT 를 즉시 바인딩 후 읽기전용으로 만들어 덮어쓰기 차단.
- **PIE + `_FORTIFY_SOURCE=2`**: 주소 랜덤화·서식 검사로 다층 방어.
