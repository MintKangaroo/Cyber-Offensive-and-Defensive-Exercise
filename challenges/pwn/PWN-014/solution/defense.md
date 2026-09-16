# PWN-014 방어 — 스택 BOF ret2libc(libc leak)

## 취약점
`vuln()` 이 64바이트 스택 버퍼에 `read(0, buf, 512)` 로 512바이트까지 읽어 저장된 반환주소
(offset 72)를 덮는다. 카나리가 없어 즉시 제어권 탈취가 되고, no-PIE 라 바이너리 가젯/PLT 주소가
고정이다. 공유 libc 라 주소가 매 실행 달라지지만, `puts@plt(puts@got)` 로 libc 실주소를 **유출**해
`libc_base` 를 계산한 뒤 `ret2libc` 로 `system("/bin/sh")` 를 호출한다.

```
1) pop rdi; ret → puts@got → puts@plt → vuln   # GOT[puts]=libc puts 유출, 재진입
   libc_base = leaked_puts - puts_offset
2) pop rdi; ret → &"/bin/sh" → ret → system     # system("/bin/sh")
```

## 탐지 (Blue)
- 고정 크기 스택 버퍼에 크기 검증 없이 읽는 호출(`read(fd,buf,고정상수>버퍼크기)`)을 감사.
- 스택 카나리/PIE/RELRO 부재를 `checksec` 로 관측 — 모두 꺼져 있으면 BOF→ret2libc 가 성립.

## 패치
경계 검증 + 컴파일러 완화 재빌드로 오버플로우와 주소 예측을 동시에 차단한다.

```c
// 취약: 버퍼 크기(64)보다 큰 512 읽기
read(0, buf, 512);
// 안전: 버퍼 크기로 제한
read(0, buf, sizeof buf - 1);
```

```
# 재빌드 완화
gcc -fstack-protector-all -pie -fPIE -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -O2 ...
```

- **스택 카나리**(`-fstack-protector-all`): 반환주소 덮어쓰기 시 `__stack_chk_fail` 로 중단.
- **PIE/ASLR**(`-pie -fPIE`): 바이너리 가젯·PLT 주소가 무작위화되어 no-PIE 고정 가젯 사용 불가.
- **Full RELRO**(`-z relro -z now`): GOT 읽기전용 → GOT 기반 우회 차단.
- **경계 검증**: 읽기 길이를 버퍼 크기로 제한해 오버플로우 자체를 제거.
