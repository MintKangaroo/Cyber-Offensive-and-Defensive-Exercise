# PWN-020 방어 — seccomp 우회(ORW) 와 근본 원인(스택 BOF)

## 취약점
`vuln()` 의 `read(0, buf, 512)` 가 64바이트 버퍼를 넘겨 반환주소(offset 72)를 덮는다. 프로세스가
`execve/execveat` 를 막는 seccomp 필터를 설치해 셸 실행은 불가하지만, seccomp 는 **BOF 자체를 막지
않는다**. 공격자는 셸 대신 시스콜 ROP 로 `open("/flag")→read→write` 를 수행해 플래그를 직접 읽는다.

```
open("/flag",0,0)  (rax=2) → read(fd,buf,n) (rax=0) → write(1,buf,n) (rax=1)
```

seccomp 는 심층 방어일 뿐, 메모리 손상 취약점이 남아 있으면 파일 읽기/쓰기 계열 시스콜로 우회된다.

## 탐지 (Blue)
- 고정 버퍼에 크기 검증 없는 `read`(오버플로우)와 카나리/PIE 부재를 `checksec` 로 감사.
- seccomp 필터가 `open/read/write` 등 파일 I/O 를 광범위하게 허용하는지 점검(ORW 우회 여지).

## 패치
근본 원인(BOF)을 제거하고, seccomp 필터를 최소 권한으로 좁힌다.

```c
// 취약: 버퍼(64)보다 큰 512 읽기
read(0, buf, 512);
// 안전: 버퍼 크기로 제한
read(0, buf, sizeof buf - 1);
```

```
gcc -fstack-protector-all -pie -fPIE -Wl,-z,relro,-z,now ...
```

- **경계 검증 + 스택 카나리 + PIE**: 반환주소 덮어쓰기(ROP) 자체를 차단.
- **최소 권한 seccomp**: 필요한 시스콜만 allowlist. `open`/`openat` 을 제한하거나 파일 경로를 화이트리스트로
  강제해 ORW 우회 여력을 줄인다.
- **심층 방어**: seccomp 는 메모리 안전 결함을 대체하지 못한다 — 취약점 자체를 없애는 것이 우선.
