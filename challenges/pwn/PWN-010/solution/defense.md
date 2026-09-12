# PWN-010 방어 — 배열 OOB 쓰기(write-what-where)

## 취약점
`reg[idx] = val` 에서 `idx` 의 부호·상한을 검사하지 않아 배열 경계를 벗어난 상대 쓰기가 된다.
`idx` 를 음수로 주면 배열 앞쪽 전역 메모리를 덮을 수 있고, `val` 은 임의 8바이트다 →
사실상 write-what-where. 직후 호출되는 전역 함수포인터 `handler` 를 숨은 `admin_shell` 로
덮으면 제어 흐름이 탈취된다. no-PIE·static 이라 `reg·handler·admin_shell` 주소가 고정이라
`idx = (&handler - &reg)/8`, `val = &admin_shell` 로 결정적이다.

## 탐지 (Blue)
- 배열 인덱스 대입에 `0 <= idx < N` 검사가 없는 코드 경로(부호 있는 인덱스 포함) 점검.
- 인덱스로 음수·초대형 값이 들어오고 값이 `.text` 범위(0x40xxxx) 주소인 입력 관측.

## 패치
인덱스 경계를 검사한다.

```c
if (idx < 0 || idx >= 16) { puts("범위 밖 인덱스"); return 0; }
reg[idx] = val;
```

경계 검사를 넣으면 음수·초과 인덱스가 거부되어 전역 함수포인터를 오염시킬 수 없다.
심층방어로 PIE·RELRO(전역 함수포인터를 읽기전용 재배치로)·CFI 를 함께 적용한다.
