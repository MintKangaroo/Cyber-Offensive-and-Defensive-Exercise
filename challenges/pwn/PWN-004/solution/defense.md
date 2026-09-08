# PWN-004 방어 — 정수 오버플로우(길이 절단) → 스택 BOF 차단

## 취약점
샘플 길이 `count` 를 `int`(부호있음)로 받아 `count > 64` 만 검사한다. 음수 `count` 는 이 검사를
통과하고, read 크기로 넘길 때 `(unsigned short)count` 로 절단되며 거대한 양수가 된다
(예: `-1 → 65535`). 그 결과 `read(0, buf, 65535)` 가 64바이트 스택 버퍼(`buf[64]`)를 넘겨
저장된 복귀주소를 덮고, 숨은 `emergency_dump()` 로 ret2win 되어 `/flag` 가 노출된다.

## 패치
- 길이를 부호 없는 타입으로 받고 하한/상한을 모두 검사: `if (count < 0 || count > sizeof(buf)) reject;`
- read 크기와 검사 대상은 **같은 타입·같은 값**이어야 한다(절단·부호확장으로 값이 갈리지 않게).
  `size_t n = ...; if (n > sizeof(buf)) reject; read(0, buf, n);`
- 컴파일 보호 활성화: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, PIE/RELRO.
- 실행경로에 숨은 `emergency_dump()` 같은 win 함수를 남기지 않기.

## 탐지 관점(blue)
- 샘플 길이 요청에 음수 값 또는 64 를 크게 초과하는 read 길이 관측 시 경보.
- 패치 후 음수 `count` 가 거부되어 복귀주소를 덮을 수 없음(관리자 우회/flag 노출 불가).
