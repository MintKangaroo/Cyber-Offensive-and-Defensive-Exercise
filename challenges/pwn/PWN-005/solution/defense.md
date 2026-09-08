# PWN-005 방어 — Use-After-Free 함수포인터 하이재킹 차단

## 취약점
위성 객체(`struct sat`)의 첫 필드가 함수 포인터(`action`)다. 등록해제 시 `free(slots[i])` 만
하고 `slots[i]` 를 비우지 않아 **dangling 포인터**가 남는다(Use-After-Free). 공격자는 위성과
같은 크기(32B)의 관제 메모를 `malloc` 해 tcache 가 방금 free 된 청크를 재사용하게 만들고,
메모 앞 8바이트로 `action` 을 숨은 `admin_override()` 로 덮는다. 이후 그 위성을 실행하면
하이재킹된 함수가 호출되어 `/flag` 가 노출된다.

## 패치
- `free` 직후 포인터를 무효화: `free(slots[i]); slots[i] = NULL;` (dangling 제거).
- 실행 전 슬롯 유효성/생존 플래그 확인, 이중 해제(double free) 방지.
- 민감한 함수 포인터를 사용자 제어 힙 버퍼와 같은 청크에 두지 않기(간접호출 대신 인덱스/테이블).
- 완화: `-fstack-protector-strong`, RELRO/PIE, glibc tcache safe-linking(주소 유출 없으면
  포인터 위조는 어렵지만, 본 문제처럼 **덮어쓰기**엔 무력하므로 근본 원인=dangling 을 제거).

## 탐지 관점(blue)
- 등록해제(free)된 슬롯에 대한 실행/재점유 시퀀스(delete→note→run) 관측 시 경보.
- 패치 후 free 된 슬롯 실행이 거부되어 함수포인터 하이재킹 불가.
