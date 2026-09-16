# PWN-016 방어 — tcache 이중 free(dup) + safe-linking/key 우회

## 취약점
`free()` 후 슬롯 포인터를 초기화하지 않아(use-after-free) freed 청크를 읽고(show) 쓸(edit) 수 있다.
이로써 glibc 2.3x tcache 의 두 방어를 모두 우회한다.

- **이중 free 탐지(e->key)**: freed 청크의 key(offset 8)를 UAF edit 로 0 으로 지워 우회.
- **safe-linking(fd 난독화)**: freed 청크의 fd 를 UAF show 로 누출 → `fd = chunk>>12` 로 힙 주소 복원.

두 번째 free 직후(freed 상태) fd 를 `(chunk>>12) ^ &g_handler` 로 포이즌하면, tcache count=2 상태에서
첫 malloc 이 청크를 반환하며 head 를 `&g_handler` 로 만들고 둘째 malloc 이 `&g_handler` 를 반환한다.
거기에 `win` 주소를 써서 전역 함수 포인터를 탈취한다.

## 탐지 (Blue)
- `free(p)` 후 `p=NULL` 로 초기화하는지(use-after-free 방지) 감사.
- freed 청크를 읽기/쓰기 가능한 API(show/edit)가 있는지 점검 — 있으면 key/fd 조작 가능.

## 패치
UAF 를 제거하면 이중 free 탐지와 safe-linking 이 정상 동작해 공격이 막힌다.

```c
// 취약: free 후 포인터 유지 → UAF read/write
free(slots[i]);
// 안전: free 후 즉시 무효화 → 이중 free/UAF 원천 차단
free(slots[i]);
slots[i] = NULL;
```

- **free 후 NULL 화**: 가장 확실한 UAF/이중 free 방지.
- **소유권 추적**: 슬롯 상태(할당/해제)를 명시적으로 관리하고 해제된 슬롯 접근을 거부.
- (심층 방어) glibc 의 tcache key/safe-linking 은 유지하되, 애플리케이션 레벨 UAF 를 없애는 것이 핵심.
