# PWN-006 방어 — tcache poisoning(임의 할당) → 전역 함수포인터 하이재킹 차단

## 취약점
냉각채널 버퍼를 `free` 해도 슬롯 포인터를 비우지 않아 **free-후-수정(UAF write)** 이 가능하다.
서로 다른 두 채널을 free 하면 tcache bin 에 2개가 쌓이고(count=2), UAF write 로 bin head 청크의
`next`(glibc safe-linking: `(청크주소>>12) XOR 다음`)를 전역 `g_ctl` 주소로 위조할 수 있다.
그러면 이어지는 두 번째 `malloc` 이 `g_ctl` 자리에 청크를 돌려주고(**tcache poisoning = 임의 주소
할당**), 그 자리에 진단 함수포인터를 `admin_shell` 로 덮어 `/flag` 가 노출된다. 채널 할당 시
출력되는 힙 핸들(`%p`)이 safe-linking 마스크(`addr>>12`) 역산을 가능하게 하는 **정보 노출**이다.

## 패치
- **근본 원인 제거**: `free(ptr); ptr = NULL;` 로 dangling 을 없애 UAF write 를 차단(가장 중요).
- 힙 주소(`%p`)를 사용자에게 출력하지 말 것(safe-linking·ASLR 우회용 정보 노출 제거).
- 해제 상태 플래그로 free 된 슬롯의 갱신/재사용 거부, double free 방지.
- 완화: 최신 glibc(safe-linking·tcache count/alignment 검사), `_FORTIFY_SOURCE`, RELRO/PIE,
  민감한 함수 포인터를 쓰기 가능한 전역 대신 읽기전용 테이블+인덱스로.

## 탐지 관점(blue)
- free 된 채널에 대한 갱신(UAF write)·비정상(대량) 핸들 참조 시퀀스 관측 시 경보.
- 패치 후 free 슬롯 갱신이 거부되어 tcache next 위조가 불가.
