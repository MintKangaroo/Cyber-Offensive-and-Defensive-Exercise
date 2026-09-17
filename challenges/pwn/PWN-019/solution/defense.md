# PWN-019 방어 — House of force(top chunk 크기 변조)

## 취약점
`alloc` 의 읽기 길이 `len` 이 검증되지 않아 힙 오버플로우가 발생한다. 첫 청크에서 넘쳐 **top chunk 의
size 필드를 `0xffffffffffffffff`** 로 덮으면, glibc 2.27 은 top size 정합성 검사(2.29 도입)가 없어
거대한 `malloc(nb)` 가 그대로 처리된다.

```
malloc(nb): victim = av->top; av->top = victim + nb; return victim+0x10
→ nb = (target - 0x10) - top_chunk 로 두면 av->top 이 target-0x10 으로 이동(래핑)
→ 다음 malloc 이 target(전역 함수 포인터)을 반환 → win 으로 덮어 실행
```

## 탐지 (Blue)
- 할당 크기와 쓰기 길이의 관계를 감사 — `len > 요청 size` 면 힙 오버플로우.
- top chunk size 가 비정상적으로 큰 값으로 바뀌는지, 거대한 malloc 요청이 들어오는지 점검.

## 패치
쓰기 길이를 요청 크기로 제한해 오버플로우를 없애고, 최신 glibc 의 완화를 활용한다.

```c
// 취약: len 미검증 → top chunk size 변조 가능
if (ln > 0) read(0, g_slot, ln);
// 안전: 쓰기 길이를 할당 크기로 제한
if (ln > 0 && (unsigned long long)ln <= sz) read(0, g_slot, ln);
```

- **경계 검증**: 읽기 길이를 할당 크기 이내로 제한 → top chunk 변조 불가.
- **glibc 2.29+**: top chunk size 정합성 검사(`malloc(): corrupted top size`)로 House of force 자체가 완화됨.
- 거대/음수 크기 malloc 요청을 상한으로 거부한다.
