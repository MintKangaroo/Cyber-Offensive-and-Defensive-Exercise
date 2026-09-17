/* PWN-019 배전망 자원 할당기 (TRAINING ONLY)
 * House of force (glibc 2.27): 힙 오버플로우로 top chunk 의 size 를 0xffff..ff 로 덮은 뒤, 거대한
 * malloc 으로 top 포인터를 임의 주소(전역 함수 포인터 g_fnptr) 직전으로 이동시키고, 다음 malloc 이
 * g_fnptr 을 반환하게 해 win 으로 덮는다. glibc 2.27 은 top size 정합성 검사(2.29 도입) 이전이라 성립.
 * no-PIE 라 g_fnptr/win 주소 고정. 힙 주소는 leak 으로 획득.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void *g_slot;
__attribute__((aligned(16))) void (*g_fnptr)(void);

void win(void) { system("cat /flag"); }
void benign(void) { puts("자원 할당 완료."); }

static unsigned long long rl(void) {
    char b[32]; int i = 0, c;
    while (i < 31 && (c = getchar()) != EOF && c != '\n') b[i++] = (char)c;
    b[i] = 0; return strtoull(b, NULL, 0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    g_fnptr = benign;
    puts("== 배전망 자원 할당기 ==");
    for (;;) {
        puts("1) alloc  2) leak  3) run  0) exit");
        printf("> "); fflush(stdout);
        unsigned long long op = rl();
        if (op == 0) break;
        if (op == 1) {
            printf("size> "); fflush(stdout); unsigned long long sz = rl();
            printf("len> "); fflush(stdout); long long ln = rl();          /* 미검증 → 힙 오버플로우 */
            g_slot = malloc(sz);
            if (ln > 0) read(0, g_slot, ln);
        } else if (op == 2) {
            printf("chunk@%p\n", g_slot);                              /* 힙 주소 leak */
        } else if (op == 3) {
            g_fnptr();
        }
    }
    return 0;
}
