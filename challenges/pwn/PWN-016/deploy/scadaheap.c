/* PWN-016 SCADA 태그 캐시 관리자 (TRAINING ONLY)
 * tcache 이중 free(double-free) + safe-linking/key 우회 → tcache 포이즈닝 → 전역 함수 포인터 탈취.
 * glibc 2.3x tcache: (1) 이중 free 는 e->key 검사로 막히지만 UAF edit 로 key 를 지워 우회,
 * (2) fd 는 safe-linking((chunk>>12)^next)으로 난독화되나 UAF show 로 freed chunk 의 fd(=chunk>>12)를
 *     누출해 복원. 이중 free 로 같은 청크를 tcache 에 두 번 넣고, 반환된 청크의 fd 를 &g_handler 로
 *     포이즌해 이어지는 malloc 이 &g_handler 를 반환 → win 으로 덮고 run 실행.
 * static·no-PIE 라 win/&g_handler 주소 고정. 힙 ASLR 은 누출로 복원.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NSLOT 16
static void *slots[NSLOT];
static long sizes[NSLOT];

__attribute__((aligned(16))) void (*g_handler)(void);

void win(void) { system("cat /flag"); }         /* off-path: 포이즈닝으로만 도달 */
void benign(void) { puts("태그 캐시 정상 처리."); }

static int rl(void) {
    char b[32]; int i = 0, c;
    while (i < 31 && (c = getchar()) != EOF && c != '\n') b[i++] = (char)c;
    b[i] = 0; return atoi(b);
}

static void menu(void) {
    puts("1) alloc  2) free  3) edit  4) show  5) run  0) exit");
    printf("> "); fflush(stdout);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    g_handler = benign;
    puts("== SCADA 태그 캐시 관리자 ==");
    for (;;) {
        menu();
        int op = rl();
        if (op == 0) break;
        if (op == 1) {
            printf("slot> "); fflush(stdout); int i = rl();
            printf("size> "); fflush(stdout); long s = rl();
            if (i < 0 || i >= NSLOT || s <= 0 || s > 0x400) { puts("bad"); continue; }
            slots[i] = malloc(s); sizes[i] = s;
        } else if (op == 2) {
            printf("slot> "); fflush(stdout); int i = rl();
            if (i < 0 || i >= NSLOT) { puts("bad"); continue; }
            free(slots[i]);                 /* UAF: 포인터 미초기화 */
        } else if (op == 3) {
            printf("slot> "); fflush(stdout); int i = rl();
            printf("len> "); fflush(stdout); long n = rl();
            if (i < 0 || i >= NSLOT || !slots[i] || n < 0 || n > 0x400) { puts("bad"); continue; }
            read(0, slots[i], n);           /* UAF write */
        } else if (op == 4) {
            printf("slot> "); fflush(stdout); int i = rl();
            if (i < 0 || i >= NSLOT || !slots[i]) { puts("bad"); continue; }
            write(1, slots[i], 8);          /* UAF read(누출) */
        } else if (op == 5) {
            g_handler();
        }
    }
    return 0;
}
