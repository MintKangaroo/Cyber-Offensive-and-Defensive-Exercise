/* PWN-021 변전소 원격제어 큐 관리자 (TRAINING ONLY)
 * 힙 선형 오버플로우로 인접 청크 침범: 각 작업(task)은 힙에 {char data[24]; void(*handler)(void);}
 * 구조로 할당되며 handler 는 기본 benign 을 가리킨다. edit 의 쓰기 길이가 할당 크기를 검증하지 않아,
 * 순차 할당으로 인접한 다음 작업의 handler 필드까지 덮어쓸 수 있다(절대주소/leak 불필요, 순수 상대
 * 오프셋 오버플로우). handler 를 win 으로 덮고 run 하면 system("cat /flag"). no-PIE 라 win 고정.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char data[24];
    void (*handler)(void);
} task_t;

void *slots[16];

void win(void) { system("cat /flag"); }
void benign(void) { puts("작업 처리 완료."); }

static long rl(void) {
    char b[32]; int i = 0, c;
    while (i < 31 && (c = getchar()) != EOF && c != '\n') b[i++] = (char)c;
    b[i] = 0; return strtol(b, NULL, 0);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("== 변전소 원격제어 큐 관리자 ==");
    for (;;) {
        puts("1) new_task  2) edit  3) run  0) exit");
        printf("> "); fflush(stdout);
        long op = rl();
        if (op == 0) break;
        if (op == 1) {
            printf("idx> "); fflush(stdout); long i = rl();
            if (i < 0 || i >= 16) { puts("bad"); continue; }
            task_t *t = malloc(sizeof(task_t));
            t->handler = benign;
            slots[i] = t;
        } else if (op == 2) {
            printf("idx> "); fflush(stdout); long i = rl();
            printf("len> "); fflush(stdout); long n = rl();
            if (i < 0 || i >= 16 || !slots[i] || n < 0 || n > 0x200) { puts("bad"); continue; }
            read(0, ((task_t *)slots[i])->data, n);   /* 취약: n 검증 없이 data[24] 넘어 인접 청크 침범 */
        } else if (op == 3) {
            printf("idx> "); fflush(stdout); long i = rl();
            if (i < 0 || i >= 16 || !slots[i]) { puts("bad"); continue; }
            ((task_t *)slots[i])->handler();
        }
    }
    return 0;
}
