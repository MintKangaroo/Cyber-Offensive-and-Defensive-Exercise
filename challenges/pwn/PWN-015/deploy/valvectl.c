/* PWN-015 정수처리장 밸브 명명 콘솔 (TRAINING ONLY)
 * off-by-one NULL 바이트: read_name() 이 64바이트 name 버퍼 바로 뒤의 함수 포인터 action 과
 * 인접한 스택 구조체를 쓴다. 입력 64바이트를 받으면 종단 널 s.name[64]='\0' 이 정확히 한 바이트
 * 버퍼를 넘겨 action 포인터의 최하위 바이트를 0 으로 만든다(single NULL overflow).
 * action 은 원래 benign() 을 가리키는데 benign 은 win() 과 같은 256바이트 정렬 블록에 있어
 * 최하위 바이트를 0 으로 만들면 action == win() 이 되어, 이어지는 s.action() 호출이 win()
 * (system("cat /flag"))으로 흐른다. no-PIE 라 함수 주소가 고정 → 결정적(스택 ASLR 무관).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* win 을 256정렬 → 주소 최하위 바이트 0x00. benign 을 바로 뒤(같은 256블록)에 배치. */
__attribute__((aligned(256))) void win(void) {
    system("cat /flag");   /* 정상 흐름에선 도달 불가 — off-by-one NULL 로만 */
}
void benign(void) {
    puts("정상 밸브가 등록되었습니다.");
}

void read_name(void) {
    struct { char name[64]; void (*action)(void); } s;
    s.action = benign;                 /* 원래는 benign() */
    printf("밸브 이름> ");
    fflush(stdout);
    int n = 0, c;
    while (n < 64 && (c = getchar()) != EOF && c != '\n')
        s.name[n++] = (char)c;
    s.name[n] = '\0';                  /* off-by-one: n==64 이면 s.action 의 LSB 를 NULL 로 */
    s.action();                        /* LSB 가 0 이 되면 benign→win */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("== 정수처리장 밸브 명명 콘솔 ==");
    read_name();
    return 0;
}
