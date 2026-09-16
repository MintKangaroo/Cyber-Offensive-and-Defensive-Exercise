/* PWN-013 SCADA HMI 진단 콘솔 (TRAINING ONLY)
 * 포맷 스트링 취약점: 사용자 입력을 printf(buf) 로 서식 인자 없이 그대로 출력한다.
 * %n 계열로 임의 주소에 임의 값을 쓸 수 있어, printf 의 GOT 엔트리를 win() 주소로 덮으면
 * 다음 루프의 printf("입력> ") 호출이 win() → system("/bin/sh") 로 흘러 셸을 얻는다.
 * dynamically-linked·no-PIE·partial-RELRO(GOT 쓰기가능·lazy) 이라 주소 고정.
 * (스택 BOF/ROP 계열과 구분되는 포맷스트링 임의쓰기 기법)
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    /* 정상 흐름에서는 절대 호출되지 않는다 — 포맷스트링 GOT 덮어쓰기로만 도달. */
    system("/bin/sh");
}

int main(void) {
    char buf[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("== SCADA HMI 진단 콘솔 ==");
    puts("진단 커맨드를 입력하세요(최대 6회).");
    for (int i = 0; i < 6; i++) {
        printf("입력> ");                 /* GOT[printf] 가 덮이면 이 호출이 win() 로 */
        if (!fgets(buf, sizeof buf, stdin)) break;
        printf(buf);                       /* 취약: 서식 문자열 = 사용자 입력 */
    }
    puts("세션 종료");
    return 0;
}
