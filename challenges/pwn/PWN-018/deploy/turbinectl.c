/* PWN-018 발전 터빈 제어 콘솔 (TRAINING ONLY)
 * ret2csu: 스택 BOF(offset 72)로 반환주소를 덮되, pop rsi/rdx 가젯이 없어 __libc_csu_init 의
 * 범용 가젯 2개로 rdx/rsi/edi 를 세팅하고 함수 포인터를 호출한다. win(a,b,c) 는 세 인자가 매직값과
 * 일치하면 system("cat /flag") 를 실행한다. glibc 2.31(Ubuntu 20.04)에 csu 가젯이 존재.
 * no-PIE 라 주소 고정. (ROP 인자제어 심화 — csu 가젯 활용)
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(long a, long b, long c) {
    if (a == 0xdeadbeef && b == 0xcafebabe && c == 0x13371337) {
        system("cat /flag");
    } else {
        puts("잘못된 제어 파라미터.");
    }
}

/* call qword [r12+rbx*8] 대상: win 을 가리키는 포인터(고정 주소) */
void (*fnptr)(long, long, long) = (void (*)(long, long, long))win;

void vuln(void) {
    char buf[64];
    printf("터빈 파라미터> ");
    fflush(stdout);
    read(0, buf, 512);   /* 취약: 64바이트 버퍼에 512바이트 → 반환주소(offset 72) 덮음 */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("== 발전 터빈 제어 콘솔 ==");
    vuln();
    puts("완료.");
    return 0;
}
