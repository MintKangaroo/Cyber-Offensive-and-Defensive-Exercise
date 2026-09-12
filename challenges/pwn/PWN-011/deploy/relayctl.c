/* PWN-011 변전소 제어 릴레이 콘솔 (TRAINING ONLY)
 * 스택 버퍼 오버플로우 → ROP 로 execve("/bin/sh",0,0) 시스콜 체인을 구성해 셸 획득.
 * ret2win 함수가 없으므로 정적 바이너리의 가젯(pop rdi/rsi/rdx/rax; syscall)과 "/bin/sh"
 * 문자열을 조합해야 한다. no-PIE·no-canary·static 이라 주소 고정.
 */
#include <stdio.h>
#include <unistd.h>

/* "/bin/sh" 문자열을 바이너리에 확실히 포함(고정 주소 제공). */
const char binsh[] = "/bin/sh";

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    char buf[64];
    puts("== 변전소 제어 릴레이 콘솔 ==");
    puts("릴레이 명령 입력:");
    read(0, buf, 512);          /* 취약: 64바이트 버퍼에 512바이트 → 스택 오버플로우 */
    puts("명령 처리됨");
    return 0;
}
