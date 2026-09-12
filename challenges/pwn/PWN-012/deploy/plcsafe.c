/* PWN-012 터빈 세이프티 PLC 콘솔 (TRAINING ONLY)
 * 스택 오버플로우 → SROP(Sigreturn-Oriented Programming): pop rax=15 후 syscall 로
 * rt_sigreturn 을 호출해 스택의 위조 sigcontext 로 모든 레지스터를 세팅, execve("/bin/sh",0,0).
 * pop-가젯 ROP(PWN-011)와 달리 단 두 가젯(pop rax; ret, syscall)만으로 전 레지스터를 제어한다.
 * no-PIE·no-canary·static 이라 주소 고정.
 */
#include <stdio.h>
#include <unistd.h>

const char binsh[] = "/bin/sh";

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    char buf[64];
    puts("== 터빈 세이프티 PLC 콘솔 ==");
    puts("세이프티 파라미터 입력:");
    read(0, buf, 1024);         /* 취약: 64바이트 버퍼에 1024바이트 → 대형 스택 오버플로우 */
    puts("파라미터 반영됨");
    return 0;
}
