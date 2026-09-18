/* PWN-020 보호계전기 진단 샌드박스 (TRAINING ONLY)
 * seccomp 우회(ORW): 프로세스가 execve/execveat 를 막는 seccomp 필터를 설치한다. 따라서 셸을 띄울
 * 수 없다. 스택 BOF(offset 72)로 ROP 를 걸어 open("/flag")→read→write 시스콜 체인으로 플래그를
 * 직접 읽어 출력한다(셸 없이). no-PIE·no-canary. 시스콜 가젯(syscall;ret)과 pop 가젯 제공.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>

/* ROP 가젯: pop rdi/rsi/rdx/rax; ret 와 syscall; ret */
__asm__(
    ".text\n"
    ".globl grop\n"
    "grop:\n"
    "    pop %rdi\n    ret\n"
    "    pop %rsi\n    ret\n"
    "    pop %rdx\n    ret\n"
    "    pop %rax\n    ret\n"
    "    syscall\n    ret\n"
);

char g_path[16] = "/flag";     /* 알려진 주소의 파일 경로 */
char g_buf[256];               /* read 대상 버퍼(알려진 주소) */

static void install_seccomp(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        /* execve(59) → KILL */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        /* execveat(322) → KILL */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        /* 나머지 허용 */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = sizeof(filter) / sizeof(filter[0]), .filter = filter };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

void vuln(void) {
    char buf[64];
    printf("진단 명령> ");
    fflush(stdout);
    read(0, buf, 512);   /* 취약: 64바이트 버퍼에 512바이트 → 반환주소(offset 72) 덮음 */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("== 보호계전기 진단 샌드박스 ==");
    puts("execve 는 봉인되었습니다(seccomp). 셸은 불가.");
    install_seccomp();
    vuln();
    puts("완료.");
    return 0;
}
