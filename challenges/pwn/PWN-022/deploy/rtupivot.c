/* PWN-022 배전 자동화 RTU 명령버퍼 (TRAINING ONLY)
 * 스택 피벗(leave;ret 스택 이주): activate() 의 오버플로우는 저장된 rbp 와 반환주소(ret 슬롯 하나)
 * 까지만 닿아 완전한 ROP 체인을 쌓을 공간이 없다. 대신 load_config() 가 고정 주소 .bss 버퍼
 * (g_config, 512B)에 임의 데이터를 담는다. 저장된 rbp 를 &g_config 로, 반환주소를 leave;ret 가젯으로
 * 덮으면 두 번째 leave;ret 가 rsp 를 g_config 로 옮겨(stack pivot) 미리 적재한 긴 ROP 체인을 실행한다.
 * no-PIE·no-canary 라 g_config·가젯·system 주소 고정.
 *
 * 빌드: gcc -no-pie -fno-stack-protector -static -O0 -o rtupivot rtupivot.c
 *       (glibc 2.31 / Ubuntu 20.04 = pwnbuilder:u20)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char g_config[512];   /* 고정 주소 .bss — 스택 피벗 대상(긴 ROP 체인 적재) */

/* 가젯을 반드시 확보하기 위해 인라인 asm 으로 심는다(주소는 no-PIE 라 고정). */
__asm__(
    ".text\n"
    ".globl gadget_pop_rdi\n"
    "gadget_pop_rdi:\n"
    "    pop %rdi\n"
    "    ret\n"
    ".globl gadget_ret\n"
    "gadget_ret:\n"
    "    ret\n"
    ".globl gadget_leave_ret\n"
    "gadget_leave_ret:\n"
    "    leave\n"
    "    ret\n"
);
extern void gadget_pop_rdi(void);
extern void gadget_ret(void);
extern void gadget_leave_ret(void);

/* 링커가 가젯과 system 을 유지하고 주소가 심볼로 남도록 참조 테이블을 둔다. */
void *const _keep[] = {
    (void *)gadget_pop_rdi,
    (void *)gadget_ret,
    (void *)gadget_leave_ret,
    (void *)system,
};

static long rl(void) {
    char b[32];
    int i = 0, c;
    while (i < 31 && (c = getchar()) != EOF && c != '\n') b[i++] = (char)c;
    b[i] = 0;
    return strtol(b, NULL, 0);
}

void load_config(void) {
    /* .bss 버퍼에 최대 512B 적재 — 공격자는 여기에 완전한 ROP 체인 + 문자열을 담는다. */
    printf("len> "); fflush(stdout);
    long n = rl();
    if (n < 0 || n > (long)sizeof(g_config)) { puts("bad"); return; }
    read(0, g_config, n);
    puts("config loaded.");
}

void activate(void) {
    char buf[64];
    puts("원격 활성화 명령 입력:");
    printf("cmd> "); fflush(stdout);
    /* 취약: buf(64) 를 넘어 저장된 rbp·반환주소까지 읽는다(ret 슬롯 하나뿐 — 체인 공간 없음). */
    read(0, buf, 0x100);
    puts("activation dispatched.");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("== 배전 자동화 RTU 명령 콘솔 ==");
    for (;;) {
        puts("1) load_config  2) activate  3) diag  0) exit");
        printf("> "); fflush(stdout);
        long op = rl();
        if (op == 0) break;
        else if (op == 1) load_config();
        else if (op == 2) activate();
        else if (op == 3) system("echo [diag] RTU queue online");
        else puts("bad");
    }
    return 0;
}
