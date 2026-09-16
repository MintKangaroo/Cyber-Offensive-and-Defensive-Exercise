/* PWN-017 배전 자동화 피더 단말 (TRAINING ONLY)
 * ret2dlresolve: dynamically-linked·no-PIE·partial-RELRO(lazy binding). 스택 BOF 로 ROP 를 걸어
 * (1) read 로 .bss 의 stage 버퍼에 가짜 Elf64_Rela/Elf64_Sym/심볼문자열("system")과 "/bin/sh" 를
 * 심고, (2) 조작한 reloc 인덱스로 PLT0(_dl_runtime_resolve 트램폴린)을 호출해 system 을 즉석
 * 해석·호출한다. libc 주소 누출 없이 셸을 얻는다(정적 심볼 해석 악용).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* ROP 게이트: pop rdi; pop rsi; pop rdx; ret (read 인자·rdi 세팅용) */
__asm__(
    ".text\n"
    ".globl rop_gadgets\n"
    "rop_gadgets:\n"
    "    pop %rdi\n"
    "    pop %rsi\n"
    "    pop %rdx\n"
    "    ret\n"
);

char stage[512];   /* .bss — 가짜 구조체를 심을 알려진 쓰기 영역 */

void vuln(void) {
    char buf[64];
    printf("피더 명령> ");
    fflush(stdout);
    read(0, buf, 512);   /* 취약: 64바이트 버퍼에 512바이트까지 → 반환주소(offset 72) 덮음 */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("== 배전 자동화 피더 단말 ==");
    vuln();
    puts("완료.");
    return 0;
}
