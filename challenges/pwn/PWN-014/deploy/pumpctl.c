/* PWN-014 수처리장 취수펌프 제어 콘솔 (TRAINING ONLY)
 * 스택 버퍼 오버플로우 + ret2libc(libc leak). read(0,buf,512) 가 64바이트 buf 를 넘겨 저장된
 * 반환주소(offset 72)를 덮는다. 카나리 없음·no-PIE 라 바이너리 주소가 고정.
 *
 * 익스플로잇 2단계:
 *  1) 유출: ROP 로 puts(puts@got) 를 호출해 libc 의 puts 실주소를 누출하고 vuln 으로 복귀.
 *     libc_base = leaked_puts - puts_offset.
 *  2) 셸: ret2libc 로 system("/bin/sh") 호출(정렬용 ret 게이트 포함).
 * dynamically-linked(공유 libc) 라 정적 바이너리와 달리 libc 주소를 런타임에 유출해야 한다.
 * pop rdi; ret 게이트를 보장하려고 전역 asm 게이트를 심어둔다(정상 흐름에선 호출 안 됨).
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* ROP 게이트 보장용: pop rdi; ret / 그리고 바로 뒤 ret(정렬용). */
__asm__(
    ".text\n"
    ".globl rop_gadgets\n"
    "rop_gadgets:\n"
    "    pop %rdi\n"
    "    ret\n"
);

void vuln(void) {
    char buf[64];
    printf("펌프 명령> ");
    fflush(stdout);
    read(0, buf, 512);   /* 취약: 64바이트 버퍼에 512바이트까지 읽어 반환주소 덮어씀 */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    puts("== 수처리장 취수펌프 제어 콘솔 ==");
    puts("명령을 입력하세요. (빈 줄로 종료)");
    for (;;) {
        vuln();           /* 루프 → 유출/셸 2단계를 같은 세션에서 수행 */
    }
    return 0;
}
