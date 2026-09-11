/* PWN-009 댐 방류 게이트 제어 콘솔 (TRAINING ONLY)
 * 스택 카나리(-fstack-protector-all) 존재. 1단계에서 경계 없는 write 로 카나리를 유출한 뒤,
 * 2단계 오버플로우에서 유출한 카나리를 제자리에 넣어 검사를 통과시키고 복귀주소를
 * spillway_override 로 덮는다(카나리 우회 → ret2win). no-PIE·static 이라 주소 고정.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void spillway_override(void);
void (*volatile _keep)(void) = spillway_override;  /* 링커 리텐션 */

void spillway_override(void) {
    char line[160];
    FILE *f = fopen("/flag", "r");
    if (!f) { puts("[!] flag 파일 없음(운영 환경 아님)"); return; }
    puts("[+] 방류 게이트 비상 오버라이드 승인:");
    while (fgets(line, sizeof line, f)) fputs(line, stdout);
    fclose(f);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    char buf[64];
    puts("== 댐 방류 게이트 제어 콘솔 ==");
    puts("게이트 상태 조회 코드(64바이트) 입력:");
    read(0, buf, 64);            /* 딱 64바이트 채움(오버플로우 아님) */
    printf("조회 응답: ");
    write(1, buf, 80);           /* 취약: buf 뒤 카나리(rbp-8, buf+72)까지 반향 → 카나리 유출 */
    puts("");
    puts("방류 설정 페이로드 입력:");
    read(0, buf, 256);           /* 취약: 스택 오버플로우(카나리 검사 있음) */
    puts("설정 반영됨");
    return 0;
}
