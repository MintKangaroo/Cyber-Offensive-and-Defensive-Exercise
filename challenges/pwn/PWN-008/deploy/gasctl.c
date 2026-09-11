/* PWN-008 가스터미널 압력제어 콘솔 (TRAINING ONLY)
 * 스택 버퍼 오버플로우 + ROP 인자 제어: admin_shell 은 rdi=0xC0DEC0DE 일 때만 flag 를 낸다.
 * 단순 ret2win 으로는 인자를 못 넘기므로 `pop rdi; ret` 가젯으로 ROP 체인을 구성해야 한다.
 * no-PIE·no-canary·static 이라 주소가 고정.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* admin_shell 이 링커에 의해 제거되지 않도록 주소를 전역에 보관(공격 표면과 무관, 리텐션용). */
void admin_shell(unsigned long key);
void (*volatile _keep)(unsigned long) = admin_shell;

void admin_shell(unsigned long key) {
    if (key != 0xC0DEC0DEUL) {
        puts("[!] 인증 키 불일치 — 관리자 셸 접근 거부");
        return;
    }
    char line[160];
    FILE *f = fopen("/flag", "r");
    if (!f) { puts("[!] flag 파일 없음(운영 환경 아님)"); return; }
    puts("[+] 관리자 셸 승인 — 압력 안전 인터록 해제:");
    while (fgets(line, sizeof line, f)) fputs(line, stdout);
    fclose(f);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    char buf[64];
    puts("== 가스터미널 압력제어 콘솔 ==");
    puts("압력 설정값(bar)을 입력하세요:");
    read(0, buf, 256);              /* 취약: 64바이트 버퍼에 256바이트 read → 스택 오버플로우 */
    printf("설정 반영됨: %.10s\n", buf);
    return 0;
}
