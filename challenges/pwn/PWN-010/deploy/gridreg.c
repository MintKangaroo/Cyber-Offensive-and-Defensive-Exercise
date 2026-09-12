/* PWN-010 송전망 SCADA 레지스터 콘솔 (TRAINING ONLY)
 * 경계 검사 없는 배열 쓰기(reg[idx]=val, idx 부호/범위 무검사) → OOB 상대 쓰기.
 * 전역 함수포인터 handler(=safe_handler)를 admin_shell 로 덮으면 handler() 호출 시 flag.
 * no-PIE·static 이라 reg·handler·admin_shell 주소가 고정.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void admin_shell(void) {
    char line[160];
    FILE *f = fopen("/flag", "r");
    if (!f) { puts("[!] flag 파일 없음(운영 환경 아님)"); return; }
    puts("[+] 관리자 처리기 실행 — 송전 인터록 해제:");
    while (fgets(line, sizeof line, f)) fputs(line, stdout);
    fclose(f);
}

void safe_handler(void) { puts("[*] 정상 처리기: 레지스터 커밋 완료"); }

long reg[16];                              /* 설정 레지스터 배열(.bss) */
void (*handler)(void) = safe_handler;      /* 전역 처리기(.data) — 공격 목표 */

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    long idx, val;
    puts("== 송전망 SCADA 레지스터 콘솔 ==");
    puts("설정할 레지스터 인덱스:");
    if (scanf("%ld", &idx) != 1) return 0;
    puts("값(정수):");
    if (scanf("%ld", &val) != 1) return 0;
    reg[idx] = val;                        /* 취약: 경계 없는 OOB 쓰기 */
    printf("reg[%ld] = 0x%lx 설정됨\n", idx, (unsigned long)val);
    handler();                             /* OOB 로 admin_shell 로 덮이면 flag */
    return 0;
}
