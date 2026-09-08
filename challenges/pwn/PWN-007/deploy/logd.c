// 발전소 로그 수집 데몬 (TRAINING ONLY) — 포맷 스트링 임의쓰기 → 전역 함수포인터 하이재킹.
// 로그 메시지를 printf(buf) 로 그대로 출력해 포맷 스트링 취약점이 있다(%n 임의쓰기 가능).
// 전역 처리기 g_log(정상 처리기로 초기화)를 %hn 으로 admin_shell 로 덮은 뒤 '로그 처리'를
// 실행하면 /flag 가 노출된다. no-PIE 라 g_log·admin_shell 주소가 고정이고, 두 함수가 같은
// 0x40xxxx 영역이라 하위 2바이트만 덮으면 된다.
// 컴파일: gcc -static -no-pie -fno-stack-protector.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void log_normal(void){ puts("[로그처리] 이벤트 정상 적재 완료"); }

// 전역 함수포인터: 포맷스트링 임의쓰기의 목표.
void (*g_log)(void) = log_normal;

// 숨은 win — 정상 흐름에선 호출되지 않는다. g_log 를 여기로 덮으면 /flag 노출.
void admin_shell(void){
    char flag[128];
    FILE *f = fopen("/flag","r");
    if(!f){ puts("[!] flag 열기 실패"); _exit(1); }
    if(fgets(flag,sizeof(flag),f)) printf("[관리 콘솔] 마스터 토큰: %s\n", flag);
    fclose(f); fflush(stdout); _exit(0);
}

static void log_event(void){
    char buf[256];
    printf("로그 메시지> ");
    int n = read(0, buf, sizeof(buf)-1);
    if(n <= 0) return;
    buf[n] = 0;
    printf(buf);   // 취약: 포맷 스트링(사용자 입력을 포맷으로 사용)
    puts("");
}

int main(void){
    setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
    puts("======================================");
    puts("  발전소 로그 수집 데몬 v1.7");
    puts("======================================");
    int c;
    for(;;){
        printf("\n1) 로그 기록\n2) 로그 처리\n3) 종료\n선택> ");
        if(scanf("%d%*c",&c)!=1) return 0;
        if(c==1) log_event();
        else if(c==2) g_log();      // 하이재킹된 처리기 호출
        else if(c==3){ puts("종료"); return 0; }
        else puts("알 수 없는 메뉴");
    }
}
