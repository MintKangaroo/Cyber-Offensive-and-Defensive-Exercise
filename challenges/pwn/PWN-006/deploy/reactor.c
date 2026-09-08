// 원자로 냉각계통 제어 콘솔 (TRAINING ONLY) — tcache poisoning → 전역 함수포인터 하이재킹.
// 냉각채널 버퍼를 free 해도 슬롯 포인터를 비우지 않아 free-후-수정(UAF write)이 가능하다.
// 서로 다른 두 채널을 free 하면 tcache bin 에 2개가 쌓이는데(count=2), UAF write 로 bin
// head 청크의 next(safe-linked)를 전역 g_ctl 로 위조하면, 이어지는 두 번의 malloc 중 두 번째가
// g_ctl 자리에 청크를 돌려준다. 그 자리에 진단 함수포인터(g_ctl.diag)를 admin_shell 로 덮고
// 진단을 실행하면 /flag 가 노출된다. no-PIE 라 g_ctl·admin_shell 주소는 고정.
// 힌트용 leak: 채널 할당 시 힙 핸들(%p)을 출력한다(safe-linking 역산에 필요).
// 컴파일: gcc -static -no-pie -fno-stack-protector.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SLOTS 10
#define CHUNK 0x30

static char *chan[SLOTS];

static void diag_normal(void){ puts("[진단] 냉각계통 상태: 정상(무결)"); }

// 16바이트 정렬 전역: 첫 필드가 진단 함수포인터. tcache poisoning 의 목표 주소.
struct ctl { void (*diag)(void); unsigned long pad; } __attribute__((aligned(16)));
struct ctl g_ctl = { diag_normal, 0 };

// 숨은 win — 정상 흐름에선 호출되지 않는다. g_ctl.diag 를 여기로 덮으면 /flag 노출.
void admin_shell(void){
    char flag[128];
    FILE *f = fopen("/flag","r");
    if(!f){ puts("[!] flag 열기 실패"); _exit(1); }
    if(fgets(flag,sizeof(flag),f)) printf("[냉각계통 관리자 셸] 마스터 토큰: %s\n", flag);
    fclose(f); fflush(stdout); _exit(0);
}

static int idx(void){
    int i;
    printf("냉각채널(0-%d)> ", SLOTS-1);
    if(scanf("%d%*c",&i)!=1) exit(0);
    if(i<0 || i>=SLOTS){ puts("[거부] 잘못된 채널"); return -1; }
    return i;
}

static void create(void){
    int i = idx();
    if(i<0) return;
    chan[i] = (char*)malloc(CHUNK);
    printf("[냉각채널 %d 할당] 핸들 %p\n", i, (void*)chan[i]);  // leak
    printf("보정 데이터(%d바이트)> ", CHUNK);
    read(0, chan[i], CHUNK);
    puts("[냉각채널] 등록 완료");
}

static void edit(void){
    int i = idx();
    if(i<0) return;
    printf("보정 데이터(%d바이트)> ", CHUNK);
    read(0, chan[i], CHUNK);   // 취약: free 후에도 기록 가능(UAF write)
    puts("[냉각채널] 갱신");
}

static void release(void){
    int i = idx();
    if(i<0) return;
    free(chan[i]);             // 취약: 슬롯을 비우지 않음 → dangling
    puts("[냉각채널] 해제");
}

static void run_diag(void){
    g_ctl.diag();              // 전역 함수포인터 호출(하이재킹 대상)
}

int main(void){
    setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
    puts("======================================");
    puts("  원자로 냉각계통 제어 콘솔 v3.0");
    puts("======================================");
    int c;
    for(;;){
        printf("\n1) 냉각채널 등록\n2) 냉각채널 갱신\n3) 냉각채널 해제\n4) 진단 실행\n5) 종료\n선택> ");
        if(scanf("%d%*c",&c)!=1) return 0;
        if(c==1) create();
        else if(c==2) edit();
        else if(c==3) release();
        else if(c==4) run_diag();
        else if(c==5){ puts("종료"); return 0; }
        else puts("알 수 없는 메뉴");
    }
}
