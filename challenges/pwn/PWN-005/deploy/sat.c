// 위성 TLE 관제 콘솔 (TRAINING ONLY) — Use-After-Free → 함수 포인터 하이재킹.
// 위성 객체(sat)는 첫 필드로 함수 포인터(action)를 갖는다. 등록해제(delete)가 free() 후
// 슬롯을 비우지 않아 dangling 포인터가 남는다(UAF). 같은 크기의 note 를 malloc 하면 tcache 가
// 방금 free 된 sat 청크를 그대로 돌려주므로, note 앞 8바이트로 action 포인터를 덮을 수 있다.
// 덮은 뒤 해당 위성을 run 하면 하이재킹된 함수(admin_override)가 호출되어 /flag 를 출력한다.
// 컴파일: gcc -static -no-pie -fno-stack-protector.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SLOTS 8

typedef void (*action_fn)(void);

typedef struct sat {
    action_fn action;   // 첫 필드: 함수 포인터
    char label[24];     // sizeof(struct sat) = 32 → tcache bin 0x30
} sat;

static sat *slots[SLOTS];

static void status_ok(void){ puts("[TLE] 위성 상태: NOMINAL (정상 추적 중)"); }

// 숨은 win 함수 — 정상 흐름에선 호출되지 않는다. UAF 로 action 을 여기로 덮으면 /flag 노출.
void admin_override(void){
    char flag[128];
    FILE *f = fopen("/flag","r");
    if(!f){ puts("[!] flag 열기 실패"); _exit(1); }
    if(fgets(flag,sizeof(flag),f)) printf("[관제 오버라이드 승인] 마스터 토큰: %s\n", flag);
    fclose(f); fflush(stdout); _exit(0);
}

static int read_index(void){
    int i;
    printf("슬롯(0-%d)> ", SLOTS-1);
    if(scanf("%d%*c",&i)!=1) exit(0);
    if(i<0 || i>=SLOTS){ puts("[거부] 잘못된 슬롯"); return -1; }
    return i;
}

static void create_sat(void){
    int i = read_index();
    if(i<0) return;
    slots[i] = (sat*)malloc(sizeof(sat));
    slots[i]->action = status_ok;
    printf("위성 라벨(최대 23)> ");
    read(0, slots[i]->label, 23);
    slots[i]->label[23] = 0;
    puts("[TLE] 위성 등록 완료");
}

static void delete_sat(void){
    int i = read_index();
    if(i<0) return;
    free(slots[i]);            // 취약: 슬롯을 비우지 않음 → dangling(UAF)
    puts("[TLE] 위성 등록해제");
}

static void add_note(void){
    // 관제 메모: sizeof(sat) 와 같은 32바이트 malloc → 방금 free 된 위성 청크를 재사용(tcache).
    char *n = (char*)malloc(sizeof(sat));
    printf("메모(32바이트)> ");
    read(0, n, sizeof(sat));   // 32바이트 전부 제어 → 재사용된 sat->action 을 덮음
    puts("[TLE] 메모 저장");
}

static void run_sat(void){
    int i = read_index();
    if(i<0) return;
    if(!slots[i]){ puts("[거부] 빈 슬롯"); return; }
    slots[i]->action();        // UAF: dangling 포인터의 함수 포인터 호출
}

int main(void){
    setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0);
    puts("======================================");
    puts("  위성 TLE 관제 콘솔 v2.1");
    puts("======================================");
    int c;
    for(;;){
        printf("\n1) 위성 등록\n2) 위성 등록해제\n3) 관제 메모\n4) 위성 실행(상태보고)\n5) 종료\n선택> ");
        if(scanf("%d%*c",&c)!=1) return 0;
        if(c==1) create_sat();
        else if(c==2) delete_sat();
        else if(c==3) add_note();
        else if(c==4) run_sat();
        else if(c==5){ puts("종료"); return 0; }
        else puts("알 수 없는 메뉴");
    }
}
