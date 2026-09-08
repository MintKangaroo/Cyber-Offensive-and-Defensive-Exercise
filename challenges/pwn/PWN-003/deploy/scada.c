// 스마트그리드 SCADA 세션 관리 콘솔 (TRAINING ONLY) — 힙 버퍼 오버플로우(인접 청크 오염).
// 라벨 버퍼(heap chunk A)와 세션 구조체(heap chunk B, authed 필드)를 연달아 malloc 한다.
// 라벨 입력에 크기 검증이 없어 A 를 넘겨 인접한 B->authed 를 덮어써 관리자 인증을 우회한다.
// 컴파일: gcc -static -no-pie -fno-stack-protector. free 를 하지 않으므로 메타데이터 오염이
// 크래시로 이어지지 않는다(관리자 패널은 authed 만 읽음).
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct sess { long authed; char role[56]; };

char *label;        // heap chunk A (malloc 64)
struct sess *S;     // heap chunk B (malloc, A 직후 할당 → 인접)

void setup(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0); }

void set_label(void){
    printf("SCADA 세션 라벨을 입력하세요: ");
    // 취약점: 64바이트 힙 버퍼에 최대 256바이트 read → 인접 청크(B) 오염
    ssize_t n = read(0, label, 256);
    if(n>0 && label[n-1]=='\n') label[n-1]=0;
    printf("라벨 설정: %.64s\n", label);
}

void admin_panel(void){
    if(S->authed){
        char flag[128];
        FILE *f = fopen("/flag","r");
        if(!f){ puts("[!] flag 열기 실패"); return; }
        if(fgets(flag,sizeof(flag),f)) printf("[관리자 인증됨] 그리드 마스터 토큰: %s\n", flag);
        fclose(f);
    } else {
        puts("[거부] 관리자 세션 아님");
    }
}

int main(void){
    setup();
    label = malloc(64);
    S = malloc(sizeof(struct sess));
    memset(label, 0, 64);
    S->authed = 0; memset(S->role, 0, sizeof(S->role));
    puts("==========================================");
    puts("  스마트그리드 SCADA 세션 관리 콘솔 v4.1");
    puts("==========================================");
    int c;
    for(;;){
        printf("\n1) 세션 라벨 설정\n2) 관리자 패널\n3) 종료\n선택> ");
        if(scanf("%d%*c",&c)!=1) return 0;
        if(c==1) set_label();
        else if(c==2) admin_panel();
        else if(c==3){ puts("종료"); return 0; }
        else puts("알 수 없는 메뉴");
    }
}
