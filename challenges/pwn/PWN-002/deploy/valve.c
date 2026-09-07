// 가스공사 밸브 제어 인증 콘솔 (TRAINING ONLY) — 전역(.bss) 버퍼 오버플로우 → 인증 우회.
// 전역 구조체의 name[64] 버퍼에 크기 검증 없이 입력받아, 바로 뒤 authed 필드를 덮어쓴다.
// authed 가 0이 아니면 관리자 패널이 비상 밸브 토큰(flag)을 출력한다.
// 컴파일: gcc -static -no-pie -fno-stack-protector (전역 레이아웃 결정론적).
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

struct state { char name[64]; long authed; };
struct state st;   // 전역(.bss) — name 바로 뒤에 authed(오프셋 64)

void setup(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0); }

void set_operator(void){
    printf("운영자 이름을 입력하세요: ");
    // 취약점: name[64] 에 최대 200바이트 입력 → 인접 authed 덮어쓰기
    ssize_t n = read(0, st.name, 200);
    if(n>0 && st.name[n-1]=='\n') st.name[n-1]=0;
    printf("등록된 운영자: %.64s\n", st.name);
}

void admin_panel(void){
    if(st.authed){
        char flag[128];
        FILE *f = fopen("/flag","r");
        if(!f){ puts("[!] flag 열기 실패"); return; }
        if(fgets(flag,sizeof(flag),f)) printf("[관리자 인증됨] 비상 밸브 토큰: %s\n", flag);
        fclose(f);
    } else {
        puts("[거부] 관리자 인증되지 않음");
    }
}

int main(void){
    setup();
    memset(&st,0,sizeof(st));
    puts("======================================");
    puts("  가스공사 밸브 제어 인증 콘솔 v3.0");
    puts("======================================");
    int c;
    for(;;){
        printf("\n1) 운영자 이름 등록\n2) 관리자 패널\n3) 종료\n선택> ");
        if(scanf("%d%*c",&c)!=1) return 0;
        if(c==1) set_operator();
        else if(c==2) admin_panel();
        else if(c==3){ puts("종료"); return 0; }
        else puts("알 수 없는 메뉴");
    }
}
