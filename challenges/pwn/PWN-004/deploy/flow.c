// 상수도 유량 계측 콘솔 (TRAINING ONLY) — 정수 오버플로우 → 스택 버퍼 오버플로우 → ret2win.
// 샘플 길이 count 를 int(부호있음)로 받고 'count > 64' 만 검사한다. 음수 count 는 검사를
// 통과하지만, 하드웨어 16비트 길이 레지스터로 넘길 때 (unsigned short) 로 절단되면서 거대한
// 양수(예: -1 → 65535)가 되어 read() 로 버퍼를 넘겨 저장된 복귀주소를 덮는다. 숨은
// emergency_dump()로 복귀시키면 /flag 를 출력한다.
// 컴파일: gcc -static -no-pie -fno-stack-protector.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void setup(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0); }

void emergency_dump(void){
    char flag[128];
    FILE *f = fopen("/flag","r");
    if(!f){ puts("[!] flag 열기 실패"); _exit(1); }
    if(fgets(flag,sizeof(flag),f)) printf("[비상 유량 오버라이드] 토큰: %s\n", flag);
    fclose(f); fflush(stdout); _exit(0);
}

void upload_sample(void){
    char buf[64];
    int count;
    printf("샘플 바이트 수(최대 64)> ");
    if(scanf("%d%*c", &count) != 1) return;
    if(count > 64){ puts("[거부] 너무 큼"); return; }
    // 취약점: count 가 음수면 검사를 통과하지만, 16비트 길이 레지스터로 절단(unsigned short)
    // 되면서 거대한 양수(-1 → 65535)가 되어 read() 로 64바이트 버퍼를 넘겨 덮어쓴다.
    printf("샘플 데이터 입력> ");
    read(0, buf, (size_t)(unsigned short)count);
    puts("샘플 수신 완료");
}

int main(void){
    setup();
    puts("======================================");
    puts("  상수도 유량 계측 콘솔 v1.4");
    puts("======================================");
    int c;
    for(;;){
        printf("\n1) 샘플 업로드\n2) 종료\n선택> ");
        if(scanf("%d%*c",&c)!=1) return 0;
        if(c==1) upload_sample();
        else if(c==2){ puts("종료"); return 0; }
        else puts("알 수 없는 메뉴");
    }
}
