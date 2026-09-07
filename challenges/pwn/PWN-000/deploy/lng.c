// LNG 경보센터 제어 콘솔 (TRAINING ONLY) — 스택 버퍼 오버플로우 → ret2win.
// 경보 메시지 입력 버퍼가 크기 검증 없이 read() 로 과다 입력을 받아 저장된 복귀주소를
// 덮어쓸 수 있다. 숨겨진 emergency_override() 로 복귀주소를 돌리면 /flag 를 출력한다.
// 컴파일: gcc -static -no-pie -fno-stack-protector -z noexecstack (주소 결정론적).
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void setup(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0); setvbuf(stderr,0,2,0); }

void banner(void){
    puts("==============================================");
    puts("  국가 LNG 인수기지 경보센터 제어 콘솔 v1.2");
    puts("==============================================");
}

// ret2win 타깃: 비상 오버라이드 — /flag 출력. 정상 메뉴에서는 절대 호출되지 않는다.
void emergency_override(void){
    char flag[128];
    FILE *f = fopen("/flag", "r");
    if(!f){ puts("[!] flag 파일을 열 수 없습니다"); fflush(stdout); _exit(1); }
    if(!fgets(flag, sizeof(flag), f)){ puts("[!] flag 읽기 실패"); _exit(1); }
    fclose(f);
    printf("[EMERGENCY OVERRIDE ENGAGED]\n안전 인터록 해제 토큰: %s\n", flag);
    fflush(stdout);
    _exit(0);
}

void set_alarm(void){
    char buf[64];
    printf("경보 메시지를 입력하세요(최대 63자): ");
    // 취약점: 버퍼 크기(64)를 무시하고 256바이트까지 읽는다 → 저장된 복귀주소 덮어쓰기.
    read(0, buf, 256);
    printf("경보 메시지가 설정되었습니다: %s\n", buf);
}

void show_status(void){
    puts("[상태] 탱크 압력 정상 · 온도 -162C · 경보 대기");
}

int main(void){
    setup();
    banner();
    int choice;
    for(;;){
        printf("\n1) 경보 메시지 설정\n2) 기지 상태 조회\n3) 종료\n선택> ");
        if(scanf("%d%*c", &choice) != 1) return 0;
        if(choice==1) set_alarm();
        else if(choice==2) show_status();
        else if(choice==3){ puts("콘솔을 종료합니다."); return 0; }
        else puts("알 수 없는 메뉴");
    }
}
