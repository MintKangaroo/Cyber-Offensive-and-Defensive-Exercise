// 정수처리장 로그 콘솔 (TRAINING ONLY) — 포맷 스트링 취약점.
// 로그 메시지를 printf(user_input) 로 그대로 출력 → 포맷 지정자(%p,%s,%N$s)로 스택을
// 읽을 수 있다. 비상 대응 토큰(flag)의 포인터가 스택 지역변수로 올라와 있어 %N$s 로 유출된다.
// 컴파일: gcc -static -no-pie -fno-stack-protector.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void setup(void){ setvbuf(stdout,0,2,0); setvbuf(stdin,0,2,0); }

char *load_flag(void){
    FILE *f = fopen("/flag","r");
    if(!f){ return NULL; }
    char *b = malloc(128);
    if(!b){ return NULL; }
    memset(b,0,128);
    if(!fgets(b,127,f)){ free(b); fclose(f); return NULL; }
    fclose(f);
    return b;
}

void log_console(void){
    char *flag = load_flag();          // 비상 대응 토큰 포인터(스택 지역변수)
    char buf[256];
    memset(buf,0,sizeof(buf));
    printf("정수처리장 로그 메시지를 입력하세요: ");
    ssize_t n = read(0, buf, sizeof(buf)-1);
    if(n>0 && buf[n-1]=='\n') buf[n-1]=0;
    printf("기록된 로그: ");
    printf(buf);                        // 취약점: 포맷 스트링
    printf("\n");
    if(flag) free(flag);
}

int main(void){
    setup();
    puts("==============================================");
    puts("  국가 정수처리장(K-water) 운영 로그 콘솔 v2.1");
    puts("==============================================");
    log_console();
    puts("로그 세션을 종료합니다.");
    return 0;
}
