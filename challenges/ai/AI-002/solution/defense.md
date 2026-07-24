# AI-002 방어 노트 (Blue)

## 무슨 일이 있었나
공격자가 "Ignore all previous instructions ... developer debug mode" 형태의 **지시 무시형
프롬프트 인젝션**으로 가드레일을 우회했고, 어시스턴트가 시스템 프롬프트의 내부 API 키를
그대로 노출했다.

## 방어 (OWASP LLM Top 10 - LLM01 Prompt Injection)
- **비밀을 시스템 프롬프트에 넣지 않기**: 키/자격증명은 프롬프트가 아니라 서버 측에서만 접근.
  프롬프트에 있으면 인젝션 한 번에 새어나간다(최소권한 원칙).
- **입력/명령 분리**: 사용자 입력을 신뢰 경계 밖 데이터로 취급, 시스템 지시와 구조적으로 분리.
- **출력 필터링**: 응답에 비밀 패턴(API 키/시스템 프롬프트)이 포함되면 차단.
- **도구 권한 최소화**: 모델이 접근할 수 있는 데이터/도구를 필요한 것만 노출.

## 탐지
- 대화 로그에서 'ignore previous instructions', 'developer/debug mode', 'print the system prompt'
  같은 인젝션 시그니처와, 응답 내 비밀 패턴 노출을 모니터링.
