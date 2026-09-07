# PWN-002 방어 — 전역 버퍼 오버플로우 차단

## 취약점
전역 구조체 `struct { char name[64]; long authed; }` 의 name 에 크기 검증 없이 최대 200바이트를
읽어(`read(0, st.name, 200)`) 바로 뒤 authed 필드를 덮어쓴다. authed 를 0이 아닌 값으로 만들면
관리자 인증을 우회한다.

## 패치
- 버퍼 크기만큼만 읽기: `read(0, st.name, sizeof(st.name)-1)`.
- 인증 상태를 오염 가능한 인접 메모리에 두지 않기(별도 저장/불변식 검증).
- 컴파일 보호(`-fstack-protector`, `_FORTIFY_SOURCE`)와 경계 검사 표준화.

## 탐지 관점(blue)
- 운영자 이름 등록 입력이 버퍼 크기(64)를 크게 초과하는 요청, 이후 인증 우회 흔적 경보.
