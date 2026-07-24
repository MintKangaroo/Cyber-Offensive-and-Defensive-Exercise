# WEB-000 방어 해법

`PATCH_WEB_000=true` 설정 시 `/api/debug/config`가 404를 반환한다(라우트 자체 비활성화).
탐지는 이 엔드포인트 접근 로그를 SIEM의 `TWIN-DEBUG-001` 규칙(06번 문서)으로 잡는다.
