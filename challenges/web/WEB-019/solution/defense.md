# WEB-019 방어 — GraphQL introspection + IDOR 차단

## 취약점
- introspection 이 켜져 있어 스키마(숨은 쿼리/필드)가 그대로 노출된다.
- `citizen(id)` 에 인가 검사가 없어(IDOR) 공개 목록에 없는 제한 계정(id 0)의 note(flag)를 읽는다.

## 패치 (`PATCH_WEB_019=true`)
- 운영 환경에서 **introspection 비활성화**(NoSchemaIntrospectionCustomRule).
- 객체 단위 **인가(authorization)**: 제한 계정/필드는 권한 없는 요청에 반환하지 않기.
- 쿼리 깊이/복잡도 제한, 필드 레벨 접근제어.

## 탐지 관점(blue)
- `__schema`/`__type` introspection 쿼리, 공개 범위 밖 id 를 지정한 단건 조회 경보.
