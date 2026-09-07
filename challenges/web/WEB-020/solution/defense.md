# WEB-020 방어 — 프로토타입 오염 차단

## 취약점
설정 병합이 사용자 JSON 을 재귀 병합하면서 `__proto__`/`constructor`/`prototype` 키를 거르지
않는다. `{"__proto__":{"isAdmin":true}}` 를 병합하면 Object.prototype 이 오염돼, 이후 생성되는
빈 객체 `{}` 도 `isAdmin===true` 가 된다(권한 우회).

## 패치 (`PATCH_WEB_020=true`)
- 병합 시 위험 키(`__proto__`,`constructor`,`prototype`) 건너뛰기.
- `Object.create(null)` 사용, `Map` 으로 사용자 데이터 보관, 스키마 검증(허용 키 화이트리스트).
- 라이브러리는 안전한 merge(lodash `_.merge` 대신 방어형) 사용.

## 탐지 관점(blue)
- 요청 바디에 `__proto__`/`constructor`/`prototype` 키가 포함된 병합/설정 요청 경보.
