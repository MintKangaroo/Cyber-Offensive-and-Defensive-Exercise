# ICS-001 방어 노트 (Blue) — 실 OPC UA/TCP

## 취약점
OPC UA 서버가 **익명(Anonymous) 세션**을 허용하고 노드 접근 권한이 없다. 인증 없이
`ActivateSession` 이 통과하고 `Browse` 로 전체 주소공간이 열거되며, 민감한 진단 노드까지
`Read` 로 노출된다.

## 권장 방어
1. **익명 세션 비활성화**: `UserTokenPolicy` 에서 Anonymous 제거 — 사용자/인증서 기반
   세션만 허용. 프로덕션 엔드포인트는 `SecurityPolicy ≠ None`(Sign/SignAndEncrypt).
2. **Role 기반 노드 권한**: 진단·유지보수 노드는 특정 Role(엔지니어)에만 Read 허용.
   RolePermissions/UserRolePermissions 속성으로 강제.
3. **주소공간 최소화**: 운영에 불필요한 진단 노드를 익명 브라우즈 대상에서 제외.
4. **네트워크 세그먼트/탐지**: OPC UA 엔드포인트를 OT 세그먼트로 제한하고, 익명 세션
   활성화·진단 노드 Read 를 SIEM 룰로 경보(raw.protocol=opcua).

핵심 키워드: **익명 / anonymous 세션**.
