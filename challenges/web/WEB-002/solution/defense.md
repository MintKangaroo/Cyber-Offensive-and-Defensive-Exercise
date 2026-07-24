# WEB-002 방어 해법

## 패치 방법

1. `PATCH_WEB_002=true` 환경변수 설정(또는 Config Service의 `/instructor/patch/toggle` 호출).
2. `GS_JWT_STRONG_SECRET`에 강한 랜덤 시크릿(32자 이상) 설정.
3. 이 상태에서는 `alg=none`이 `jwt.decode(..., algorithms=["HS256"])`로 검증되어 거부되고,
   약한 키 서명도 다른 시크릿과 비교되어 거부된다.

## 탐지 방법

12번 문서 5절의 `WEB-JWT-FORGE` Sigma 규칙을 사용:
```yaml
id: WEB-JWT-FORGE
match:
  endpoint: "/api/mission/approve"
  any:
    - raw.alg: "none"
    - metadata.forged_suspected: true
action_on_match: alert
```

## 채점 기준(blue_grader.py가 검증)

- 패치 후 `alg=none` 토큰 요청이 401을 반환하는지
- (SIEM 연동 시) 위조 시도에 대해 알림이 발생하는지
