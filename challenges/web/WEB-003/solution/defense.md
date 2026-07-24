# WEB-003 방어 해법

## 패치 방법

1. `PATCH_WEB_003=true` 환경변수 설정(또는 Config Service의 `/instructor/patch/toggle` 호출).
2. 패치판은 계획 조회 시 **소유자 검증**을 수행한다: 요청자 팀(`X-Team-Id`)이
   해당 계획의 소유자가 아니면 `403`을 반환한다.
3. 근본 원칙: 객체 참조(plan_id)만으로 인가를 대신하지 말 것. 모든 리소스 접근은
   "이 주체가 이 객체에 접근할 권한이 있는가"를 서버에서 확인해야 한다(IDOR 방지).

## 탐지 방법

`WEB-IDOR-SCAN` Sigma 규칙 — 동일 팀이 짧은 시간에 다수의 서로 다른 `plan_id`를
순차적으로 조회하면 순차 스캔으로 판정:
```yaml
id: WEB-IDOR-SCAN
match:
  endpoint_prefix: "/api/mission/plan/"
  threshold:
    distinct_plan_ids: 20
    window_sec: 60
action_on_match: alert
```

## 채점 기준(blue_grader.py가 검증)

- 패치 후 남의 소유 기밀 계획(`plan_id=4137`) 접근이 `403`을 반환하는지
- (SIEM 연동 시) 순차 스캔 시도에 대해 알림이 발생하는지
