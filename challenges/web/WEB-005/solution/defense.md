# WEB-005 방어 해법

## 패치 방법

1. `PATCH_WEB_005=true` 환경변수 설정(또는 Config Service의 `/instructor/patch/toggle` 호출).
2. 패치판은 `pickle.loads`를 폐기하고 **안전한 JSON 역직렬화(`json.loads`)만** 허용한다.
   pickle 매직바이트로 시작하는 바이너리 페이로드는 UTF-8/JSON 파싱에 실패해 `400`으로 거부된다.
3. 근본 원칙: **신뢰할 수 없는 입력을 절대 pickle/marshal/PyYAML unsafe_load 등으로 역직렬화하지 말 것.**
   구조화 데이터는 JSON 같은 데이터 전용 포맷으로 교환하고, 스키마 검증(pydantic 등)을 붙인다.

## 탐지 방법

`WEB-PICKLE-RCE` Sigma 규칙 — import 엔드포인트로 들어온 base64 디코딩 결과가
pickle 매직바이트(`\x80` opcode)로 시작하면 역직렬화 공격으로 판정:
```yaml
id: WEB-PICKLE-RCE
match:
  endpoint: "/api/historian/import"
  decoded_body_prefix_hex: "80"   # pickle PROTO opcode
action_on_match: alert
```

## 채점 기준(blue_grader.py가 검증)

- 패치 후 pickle 페이로드가 코드 실행 없이(비200) 거부되는지
- (SIEM 연동 시) pickle 페이로드에 대해 알림이 발생하는지

## 안전(hardened) 배포

실제 RCE가 나므로 `deploy/docker-compose.yaml`에 `cap_drop: [ALL]`, `read_only: true`,
`mem_limit`, `no-new-privileges`, `internal` 네트워크(egress 차단)를 적용했다.
