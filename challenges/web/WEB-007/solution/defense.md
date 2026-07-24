# WEB-007 방어 해법

## 패치 방법

1. `PATCH_WEB_007=true` 환경변수 설정(또는 Config Service의 `/instructor/patch/toggle` 호출).
2. 패치판은 클라이언트가 보낸 `content_type`을 **신뢰하지 않고**, 파일의 **실제 확장자를
   화이트리스트(`png/jpg/jpeg/gif`)**로 검증한다. 스크립트 확장자(`.py` 등)는 `400`으로 거부.
3. 추가 권장(심화 방어):
   - 확장자뿐 아니라 매직바이트(파일 시그니처)로 실제 타입 확인.
   - 업로드 파일은 실행 불가 경로에 저장하고, 랜덤 파일명으로 리네임.
   - 업로드 디렉토리에서 스크립트 실행 비활성화(웹서버 설정).

## 탐지 방법

`WEB-UPLOAD-BYPASS` Sigma 규칙 — 업로드된 filename의 실제 확장자가 이미지 화이트리스트에
없는데 요청이 이미지 content_type을 주장하면 우회 시도로 판정:
```yaml
id: WEB-UPLOAD-BYPASS
match:
  endpoint: "/api/upload"
  condition:
    claimed_content_type: "image/*"
    actual_extension_not_in: [png, jpg, jpeg, gif]
action_on_match: alert
```

## 채점 기준(blue_grader.py가 검증)

- 패치 후 `content_type=image/png`로 위조한 `shell.py` 업로드가 `400`으로 거부되는지
- (SIEM 연동 시) 우회 업로드 시도에 대해 알림이 발생하는지
