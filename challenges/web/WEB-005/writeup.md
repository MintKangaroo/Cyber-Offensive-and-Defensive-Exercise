# WEB-005 Writeup (훈련 후 공개)

**근본원인**: 히스토리안 리포트 "가져오기"가 신뢰할 수 없는 사용자 입력을 `pickle.loads`로
역직렬화했다. pickle은 역직렬화 과정에서 객체의 `__reduce__`가 지정한 **임의 호출**을
실행하므로, 이는 곧 원격 코드 실행(RCE)이다.

**공격**:
1. import가 받는 `data`가 base64로 감싼 pickle임을 파악.
2. `__reduce__`가 `subprocess.check_output(["cat", "/tmp/flag.txt"])`를 반환하는 객체를 만든다.
3. `pickle.dumps` → base64 → `POST /api/historian/import`. 서버가 역직렬화하며 명령을 실행하고,
   그 반환값(플래그 바이트)이 응답에 반영된다.

**방어**: `pickle`을 버리고 `json.loads` 같은 데이터 전용 포맷으로 전환한다. 구조화 입력에는
스키마 검증을 붙인다. 부득이 이진 직렬화가 필요하면 서명/HMAC로 무결성을 검증한 신뢰 채널에서만.

**교훈**: "pickle.loads(신뢰불가입력) == 원격 코드 실행." 역직렬화는 데이터 파싱이 아니라
객체 재구성이며, 재구성 훅이 곧 실행 경로다.
