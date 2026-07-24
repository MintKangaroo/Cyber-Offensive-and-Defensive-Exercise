# FOR-007 — 프로세스 할로잉 인메모리 인젝션 라이트업

## 개요
- 분야: forensics / 난이도: hard / MITRE: T1055.012(Process Hollowing)
- 아티팩트: `process_snapshot.json` — 프로세스별 메모리 영역(base/size/protect/type) 스냅샷.

## 의도된 해법
1. **이상 영역 correlate**: 모든 프로세스의 영역을 훑어 `type=private` 이면서 `protect=RX`인
   영역(W^X 위반, 익명 실행 메모리 = 주입 코드)을 가진 프로세스를 찾는다. 정상은 실행권한이
   image 타입에만 붙는다.
2. **스테이저 추출**: 그 영역의 `data`(base64)를 디코드 → `XORKEY=<k>\nPAYLOAD=<hex>`.
3. **복호**: PAYLOAD(hex)를 XORKEY로 반복 XOR → `flag{process_hollowing_<hmac12>}`.

## 왜 hard인가
- 문자열 검색으로는 못 푼다 — 정상/주입 영역을 protect+type 조합으로 판별하는 correlation이 필요.
- 탐지 후에도 base64 은닉 + 반복키 XOR 2단 복호를 거쳐야 flag가 나온다.

## 검증
- C-QA `run_all.py --challenge FOR-007`(artifact_solve): 생성 → solve(탐지+복호) → grade_red PASS +
  빈 제출 거부. 팀별 HMAC으로 할로잉 대상/키/플래그가 유니크(같은 팀은 재생성에도 동일).
