# REV-009 — 커스텀 VM 난독화 (핸들러 테이블) 풀이

## 개요
`vm_image.json`은 스택 기반 커스텀 VM 이미지다. REV-004(4-op 스택 VM)와 달리 세 겹의 난독화가 있다.

## 1단계 — 핸들러 테이블(dispatch) 복원
`program`의 각 명령은 `[raw_op, arg]` 꼴이다. raw_op을 그대로 쓰면 안 되고 `dispatch` 배열로
canonical 연산을 얻어야 한다: `canonical = dispatch[raw_op]`. 이것이 "핸들러 점프 테이블"이다.

canonical opcode(0..7)의 의미:
| id | 연산 | 동작 |
|----|------|------|
| 0 | PUSHI n | 스택에 n push |
| 1 | DUP | top 복제 |
| 2 | ADD | b=pop,a=pop → push(a+b) |
| 3 | SUB | b=pop,a=pop → push(a-b) |
| 4 | XORK | a=pop → push(a ^ 키스트림바이트) |
| 5 | ROL n | a=pop → push(rol8(a&0xFF, n)) |
| 6 | MOD256 | a=pop → push(a & 0xFF) |
| 7 | EMIT | pop() & 0xFF 를 출력 바이트로 |

## 2단계 — LCG 키스트림 재현
XORK는 이미지의 `lcg`(a, c, seed)로 구동되는 LCG 키스트림을 소비한다. 초기 state=seed,
호출마다 `state = (a*state + c) & 0xFF` 로 전진하며 그 값을 XOR에 사용한다. 호출 순서를 정확히
맞춰야 한다(문자당 XORK 1회).

## 3단계 — VM 실행
스택 VM을 구현해 `program`을 순서대로 실행하면 EMIT 바이트열이 플래그가 된다.

방출 시퀀스(문자당): `PUSHI a, PUSHI b, ADD, XORK, ROL r, MOD256, EMIT` →
`rol8(((a+b) ^ k) & 0xFF, r) & 0xFF == 문자코드`.

## 자동 해법
`solution/exploit.py`의 `solve(artifact_path)`가 위 3단계를 그대로 구현한다.

```bash
python3 solution/exploit.py deploy/vm_image.json
# flag{vmhandler_...}
```

## 방어 관점(blue)
VM 난독화는 클라이언트 측 검증 로직을 감추는 용도로 남용되지만, 결국 이미지에 dispatch/키스트림이
포함돼 결정론적으로 복원된다. 진짜 비밀 검증은 서버 측(또는 TPM/HSM)에서 수행하고, 클라이언트엔
검증 결과만 전달해야 한다.
