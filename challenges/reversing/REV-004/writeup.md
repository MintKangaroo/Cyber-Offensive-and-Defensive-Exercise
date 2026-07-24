# REV-004 풀이 (Writeup)

## 개요
`program.json`은 스택 기반 VM의 바이트코드다. 명령:
- `["PUSH", n]` — n을 스택에 push
- `["ADD"]` — 상위 두 값을 더해 push
- `["XOR", k]` — top을 k와 XOR
- `["EMIT"]` — top을 pop해 바이트로 출력

## 풀이
인터프리터를 구현해 명령을 순서대로 실행한다. 각 플래그 문자는
`(a + b) XOR K == charcode` 형태로 인코딩되어 있어(리터럴 은닉), VM을 돌려야 실제 문자가 나온다.

```python
stack, out = [], bytearray()
for op, *args in program:
    if op == "PUSH": stack.append(args[0])
    elif op == "ADD": a=stack.pop(); b=stack.pop(); stack.append(b+a)
    elif op == "XOR": stack.append(stack.pop() ^ args[0])
    elif op == "EMIT": out.append(stack.pop() & 0xFF)
print(out.decode())   # flag{vm_...}
```

## 방어 관점
VM/바이트코드 난독화는 분석을 늦출 뿐이다. 명령 집합만 파악하면 인터프리터로 결정적으로
복원된다 — 기밀은 난독화가 아니라 암호로 보호해야 한다.
