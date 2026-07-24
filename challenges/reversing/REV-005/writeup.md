# REV-005 풀이 (Writeup)

## 개요
`cipher.bin` = `[4바이트 seed(LE)] + XOR(flag, LCG_keystream)`.
LCG 파라미터는 glibc 계열 상수: `a=1103515245, c=12345, m=2^31`, 출력 바이트는 `(state >> 16) & 0xFF`.

## 풀이
1. 앞 4바이트를 리틀엔디언 정수로 읽어 **seed** 복원.
2. seed로 LCG를 돌려 나머지 바이트 수만큼 **키스트림** 생성.
3. 나머지와 키스트림을 XOR → `flag{lcg_...}`.

```python
state = seed
ks = []
for _ in range(len(cipher)):
    state = (1103515245*state + 12345) % 2**31
    ks.append((state >> 16) & 0xFF)
flag = bytes(a ^ b for a, b in zip(cipher, ks)).decode()
```

## 방어 관점
LCG는 암호학적으로 안전하지 않다(seed/파라미터를 알면 키스트림이 결정적으로 재현됨).
스트림 암호에는 CSPRNG/표준 암호(AES-CTR, ChaCha20)를 써야 한다.
