# CRY-016 방어 — RSA 저지수(e=3) stereotyped 메시지(Coppersmith)

## 취약점
명령 `m = int(prefix) << k | token` 을 `e=3` 으로 암호화하고 접두부 `prefix` 와 미지 비트수 `k` 를
공개한다. 미지 부분 `token` 이 작으면(`|x0| < N^(1/e)`) 다항식

```
f(x) = (a + x)^3 - c  (mod N),   a = int(prefix) << k
```

의 작은 근 `x0 = token` 을 Coppersmith 의 작은 근 정리(Howgrave-Graham 격자 + LLL)로 **개인키 없이**
복구할 수 있다. 512비트 `N`, `e=3` 이면 `N^(1/3) ≈ 170비트` 까지의 미지 부분이 노출된다.

## 탐지 (Blue)
- RSA 공개지수가 작은지(`e=3`) 확인 — 저지수는 여러 공격(Håstad·stereotyped·partial known)에 취약.
- 메시지의 상당 부분이 예측 가능(고정 접두부/포맷)한지 감사 — 미지 부분이 `N^(1/e)` 보다 작으면 위험.

## 패치
`PATCH_CRY_016=true` — 공개지수를 `e=65537` 로 올리고, 무작위 패딩(OAEP)을 적용한다.

```python
# 취약: 저지수 + 예측 가능한 메시지 구조
e = 3
c = pow(int(prefix)<<k | token, 3, N)
# 안전: 큰 공개지수 + OAEP 무작위 패딩
e = 65537
c = rsa_oaep_encrypt(N, e, message)   # 매 암호화마다 무작위성 주입
```

- **큰 공개지수(e=65537)**: 미지 부분이 `N^(1/e)` 를 크게 초과해 Coppersmith 불가.
- **RSA-OAEP**: 메시지에 무작위 패딩을 넣어 stereotyped/저지수 공격을 원천 차단.
- 고정 접두부·짧은 미지값 같은 예측 가능한 평문 구조를 피한다.
