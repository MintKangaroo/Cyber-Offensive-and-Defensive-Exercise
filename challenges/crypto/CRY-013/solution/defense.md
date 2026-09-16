# CRY-013 방어 — AES-GCM 논스 재사용(forbidden attack)

## 취약점
같은 키·같은 nonce 로 두 메시지를 GCM 인증하면 두 태그의 차이가 GHASH 부분키 `H = E_K(0^128)` 에
대한 GF(2^128) 다항식이 된다.

```
tag_i = GHASH_H(aad, ct_i, len) XOR E_K(J0)
tag1 XOR tag2 = GHASH_H(aad, ct1, len) XOR GHASH_H(aad, ct2, len)   # E_K(J0) 소거
             = f(H) 형태의 다항식 (근에 H 포함)
```

`H` 를 복구하면 `E_K(J0) = GHASH_H(aad, ct1, len) XOR tag1` 도 얻고, 알려진 평문으로 keystream 을
복구해 **임의 메시지의 유효한 태그를 위조**할 수 있다(J.Joux, "forbidden attack"). GCM 은 nonce 재사용
시 기밀성뿐 아니라 무결성(인증)까지 완전히 무너진다.

## 탐지 (Blue)
- 동일 (키, nonce) 쌍으로 두 번 이상 암호화하는지 감사 — GCM 에서 nonce 재사용은 치명적.
- nonce 생성이 고정 상수/저엔트로피/카운터 리셋에 의존하는지 점검.

## 패치
`PATCH_CRY_013=true` — 메시지마다 서로 다른 nonce 를 사용해 `E_K(J0)` 와 `H` 소거를 불가능하게 한다.

```python
# 취약: 두 메시지에 같은 nonce
nonce = FIXED_NONCE
# 안전: 메시지마다 유일한 nonce(무작위 96비트 또는 결코 반복 않는 카운터)
nonce = os.urandom(12)
```

- **96비트 무작위 nonce**: 키당 메시지 수가 많으면 생일한계 위험 → 키 롤오버 병행.
- **결정적 nonce(카운터)**: 절대 리셋/중복되지 않도록 영속 카운터로 관리.
- 더 강한 대안: nonce 오용에 견고한 **AES-GCM-SIV**(RFC 8452) 채택.
