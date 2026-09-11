# CRY-006 방어 — 해시 길이확장 서명 위조

## 취약점
MAC 을 `SHA256(SECRET ‖ message)` (secret-prefix 해시)로 구성했다. SHA-256 은
Merkle–Damgård 구조라 최종 해시값이 곧 내부 상태다. 공격자는 SECRET 을 몰라도:

1. 알려진 MAC 8워드를 SHA-256 내부 상태로 삼아 이어서 해시를 계속하고,
2. `SECRET ‖ message` 의 MD 패딩(glue padding)을 계산해 붙인 뒤,
3. 임의 확장(`&role=admin`)에 대한 유효 MAC 을 만들 수 있다.

SECRET 길이만 알거나 브루트포스(1..40)하면 서명 위조가 성립한다.

## 탐지 (Blue)
- MAC 구성이 `SHA256(secret‖msg)` 형태인지 코드/설정 점검 — 길이확장에 취약한 안티패턴.
- 서로 다른 요청에서 원본 메시지 뒤에 `0x80 … 길이필드 … 확장` 형태의 **비인쇄 glue 패딩**이
  섞인 메시지가 검증을 통과하는지 관측.

## 패치
`PATCH_CRY_006=true` — MAC 을 **HMAC-SHA256** 으로 교체한다.
HMAC 은 `H((K⊕opad) ‖ H((K⊕ipad) ‖ m))` 구조라 내부 상태를 알아도 바깥 해시를 재개할 수 없어
길이확장이 불가능하다. 패치 후 위조 MAC 은 전부 거부된다.

```python
# 취약
mac = hashlib.sha256(KEY + message).hexdigest()
# 안전
import hmac
mac = hmac.new(KEY, message, hashlib.sha256).hexdigest()
```

일반 원칙: **비밀키로 MAC 을 만들 때는 직접 해시 접합 대신 HMAC 을 쓴다.**
