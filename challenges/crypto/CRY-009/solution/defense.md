# CRY-009 방어 — MT19937 상태복구 예측

## 취약점
일회용 토큰을 파이썬 기본 PRNG(MT19937, `random`)로 생성한다. MT19937 은 암호학적으로 안전하지
않다. 연속된 624개의 32비트 출력을 관측하면 tempering 을 역산(untemper)해 내부 상태 624워드를
완전히 복구할 수 있고, 상태를 복제하면 그 이후 모든 출력을 정확히 예측할 수 있다.

## 탐지 (Blue)
- 토큰/OTP/세션ID 가 `random`(MT19937) 기반인지 점검 — CSPRNG(`secrets`, `os.urandom`)가 아니면 취약.
- 연속된 난수 출력이 그대로(또는 얇은 인코딩만 거쳐) 외부로 노출되는 경로 관측.

## 패치
`PATCH_CRY_009=true` — 관리자 OTP 를 CSPRNG 로 발급한다.

```python
# 취약: 예측 가능한 MT19937
import random; otp = random.getrandbits(32)
# 안전: 암호학적 난수
import secrets; otp = secrets.randbits(32)   # 또는 os.urandom
```

CSPRNG 는 출력으로부터 내부 상태를 복구할 수 없어 624개(그 이상)를 관측해도 다음 값을
예측할 수 없다. 일반 원칙: **보안 토큰·OTP·키·논스는 반드시 CSPRNG 로 생성**한다.
