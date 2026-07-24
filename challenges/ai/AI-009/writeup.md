# AI-009 — 적대적 회피 인시던트 재구성 풀이

## 개요
`evasion_incident.json`에는 로지스틱 회귀 탐지기의 모델 카드(weights/bias/threshold),
알려진 악성 시드 벡터, 그리고 공격자가 던진 쿼리 로그(features + score)가 들어 있다.

## 1단계 — 모델 재평가로 회피 쿼리 후보 추림
각 쿼리의 특징으로 `sigmoid(w·x + b)`를 다시 계산해 `score < threshold`(양성 회피)인
쿼리만 남긴다.

## 2단계 — 최소 L0 섭동 = 회피 쿼리
회피 후보 중 악성 시드와 **다른 특징 인덱스 수(L0 거리)**가 최소인 쿼리가 전이 회피의
결과다(공격자는 최소 섭동을 노린다). 잡음 쿼리는 시드와 6개 특징 전부 다르지만, 회피
쿼리는 3개만 다르다. 그 다른 인덱스 집합 S 를 구한다.

## 3단계 — sig 반복 XOR 복호
회피 쿼리의 `sig`(hex)를, `S`를 정렬해 콤마로 이은 문자열(예 `"0,2,4"`)을 키로 반복
XOR 하면 플래그가 복원된다.

```python
key = ",".join(str(i) for i in sorted(S))
flag = bytes(v ^ key.encode()[i % len(key)] for i, v in enumerate(bytes.fromhex(sig)))
```

## 자동 해법
```bash
python3 solution/exploit.py deploy/evasion_incident.json
# {'evasion_query_id': 'q...', 'perturbed_features': [...], 'flag': 'flag{transfer_evasion_...}'}
```

## 방어 관점(blue)
전이 회피는 최소 섭동을 노리므로, 알려진 악성 시드 근방(저 L0 거리)에서 판정이 뒤집히는
쿼리를 모니터링하면 탐지할 수 있다. 입력 정규화·인접성 기반 이상탐지·앙상블 다양화가 완화책.
