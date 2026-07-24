# AI-007 — 예산 제약 적대적 회피(PGD Evasion) 라이트업

## 개요
- 분야: AI / 난이도: hard / MITRE: T1027
- 배포: FastAPI 악성코드 탐지기(numpy 2층 MLP). `/model`(화이트박스 가중치), `/source`(소스
  x0·예산 eps), `/classify`(예산·박스 검사 후 판정, 회피 성공 시 팀별 플래그 발급).

## 의도된 해법
1. `/model`에서 W1,b1,W2,b2를, `/source`에서 x0·epsilon을 받아 MLP를 numpy로 재구성.
2. malware 로짓 − benign 로짓의 입력 그래디언트를 ReLU 마스크를 반영해 계산.
3. `x ← x − lr·sign(grad)` 스텝마다 **x0±epsilon 볼**과 **[0,1] 박스**로 사영(PGD).
4. benign으로 넘어가면 `/classify`에 제출 → 서버가 `flag{pgd_evasion_<hmac12>}` 발급.

## 왜 AI-000보다 어려운가
- 모델이 **비선형(MLP)** → 선형 계수만 보고 특징을 미는 방식이 그대로 통하지 않는다.
- 서버가 **L∞ 예산 + 박스 제약**을 강제 → 특징을 정상값으로 몰아넣는 회피는 '예산 초과'로 거부.
- 따라서 예산 안의 최소 섭동을 찾는 **그래디언트 기반 반복 공격(PGD)** 이 필요.

## 검증
- C-QA `run_all.py --challenge AI-007`(full docker): deploy_up → intended_solve(PGD로 실제 회피 →
  플래그) → blank_submit(빈 제출 거부) → flag_determinism(재배포 일관성) → teardown.
- 팀별 플래그 유니크성: HMAC(secret, "AI-007:team") → 팀마다 상이, 같은 팀은 재배포에도 동일.
