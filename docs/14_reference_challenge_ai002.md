# 레퍼런스 문제 패키지 — AI-002 (피싱 탐지기 문제공간 회피)

> AI 보안 분야 레퍼런스. 사용자의 적대적 ML 랩 경험(Pierazzi 문제공간 프레임워크, 피싱 URL 탐지기,
> constrained/unconstrained evasion)을 훈련 문제로 정식화. Red=회피, Blue=견고화.

---

## 1. challenge.yaml

```yaml
challenge:
  id: "AI-002"
  title: "탐지를 속이는 링크 - Problem-Space Evasion"
  category: "ai"
  difficulty: "medium"
  points: { red: 200, blue: 200 }
  asset: null                      # 독립 챌린지(트윈 비연동)
  mitre: [T1027]                   # 방어우회 계열(개념적 매핑)

  description: |
    사내 피싱 URL 탐지기(블랙박스 API)가 있다. 주어진 악성 URL을
    '실제로 유효한 URL의 형태를 유지한 채(problem-space 제약)' 변형하여
    탐지기가 benign 으로 오분류하게 만들어라. feature-space 만의 조작은 인정되지 않는다.

  red_task:
    goal: "제공된 악성 URL을 problem-space 제약 하에서 변형해 detector가 benign(<0.5)으로 판정"
    submit_fields:
      - evasive_url                # 제출한 회피 URL
    constraints:                   # 문제공간 제약(검증됨)
      - "URL이 문법적으로 유효(스킴/호스트/경로 파싱 가능)"
      - "원 악성 목적지로 여전히 도달 가능(리다이렉트/동형이의 허용)"
      - "사람이 보기에 원 브랜드를 사칭(피싱 의도 유지)"
    flag_on_success: "flag{evaded_in_problem_space}"
    hints:
      - { cost: 25, text: "탐지기가 어떤 특징(길이, 서브도메인 수, 특수문자)에 민감한지 프로빙하라." }
      - { cost: 40, text: "feature 값을 바꾸되 URL 유효성을 깨지 않는 변형만 허용된다." }

  blue_task:
    goal: "회피에 견고한 탐지기로 개선 (재학습/특징강화/전처리)"
    success_criteria: |
      개선된 탐지기가 (a) 원 테스트셋 정확도 유지(>0.9) &
      (b) Red가 제출한 회피 샘플들을 다시 malicious로 탐지(>0.8 재탐지율)
    points_breakdown: { robustness: 120, accuracy_kept: 80 }

  scoring:
    red_verify: "detector_query + constraint_check"
    blue_verify: "holdout_eval"

  artifacts:
    - "detector_api/  (블랙박스 추론 서비스)"
    - "sample_urls.csv (악성/정상 시드)"
  safety:
    profile: "hardened"            # ML 서비스 격리
    notes: "합성 데이터셋. 실제 피싱 URL/실도메인 미포함. 모델은 훈련용 소형 분류기."
```

---

## 2. 취약 탐지기 (detector_api/ — 회피 가능한 베이스라인)

```python
"""
피싱 URL 탐지기(블랙박스). 회피에 취약한 얕은 특징 기반 모델.
훈련용 합성 데이터로 학습된 소형 분류기(로지스틱/랜덤포레스트 수준).
"""
from fastapi import FastAPI
from pydantic import BaseModel
import joblib, re

app = FastAPI(title="Phishing URL Detector (training)")
model = joblib.load("detector.pkl")   # 사전 학습된 소형 모델

def featurize(url: str) -> list[float]:
    # 회피에 취약한 얕은 특징들(의도적으로 단순)
    return [
        len(url),                                   # 길이
        url.count('.'),                             # 서브도메인/점 개수
        len(re.findall(r'[^a-zA-Z0-9]', url)),      # 특수문자 수
        int('@' in url),                            # @ 포함
        int(bool(re.search(r'\d{1,3}(\.\d{1,3}){3}', url))),  # IP 형태
        int(any(k in url for k in ['login','secure','verify','account'])),  # 피싱 키워드
    ]

class URLIn(BaseModel):
    url: str

@app.post("/predict")
def predict(inp: URLIn):
    score = float(model.predict_proba([featurize(inp.url)])[0][1])
    return {"url": inp.url, "malicious_score": score, "verdict": "malicious" if score >= 0.5 else "benign"}
```

**왜 회피 가능한가**: 특징이 얕고(길이/점/키워드) 문제공간 제약을 반영 안 함 → 키워드 제거, 길이 조정, 인코딩 등으로 feature를 benign 쪽으로 밀면서도 URL 유효성 유지 가능.

---

## 3. Red 채점기 (grader/red_grader.py)

```python
import requests
from urllib.parse import urlparse

def grade_red(submission, context):
    url = submission.get("evasive_url", "")
    # (1) 문제공간 제약 검증
    p = urlparse(url)
    if not (p.scheme and p.netloc):
        return GradeResult(False, 0, "invalid URL (problem-space constraint violated)")
    if not constraint_reaches_target(url, context["target_domain"]):   # 리다이렉트/동형 허용
        return GradeResult(False, 0, "does not reach malicious target")
    if not looks_like_brand(url, context["impersonated_brand"]):
        return GradeResult(False, 0, "no phishing intent preserved")
    # (2) 탐지기 회피 확인
    r = requests.post(f'{context["detector"]}/predict', json={"url": url})
    score = r.json()["malicious_score"]
    if score < 0.5:
        return GradeResult(True, 200, f"evaded (score={score:.2f})")
    return GradeResult(False, 0, f"still detected (score={score:.2f})")
```

**핵심**: constraint_check가 있어서 "feature-space만 조작한 무효 URL"은 불합격 → Pierazzi 문제공간 개념을 채점에 강제.

---

## 4. Blue 채점기 (grader/blue_grader.py)

```python
def grade_blue(context):
    improved = context["blue_model"]        # Blue가 제출한 개선 모델/전처리 파이프라인
    # (a) 원 테스트셋 정확도 유지
    acc = evaluate(improved, context["holdout_testset"])
    # (b) Red 회피 샘플 재탐지율
    redetect = evaluate_on(improved, context["red_evasion_samples"], target_label="malicious")
    pts = (80 if acc > 0.9 else 0) + (120 if redetect > 0.8 else 0)
    return GradeResult(acc > 0.9 and redetect > 0.8, pts,
                       f"acc={acc:.2f} redetect={redetect:.2f}")
```

**균형의 묘미**: Blue는 정확도를 지키면서(과견고화로 정상까지 막으면 감점) 회피만 다시 잡아야 함 → 실제 적대적 견고화의 트레이드오프를 훈련.

---

## 5. 방어 가이드 (writeup.md, 훈련 후)

- 회피 원인: 얕은 특징 + 문제공간 무시.
- 방어 방향: (1) 불변/의미 특징(도메인 평판, 등록정보, 리다이렉트 체인) 추가, (2) 적대적 학습(adversarial training)으로 회피 샘플 포함 재학습, (3) 입력 정규화(동형이의·인코딩 통일), (4) 앙상블/이상탐지.
- 교훈: feature-space 방어만으론 부족. problem-space에서 실현 가능한 변형을 방어 대상으로 삼아야 함.

---

## 6. AI 분야 공통 패턴 & 안전

- **모든 모델·데이터는 합성/훈련용**. 실제 피싱 URL·실도메인·민감 데이터 배제.
- **`hardened` 안전 프로파일 강제**: ML 추론 서비스는 저권한·격리 컨테이너(08). 모델 파일은 신뢰 경계 안에서만.
- **채점에 제약 검증 필수**: AI 회피 문제는 "무효 입력으로 점수 따기"를 막는 constraint_check가 반드시 있어야 함(비의도 해법 차단).
- **확장 문제**: AI-003(모델추출)은 쿼리 로깅으로 추출 탐지, AI-004(백도어)는 뉴런 활성 분석, AI-005(프롬프트 인젝션)는 LLM 통합 지점 격리 — 모두 이 구조 재사용.
- **데이터셋 주의**: EMBER 등 공개셋 사용 시 라이선스·재현성 확인, 가능한 합성 우선.
```
