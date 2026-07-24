# AI-000 Writeup

**목표**: AI 보안 도입 - feature-space 회피 개념 체감.
**해법**: 악성 샘플의 특징(길이·점개수·특수문자·키워드)을 정상 URL 수준으로 낮추면
모델이 바로 속는다. 실제 URL로 구현 가능한지는 전혀 안 따짐(그게 AI-002의 주제).
**교훈**: feature-space 방어만으론 부족하다 — problem-space에서 실현 가능한 변형을
방어 대상으로 삼아야 한다(Pierazzi et al.).
