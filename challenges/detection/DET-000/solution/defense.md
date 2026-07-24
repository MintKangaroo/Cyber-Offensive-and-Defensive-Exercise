# DET-000 방어 해법

`solution/answer_rule.yaml`의 threshold 규칙 참고. 핵심 포인트: 우리 Detection Engine의
threshold는 "distinct(field) 개수"만 지원하므로, "같은 행위의 반복 횟수"를 세려면
이벤트마다 고유한 `timestamp`를 distinct 대상으로 삼는 우회가 필요하다(이 챌린지의
교육 포인트 중 하나 — 탐지엔진 설계의 실제 제약을 체감).
