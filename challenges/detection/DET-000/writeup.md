# DET-000 Writeup

**목표**: 첫 임계(threshold) 탐지 룰 작성 연습.
**정답**: `src.ip`로 그룹핑해 60초 내 `distinct(timestamp) >= 10`을 조건으로.
**교훈**: 탐지 엔진이 지원하는 연산(distinct count)의 한계를 이해하고, 그 안에서
원하는 탐지 로직을 어떻게 표현할지 우회하는 법을 익힌다 — 실제 SIEM 룰 작성에서
자주 마주치는 상황이다.
