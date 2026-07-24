# DET-006 방어 노트 (Blue)

## 목표
DGA(Domain Generation Algorithm) C2 랑데부를 탐지한다. 감염 호스트는 무작위처럼 보이는
도메인을 대량으로 조회하므로, 출발지별 **서로 다른 조회 도메인 수(distinct)**가 급증한다.

## 정답 규칙(개념)
```yaml
kind: threshold
threshold_group_by: "src.ip"
threshold_condition: "distinct(raw.query) >= 20"
threshold_window_sec: 300
```

## 튜닝 포인트
- **임계값**: 캐시 워밍/광고/텔레메트리로 여러 도메인을 조회하는 정상 호스트를 넘지 않게 설정.
- **엔트로피 보강**: 조회 도메인 라벨의 무작위성(엔트로피)·NXDOMAIN 비율을 함께 보면 정밀도 향상.
- 알려진 DGA 계열 시그니처/평판 피드와 결합.
