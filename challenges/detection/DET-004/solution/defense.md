# DET-004 방어 노트 (Blue)

## 목표
C2 비콘의 **주기성**을 탐지한다. (src,dst) 쌍의 연결 간격을 모아 변동계수(jitter =
표준편차/평균)가 낮으면 자동화된 비콘으로 판정한다.

## 정답 규칙(개념)
```yaml
kind: periodicity
periodicity_group_by_src: "src.ip"
periodicity_group_by_dst: "dst.ip"
periodicity_min_observations: 5     # 충분한 관측 후 판정(성급한 발화 방지)
periodicity_jitter_threshold: 0.1   # 간격 흔들림 10% 미만이면 비콘
periodicity_allowlist_dst: ["10.0.0.53"]   # 내부 DNS/NTP 등 정상 규칙 폴링 제외
```

## 튜닝 포인트
- **allowlist**가 핵심: NTP/업데이트/헬스체크처럼 원래 규칙적인 정상 폴링을 제외하지 않으면 오탐.
- **min_observations**로 초반 몇 건만으로 성급히 발화하지 않게 한다.
- 실제 악성코드는 jitter를 넣어 회피하므로 임계는 환경에 맞게 조정한다.
