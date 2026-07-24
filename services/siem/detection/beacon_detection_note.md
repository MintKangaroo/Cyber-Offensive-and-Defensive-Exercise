# C2 비콘 탐지 — 구현 완료 (이전 한계 해결됨)

> 이 문서는 원래 "현재 엔진 3종 kind로는 표현 불가"라는 한계를 기록했었다.
> 이후 세션에서 4번째 kind(`periodicity`)를 실제로 추가해 해결했다 — 아래는 최종 구현 요약.

## 구현 내용

`services/siem/detection/engine.py`에 `Rule.kind == "periodicity"`를 추가하고,
`_PeriodicityState`가 (src,dst) 쌍별 연결 시각을 슬라이딩 윈도우로 기록해
간격의 변동계수(jitter = 표준편차/평균)를 계산한다.

```python
periodicity_min_observations: int = 5       # 최소 5회 연결 관측 후 판정
periodicity_jitter_threshold: float = 0.1   # 변동계수 임계
periodicity_window_sec: int = 3600
periodicity_allowlist_dst: list[str]        # 정상 폴링 목적지 제외
```

- **edge-trigger**: threshold 규칙과 동일한 원칙 — 비콘으로 새로 판정된 순간에만 1회 발화,
  패턴이 깨지면(jitter가 다시 임계 이상으로 올라가면) 재무장.
- **allowlist**: event_collector/scoring_engine/config_service/edr_backend처럼 우리 플랫폼
  자체의 정상 폴링 목적지는 제외(안 그러면 우리 서비스들끼리의 헬스체크가 비콘으로 오탐됨).

## 실제 검증 (3가지 시나리오)

1. **규칙적 비콘**(10초 간격, 지터≈0) → 5번째 관측에서 정확히 탐지.
2. **불규칙한 정상 트래픽**(2~60초 랜덤 간격) → 미탐지(오탐 없음).
3. **allowlist 목적지**로의 규칙적 연결 → 비콘으로 오탐되지 않음.

`services/siem/detection/rules/periodicity_rules.yaml`의 `NET-C2-BEACON-001` 규칙으로
등록되어 있으며, `services/siem/api/main.py`의 룰 로더가 이 필드들을 전부 읽어들인다.

## 남은 한계

- min_observations(기본 5회) 이상 연결이 쌓여야 판정되므로, 훈련 시간이 짧으면(예: 10분
  이내) 비콘 판정까지 시간이 걸릴 수 있다 — 짧은 훈련에서는 `min_observations`를 3 정도로
  낮추는 걸 고려.
- (src,dst) 쌍이 아니라 (src,dst,port) 단위로 더 세밀하게 추적하고 싶다면
  `periodicity_group_by_dst`를 `"dst.ip:dst.port"` 형태의 조합 dot-path로 확장하는 방식을
  검토할 것(현재는 IP 단위만 지원).
