# AAR 리포트 / 사운드·알람 / ATT&CK 커버리지 — 상세 구현 계획

> 07번 문서 3·4절, 06번 문서 3절의 개요를 실제 구현 사양으로.

---

## 1. AAR(After-Action Report) 리포트 서비스

### 디렉토리
```
services/aar_report/
├─ main.py              # FastAPI: GET /report/aar?scenario_id=
├─ metrics.py           # MTTD/MTTR/탐지율/오탐률 계산
├─ attack_heatmap.py    # ATT&CK 기술 x 탐지여부 매트릭스 생성
└─ pdf/
   ├─ template.html     # Jinja2 템플릿(WeasyPrint 렌더링용)
   └─ render.py
```

### 1.1 지표 계산 (`metrics.py`) — 정확한 함수 시그니처

```python
def compute_mttd(events: list[NormalizedizedEvent_or_Event]) -> float:
    """MTTD = mean(detection_ts - attack_ts) over all matched pairs.
    matched_event_id로 연결된 (공격, 탐지) 쌍을 전부 모아 평균.
    페어링 안 된 탐지(unmatched_detection)는 제외."""

def compute_mttr(events) -> float:
    """MTTR = mean(recovered_ts - compromised_ts).
    asset_recovered 이벤트의 metadata.dwell_sec(이미 recovery_watcher가 계산해 넣어둠, 04번
    문서 2절 구현체 참고)을 그대로 평균 — 재계산 불필요."""

def detection_rate(events) -> float:
    """탐지율 = (matched_event_id가 있는 공격 수) / (전체 red_attack_started + flag_exfiltrated
    + red_objective_success 수)"""

def false_positive_rate(alerts: list[Alert], ground_truth_noise_ids: set[str]) -> float:
    """오탐률 = (ground_truth상 노이즈인데 알림이 뜬 것) / (전체 알림).
    06번 문서 6절의 오탐 트리아지 라벨(노이즈 생성기가 심어둔 ground truth)을 참조."""
```

### 1.2 ATT&CK 히트맵 (`attack_heatmap.py`)
```python
def build_heatmap(scenario_id: str) -> dict[str, dict[str, bool]]:
    """이번 훈련에서 실제 발생한 이벤트의 mitre 태그를 모아 {tactic: {technique_id: covered}}.
    'covered'는 해당 기술에 대응하는 탐지 알림이 하나라도 있었는지(탐지 성공 여부),
    단순 발생 여부가 아님 -> Red가 썼지만 Blue가 못 잡은 기술이 명확히 드러남."""
```

### 1.3 API
```python
@app.get("/report/aar")
def get_aar_report(scenario_id: str = "default") -> dict:
    """{
      "summary": {scenario_id, teams, duration_sec, final_scores},
      "timeline_highlights": [...],   # 04번 문서 dwell time이 계산된 주요 이벤트 몇 개
      "red_performance": {stages_completed, flags_obtained, stealth_bonus_total},
      "blue_performance": {mttd_sec, mttr_sec, detection_rate, false_positive_rate},
      "attack_heatmap": {...},
      "score_timeseries": [...],      # scoring_engine의 achievements를 시간순 누적합
      "recommendations": [...]         # 4절 자동 코멘트
    }"""
```

### 1.4 자동 개선 권고 코멘트 (규칙 기반, 간단하게)
```python
def generate_recommendations(report: dict) -> list[str]:
    tips = []
    if report["blue_performance"]["mttd_sec"] > 180:
        tips.append("평균 탐지시간이 3분을 넘습니다 — 임계 룰의 window_sec을 좁히거나 "
                    "알림 트리아지 프로세스를 점검하세요.")
    if report["blue_performance"]["false_positive_rate"] > 0.3:
        tips.append("오탐률이 30%를 넘습니다 — 노이즈 생성기의 eps를 낮추거나 규칙의 "
                    "임계값을 재조정하세요.")
    uncovered = [t for tactic in report["attack_heatmap"].values()
                for t, covered in tactic.items() if not covered]
    if uncovered:
        tips.append(f"다음 ATT&CK 기술이 이번 훈련에서 전혀 탐지되지 않았습니다: {uncovered}")
    return tips
```

### 1.5 PDF 생성
```python
def render_pdf(report: dict, output_path: str) -> None:
    """Jinja2로 template.html 렌더 -> WeasyPrint.HTML(string=...).write_pdf(output_path).
    차트(score_timeseries, heatmap)는 matplotlib로 PNG 렌더 후 <img>로 삽입(WeasyPrint가
    인터랙티브 차트를 못 그리므로 정적 이미지화)."""
```

### 1.6 마일스톤
| 세부 | 완료 판정 |
|---|---|
| metrics.py | 합성 이벤트 픽스처로 MTTD/MTTR/탐지율/오탐률 계산 결과가 수기 계산과 일치 |
| attack_heatmap.py | 알려진 시나리오(예: SAT-KILLCHAIN-01)의 mitre 태그가 정확히 매핑 |
| API + PDF | `/report/aar` 호출 → PDF 파일 생성, 페이지 수/차트 렌더 확인 |

---

## 2. 사운드/알람

### 구현 위치
`dashboards/livefire/src/hooks/useAlertSound.ts`

```typescript
function useAlertSound(enabled: boolean) {
  const audioCtxRef = useRef<AudioContext | null>(null);

  // 브라우저 자동재생 정책: 사용자 상호작용(클릭) 이후에만 AudioContext 생성/재생 가능
  const unlock = useCallback(() => {
    if (!audioCtxRef.current) audioCtxRef.current = new AudioContext();
  }, []);

  const playCriticalAlert = useCallback(() => {
    if (!enabled || !audioCtxRef.current) return;
    const ctx = audioCtxRef.current;
    const osc = ctx.createOscillator();
    osc.frequency.value = 880;   // 짧은 경고음(합성음, 외부 파일 의존 없음)
    osc.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.15);
  }, [enabled]);

  return { unlock, playCriticalAlert };
}
```

**연결 지점**: `EventTimeline`이 새 이벤트 수신 시 severity가 critical(또는 event_type이
`flag_exfiltrated`)이면 `playCriticalAlert()` 호출.

**기본값**: `enabled=false`. 설정 패널에 토글 추가, 세션 상태(리덕스/zustand)로만 관리 —
브라우저 저장소(localStorage 등)에 영구 저장할지는 배포 환경 정책에 따라 결정.

---

## 3. ATT&CK 커버리지 뷰 (프론트엔드)

### 데이터 소스
22번 문서에서 이미 설계한 SIEM API `GET /detection/attack-coverage`를 그대로 소비.

### 컴포넌트
```
dashboards/livefire/src/components/AttackCoverage/
├─ AttackMatrix.tsx     # MITRE ATT&CK Navigator 스타일 그리드
└─ TechniqueCell.tsx
```

```typescript
interface AttackMatrixProps {
  coverage: Record<string, Record<string, { rules: string[]; covered: boolean }>>;
}
```
- 행: Tactic(Initial Access, Execution, ...), 열: Technique ID.
- 색: covered=true(초록), false(회색 — "탐지 룰이 이 기술을 못 잡음, 갭").
- 셀 클릭 시 해당 기술을 잡는 규칙 id 목록 툴팁.

**용도**: 훈련 설계 단계에서 "이 시나리오가 쓰는 공격 기술을 우리 룰셋이 커버하는가"를
사전 점검(06번 문서 3절과 연결), 훈련 후에는 AAR의 히트맵과 같은 데이터를 다른 뷰로 제공.

---

## 4. 통합 마일스톤

| 마일스톤 | 내용 | 상태 |
|---|---|---|
| M-AAR.1 | metrics.py + attack_heatmap.py + API | ✅ 구현+검증 완료(MTTD/MTTR/탐지율/오탐률/은신보너스 전부 실제 실행 검증) |
| M-AAR.2 | PDF 렌더링 | ✅ 구현+검증 완료. **WeasyPrint 대신 reportlab 사용**(시스템 라이브러리 의존성 회피). 첫 시도에서 한글이 깨지는 실제 버그 발견 → CID 폰트(HYSMyeongJo-Medium) 등록으로 해결, pypdf로 텍스트 추출까지 재검증 |
| M-AAR.3 | 대시보드 사운드 훅 + 설정 토글 | ✅ 구현 완료. Live Fire App.tsx에 실제 연결(critical 이벤트 재생, 기본 off, unlock 처리) |
| M-AAR.4 | AttackMatrix 컴포넌트(SIEM API 연동) | ✅ 구현 완료(SIEM Dashboard의 AttackCoverageView.tsx) |
