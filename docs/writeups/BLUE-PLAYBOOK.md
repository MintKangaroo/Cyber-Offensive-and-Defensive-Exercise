# 🔵 BLUE PLAYBOOK — 방어 방법론

블루팀은 **Blue Portal(:5177)** 을 중심으로, 필요 시 **EDR 콘솔(:5173)**·**SIEM 콘솔(:5175)** 을 씁니다.
미션은 3가지: **① 탐지 → ② 대응·차단 → ③ 패치·복구**.

---
## ① 탐지 (Detect)

### A. 인시던트 피드 (Blue Portal → 인시던트 탭)
레드의 공격이 실시간 이벤트로 흐릅니다(`공격 개시`/`자산 침해`/`목표 달성`). 어떤 자산이 공격받는지 파악.

### B. 탐지 규칙 작성 (Blue Portal → 탐지 챌린지) — 점수 획득
13개 탐지 챌린지. 각 챌린지에서:
1. `⬇ 공격 로그` / `⬇ 정상 로그` 다운로드 → 두 로그의 차이를 분석.
2. **공격 로그엔 알림이 뜨고, 정상 로그엔 오탐이 없는** match/threshold/sequence 규칙(YAML)을 작성.
3. 제출하면 **실제 SIEM DetectionEngine이 채점**.

**핵심 원리 — AND 결합**: 단일 조건은 대개 정상 트래픽에 오탐합니다. 판별 조건을 모두 AND로 묶으세요.
```yaml
# 예: DET-010 EtherNet/IP CIP 안전 어셈블리 무단 SetAttribute
- id: DET-010
  title: "CIP unauthorized SetAttribute to safety assembly"
  severity: 5
  source_type: twin
  kind: match
  match:
    raw.cip_service: 16          # SetAttributeSingle  (이거 하나만 보면 조명 write에 오탐)
    raw.cip_class: 4             # Assembly
    raw.cip_instance: 101        # 안전 어셈블리        (세 조건 AND여야 무오탐)
```
규칙 종류:
- **match**: 필드 등가/부분일치(`~substring`). 여러 필드 AND.
- **threshold**: `group_by` 키별 슬라이딩 윈도우에서 `distinct(x) >= N` (스캔·브루트포스).
- **sequence**: 여러 step이 순서대로 within_sec 이내(웹쉘 업로드→실행 등).
- **periodicity**: (src,dst) 연결 간격의 변동계수로 C2 비콘 탐지.

### C. SIEM 콘솔 (:5175)
Discover에서 전문검색(예: `SetAttribute`, `jndi`), Alerts에서 발화 확인, Coverage에서 ATT&CK 커버리지.

---
## ② 대응·차단 (Respond) — EDR 콘솔 (:5173)
- **호스트 격리(Isolate)**: 침해 호스트를 네트워크에서 끊어 확산 차단.
- **프로세스 종료(Kill)**: 리버스쉘·웹서버발 셸 등 악성 프로세스 kill.
- 모든 대응은 **사유 입력 필수**(감사 로그 기록).

---
## ③ 패치·복구 (Patch & Recover) — Blue Portal → 패치 보드
- 11개 자산 × 60 취약점을 `patch`/`unpatch` 토글. **침해된 자산부터** 우선 조치.
- 패치하면 해당 엔드포인트가 401/403으로 닫혀 같은 공격이 막힙니다.
- 복구 판정(자동): 침해 이력 있는 자산이 (1)관련 취약점 patched + (2)health 3회 연속 정상이면
  `asset_recovered`(+50) 발행. **MTTR(복구 시간)이 짧을수록 유리**.

### 패치 검증 (호스트에서)
```bash
python3 shared/safe_probe.py --asset refinery_plant --summary   # 정유 섹터 패치율 확인
python3 shared/safe_probe.py --watch 30                          # 30초 간격 자동 재검증(반영 즉시 피드백)
```

---
## 방어 우선순위 (권장)
1. **인시던트 피드**로 공격받는 자산 식별 →
2. **EDR로 즉시 격리/kill**(확산 차단) →
3. **패치 보드로 해당 취약점 패치**(재공격 차단) →
4. **탐지 챌린지로 SIEM 규칙 작성**(점수 + 향후 자동탐지) →
5. `safe_probe --watch`로 패치 반영 확인 → 복구(+50).

> 상세 규칙 정답은 각 탐지 챌린지의 `solution/answer_rule.yaml`, 방어 노트는 `solution/defense.md` 참조(교관용).
