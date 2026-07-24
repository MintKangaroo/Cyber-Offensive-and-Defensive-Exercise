# 백엔드 보강 스펙 — Claude Code 빌드 프롬프트

> 로드맵 ★★★/★★ 항목 중 백엔드에 해당하는 것들을 실제 구현 사양으로 정리.
> 대상: 기존 Event Collector(:8010), Scoring Engine(:8020) + 신규 Config Service.
> 커버 항목: 탐지→점수 자동 연결, 서비스 복구 판정, 시간감쇠 점수, Instructor Console + audit log, 패치 무중단 토글.

---

## 1. 탐지·차단 → Blue 점수 자동 연결 (★★★)

**문제**: 현재 Blue 점수는 patch_verified만 자동 적립됨. "탐지했다/막았다"가 점수로 연결 안 됨 → Blue 훈련 불완전.

**구현**:
- SIEM Detection Engine이 알림 생성 시 Event Collector `POST /events`로 아래 이벤트 발행:
  - `blue_detection_success` (severity 무관, 탐지 성공) → +20
  - `blue_block_success` (pfSense/Suricata IPS가 실제 차단) → +30
- 이벤트 metadata에 `rule_id`, `mitre`, `matched_event_id`(원 공격 이벤트) 포함.
- Scoring Engine 채점 규칙(멱등):
  - 탐지 점수는 **동일 공격 achievement당 1회만** 인정: milestone `blue:{vuln_id}:detection` (같은 취약점 반복 탐지 중복 적립 방지)
  - 단, 서로 다른 공격 인스턴스는 각각 인정하고 싶다면 milestone에 `matched_event_id` 포함 옵션 제공(설정값 `DETECTION_SCORE_MODE=per_vuln|per_instance`).

**신뢰성 가드**: Red가 아직 그 취약점을 공격하지 않았는데 Blue 탐지 이벤트가 오면(오탐/치팅) → `unmatched_detection` 태그로 기록하되 점수는 보류. 교관이 검토.

---

## 2. 서비스 복구(Recovery) 자동 판정 (★★★)

**문제**: `asset_recovered`(+50) 이벤트 타입은 있으나 발행 트리거가 없음.

**구현 — Recovery Watcher (신규 경량 워커)**:
- 조건: 자산이 한 번 `asset_compromised` 상태가 된 뒤,
  1. 해당 취약점이 safe probe에서 `patched`로 확인되고
  2. 자산 `/health`가 연속 N회(기본 3회, 30초 간격) 정상이면
  → `asset_recovered` 발행(+50), Asset Map 노드 green flash.
- compromised 이력이 없으면 recovery 점수 없음(패치만으로는 복구 점수 아님 — 공격받고 되살린 경우만).
- milestone: `blue:{target_asset}:recovered` (자산당 1회, 라운드 리셋 시 초기화).

```
compromised 기록 ──▶ patched 확인 ──▶ health 3회 연속 OK ──▶ asset_recovered(+50)
```

---

## 3. 시간 감쇠 점수 / Dwell Time (★★)

**개념**: MTTD(평균 탐지시간)·MTTR(평균 복구시간)을 점수에 반영해 "빠른 방어"를 보상.

**구현**:
- 각 공격 이벤트에 `first_seen_at` 기록. 대응 탐지 이벤트의 `matched_event_id`로 연결해 **dwell_time = detection_ts − attack_ts** 계산.
- Blue 탐지 보너스: `bonus = max(0, 20 − floor(dwell_sec / 30))` (30초마다 1점씩 감소, 최소 0). 빠를수록 최대 +20 보너스.
- Red dwell 보상: 공격이 T초(기본 300) 넘게 미탐지로 유지되면 Red에 `stealth_bonus` +10 (은신 성공).
- 모든 시간 지표는 AAR 리포트로 집계(MTTD/MTTR 팀별 비교).

**주의**: 시계 동기화. 모든 서비스가 동일 시간원(UTC, NTP)을 쓰도록. 이벤트 timestamp는 수신측이 아니라 발생측 기준.

---

## 4. Instructor Console API + Audit Log (★★★)

**신규 엔드포인트** (교관 토큰 필요, `Authorization: Bearer <instructor_token>`):

| 메서드 | 경로 | 설명 |
|---|---|---|
| POST | `/instructor/scenario/start` | 시나리오 시작(scenario_id, 참가팀, 시작시각) |
| POST | `/instructor/scenario/end` | 시나리오 종료 + 최종 점수 스냅샷 |
| POST | `/instructor/event/inject` | 임의 이벤트 수동 주입(훈련 흐름 제어) |
| POST | `/instructor/score/adjust` | 점수 수동 가감(사유 필수) |
| POST | `/instructor/killswitch` | 전체 훈련 즉시 정지(6절) |
| GET | `/instructor/audit` | 모든 교관 조작 이력 조회 |

**Audit Log 스키마** (append-only, 수정/삭제 불가):
```python
class AuditEntry(BaseModel):
    audit_id: str            # ULID
    timestamp: datetime
    actor: str               # 교관 식별자(토큰 subject)
    action: str              # "scenario_start" | "score_adjust" | "event_inject" | ...
    target: str | None       # 대상 팀/자산/시나리오
    before: dict | None      # 변경 전 상태(점수 조정 시)
    after: dict | None       # 변경 후 상태
    reason: str | None       # score_adjust/killswitch는 사유 필수
    ip: str
```

**원칙**: 점수 조정·이벤트 주입은 사유(reason) 없으면 400. audit는 별도 DB 테이블 + 파일 동시 기록(변조 방지).

---

## 5. 패치 무중단 토글 — Config Service (★★★)

**문제**: PATCH_* 환경변수는 컨테이너 재기동 필요 → 시나리오 중 취약점 on/off 불가.

**구현 — 신규 Config Service(:8030) + 트윈 폴링**:
- Config Service가 취약점별 패치 상태를 보관(Redis 또는 SQLite):
  - `GET /config/patches?asset=ground_station` → `{"GS-001": false, "GS-002": true, ...}`
  - `POST /instructor/patch/toggle` (교관) → 상태 변경 + audit 기록
- 각 트윈은 `patched()` 함수를 **환경변수 대신 Config Service 폴링**(3~5초 캐시)으로 교체:
  ```python
  # 기존: os.environ.get("PATCH_GS_001")
  # 변경: config_client.is_patched("GS-001")  # 로컬 캐시 + 주기 갱신
  ```
- Config Service 다운 시 안전 기본값: **마지막 캐시 유지**(가용성 우선). 완전 미연결 초기값은 전부 vulnerable.

**교관 UX 연결**: 대시보드 Instructor Console의 패치 매트릭스에서 토글 → `/instructor/patch/toggle` → 트윈이 다음 폴링에서 반영.

---

## 6. 킬스위치 (★★)

- `POST /instructor/killswitch {reason}` → 모든 트윈을 "maintenance" 모드로(Config Service 플래그). 트윈은 이 플래그를 보면 모든 공격 표면 엔드포인트를 503으로 응답.
- 동시에 `scenario_ended`(강제) 이벤트 발행, 대시보드 전체 배너 표시.
- 복구도 교관만: `POST /instructor/killswitch/release`.

---

## 7. 개발 순서

- **M1**: Config Service + 트윈 패치 폴링 전환(5절) — 다른 기능의 기반
- **M2**: Instructor API + Audit(4절), 킬스위치(6절)
- **M3**: 탐지 점수 연결(1절) — SIEM 빌드와 동기화 필요
- **M4**: Recovery Watcher(2절)
- **M5**: 시간감쇠/dwell(3절) + AAR 지표 집계 연동

## 8. Definition of Done

- 교관이 대시보드에서 GS-001 패치를 켜면 재기동 없이 30초 내 트윈이 안전 응답으로 전환.
- Red 공격 → SIEM 탐지 → Blue 탐지점수 자동 +20, dwell 빠르면 보너스.
- Red가 자산 침해 후 Blue가 패치+복구 → asset_recovered +50.
- 모든 교관 조작이 `/instructor/audit`에 사유와 함께 남음.
