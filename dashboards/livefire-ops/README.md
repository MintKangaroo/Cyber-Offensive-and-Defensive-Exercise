# Live-Fire Ops Console (`dashboards/livefire-ops`)

CCE/Locked Shields 방송톤의 **몰입형 Red 라이브파이어 작전 콘솔**. 2단 구조:

1. **국가 기반시설 현황 아레나** — 방사형 돔 + 시설 노드 성좌, 타이머 3종, 스코어보드, Solve Log.
2. **시설별 작전 콘솔** — 노드 클릭 드릴다운. OT 침투맵 · 물리 트윈 스키매틱 · 라이브 레지스터
   테이블 · 서비스 상태 · 킬체인 셰브론 · EXECUTE STRIKE.

플래그 제출 UI 가 아니라, 공격 행위가 **실제 ICS 트윈의 물리 상태**(터빈 RPM·냉각수·SIS·DAMAGE 등)에
즉시 반영되는 라이브 경험. 자산명·프로토콜·포트·레지스터·취약점 ID·점수는 모두 실제 코드에서 가져온다.

디자인 계약은 [`DESIGN.md`](./DESIGN.md) 참조(red↔blue 듀얼리티·플랫 하드엣지 패널·브래킷 HUD·tri-font).

## 빌드 / 테스트

```bash
npm install
npm run dev        # 개발 서버
npm run build      # tsc -b && vite build → dist/
npx vitest run     # 유닛/계약/접근성 테스트
```

## 라이브 트윈 연결

콘솔은 선택된 섹터의 트윈에 대해 (1) `/api/telemetry` 를 1.5초 간격 폴링해 게이지를 움직이고,
(2) 킬체인 `EXECUTE STRIKE` 가 트윈의 공격 엔드포인트를 호출해 실제 물리 파국을 유발하며,
(3) `event_collector` SSE `/stream` 으로 스트라이크/점수/타이머를 받는다. 트윈 미도달 시 정적
데모(mock)로 폴백한다(오프라인에서도 UI 동작, 상태 badge 가 `DEMO`/`LIVE` 로 표시).

트윈 URL 주입(빌드 타임, Vite 환경변수):

| 변수 | 대상 | 기본값 |
|---|---|---|
| `VITE_COLLECTOR_URL` | event_collector | `http://localhost:8010` |
| `VITE_POWER_TWIN_URL` | 발전소 트윈 | `http://localhost:8002` |
| `VITE_TWIN_<SECTOR>` | 그 외 섹터 트윈 | 미설정 시 폴백 |

`<SECTOR>` 는 대문자 섹터 id(예: `VITE_TWIN_WATER`, `VITE_TWIN_HOSPITAL`). 미설정 섹터는
라이브로 표시하지 않는다(정직 — no-op 애니메이션 금지).

### 예: 상수도 섹터 라이브(E2E 검증됨)

```bash
# 1) 상수도 트윈 기동
PYTHONPATH="$REPO" RBAC_ALLOW_INSECURE_DEV=true \
  python3 -m uvicorn services.water_utility.main:app --host 127.0.0.1 --port 8203

# 2) 콘솔을 트윈 URL 로 빌드 후 서브
echo 'VITE_TWIN_WATER=http://127.0.0.1:8203' > .env.local   # .gitignore 아님 — 커밋 금지
npm run build && npx vite preview --port 5177
# → http://localhost:5177/?v=facility&sector=water
```

콘솔 킬체인(SCADA HMI 기본계정 → 펌프 제어 → 염소 과투입 → **SIS 무력화**)을 실행하면 상수도
트윈이 실제로 구동된다: 안전 인터록(SIS)이 ARMED 인 동안은 `RESERVOIR_PPM` 이 redline(4ppm)에서
캡되고, `/api/safety/override` 로 SIS 를 BYPASS 하면 염소 과투입이 지속돼 `RESERVOIR_PPM` 이
한계를 넘고 `CONTAMINATION` 이 누적, `CATASTROPHIC_FAILURE`(급수 오염 파국)에 도달한다 —
콘솔 게이지·푸터 티커가 이를 라이브로 반영.

## 섹터 라이브 커버리지

- **발전소(power)** — 전용 트윈, 완전 라이브(냉각수/온도 포함). 기함 수직 슬라이스.
- **상수도(water)·병원(hospital)** — 통일 `/api/telemetry` 규약, 킬체인 전 단계 라이브 액션.
  엔드포인트는 실제 트윈 라우트와 일치(회귀: `src/sector-live.test.tsx` +
  `tests/unit/test_twin_telemetry.py` · `test_twin_safety_override.py`).
- **그 외 섹터** — 아레나 노드로 표시, 콘솔은 확장 패턴(트윈 + `VITE_TWIN_<SECTOR>` 추가 시 라이브).
