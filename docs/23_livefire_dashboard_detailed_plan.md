# Live Fire Dashboard — 상세 구현 계획 (02·07번 문서의 실행 사양)

> 화면 목록과 디자인 방향은 02번에 있다. 여기서는 실제로 짤 수 있는 컴포넌트 트리,
> 상태관리 구조, API 연동 지점을 파일 단위까지 내렸다.

---

## 0. 디렉토리

```
dashboards/livefire/
├─ src/
│  ├─ api/
│  │  ├─ types.ts            # Event/Score/Scenario 타입(contracts와 동일 필드)
│  │  ├─ client.ts           # fetch 래퍼
│  │  ├─ useEventStream.ts   # WS 훅(재연결 백오프)
│  │  ├─ useScores.ts        # 폴링 훅
│  │  └─ useReplay.ts        # 리플레이 전용 데이터 소스
│  ├─ store/
│  │  └─ rangeStore.ts       # zustand — 자산상태/이벤트버퍼/점수/역할
│  ├─ components/
│  │  ├─ AssetMap/
│  │  │  ├─ AssetMap.tsx
│  │  │  ├─ AssetNode.tsx
│  │  │  └─ useAssetState.ts  # 이벤트 -> 자산상태 파생 로직
│  │  ├─ Timeline/
│  │  │  ├─ EventTimeline.tsx
│  │  │  └─ EventRow.tsx
│  │  ├─ Score/
│  │  │  ├─ ScoreBoard.tsx
│  │  │  └─ ScoreChart.tsx
│  │  ├─ PatchStatus/
│  │  │  └─ PatchMatrix.tsx
│  │  ├─ FlagTracker/
│  │  │  └─ FlagList.tsx
│  │  ├─ Instructor/
│  │  │  ├─ InstructorConsole.tsx
│  │  │  └─ AuditLogView.tsx
│  │  └─ Replay/
│  │     └─ ReplayControls.tsx
│  ├─ views/
│  │  ├─ RedView.tsx
│  │  ├─ BlueView.tsx
│  │  ├─ ObserverView.tsx
│  │  └─ InstructorView.tsx
│  └─ App.tsx                 # role 기반 라우팅
```

---

## 1. 상태관리 (zustand)

### `store/rangeStore.ts`
```typescript
type AssetState = "secure" | "under_attack" | "compromised" | "recovered";

interface RangeStore {
  events: Event[];                          // 최근 500건 링버퍼
  assetStates: Record<string, AssetState>;   // asset -> 상태
  scores: { teams: Record<string, {red: number; blue: number}> } | null;
  role: "red" | "blue" | "observer" | "instructor";
  paused: boolean;                            // Timeline 일시정지(스크롤백)

  pushEvent: (e: Event) => void;
  setScores: (s: RangeStore["scores"]) => void;
  setRole: (r: RangeStore["role"]) => void;
  togglePause: () => void;
}
```

### `components/AssetMap/useAssetState.ts` — 이벤트→자산상태 파생 규칙(명시적 매핑)
```typescript
function deriveAssetState(events: Event[], asset: string): AssetState {
  const relevant = events.filter(e => e.target_asset === asset);
  const last = relevant[0]; // events는 최신순 정렬 가정
  if (!last) return "secure";
  if (last.event_type === "asset_recovered") return "recovered";
  if (last.event_type === "asset_compromised") return "compromised";
  if (["red_attack_started", "flag_exfiltrated"].includes(last.event_type)) return "under_attack";
  return "secure";
}
```
**주의**: "recovered" 상태는 몇 초간 초록 플래시 후 "secure"로 자동 전환(타이머로 처리, 3초 뒤
setAssetState(asset, "secure")).

---

## 2. AssetMap (시그니처 컴포넌트)

### `AssetMap.tsx`
- SVG 기반, 4개 구역(ground_station/power_plant/defense_network/dmz) 고정 좌표.
- 자산 간 연결선: DMZ→각 자산. 공격 이벤트 발생 시 해당 연결선에 애니메이션(stroke-dasharray
  이동)으로 "트래픽 흐름" 표현.
- `AssetNode.tsx` props:
  ```typescript
  interface AssetNodeProps {
    asset: string;
    state: AssetState;
    onClick: (asset: string) => void;
  }
  ```
  상태별 색상(색만 쓰지 않고 아이콘 병행 — 접근성):
  - secure: 파랑 + 방패 아이콘
  - under_attack: 앰버 펄스 + 경고 아이콘
  - compromised: 빨강 + X 아이콘
  - recovered: 초록 플래시(1회성 애니메이션) + 체크 아이콘

**완료 판정**: PP-005(세이프티 우회) curl → `power_plant` 노드가 3초 내 compromised로 전환.

---

## 3. Event Timeline

### `EventTimeline.tsx`
- 가상 스크롤(react-window 또는 자체 windowing) — 500건 이상 쌓여도 렉 없어야 함.
- 필터 바: team_id, asset, event_type 드롭다운(다중선택).
- 일시정지 토글: paused=true면 신규 이벤트는 버퍼에 쌓이지만 리스트 리렌더 안 함(스크롤 위치 유지),
  재개 시 한번에 반영 + "N건 놓침" 배지.

### `EventRow.tsx`
```typescript
interface EventRowProps { event: Event; }
```
이벤트 타입별 아이콘/색(AssetNode와 동일 팔레트 재사용): 공격=앰버, 탐지=시안, 패치=초록,
유출=마젠타, 복구=초록, stage_completed=보라(신규 타입이므로 구분).

---

## 4. Score Board

### `ScoreBoard.tsx`
- 팀별 Red/Blue 대형 숫자 카운트업(react-spring 또는 자체 requestAnimationFrame 보간).
- `/scores` 3초 폴링 + `score_updated` 이벤트 수신 시 즉시 갱신(폴링과 이벤트 중 빠른 쪽 우선).

### `ScoreChart.tsx`
- `/scores/history`(achievements 타임라인)를 시간축 누적합으로 변환해 recharts 라인차트.
```typescript
function toCumulativeSeries(achievements: Achievement[]): {t: number; red: number; blue: number}[]
```

---

## 5. Patch Status

### `PatchMatrix.tsx`
- 행: 취약점(vuln_catalog.json), 열: 팀(멀티팀 지원 시) 또는 단일 열(싱글팀).
- Config Service `/config/patches` 폴링(5초) — 상태 3가지: vulnerable(빨강)/patched(초록)/
  checking(회색, safe_probe 진행 중 — 이 상태는 프론트에서 낙관적으로 표시: 토글 클릭 직후
  ~5초간 checking으로 보여주고 다음 폴링에서 실제 상태로 확정).

---

## 6. Flag Tracker

### `FlagList.tsx`
- `flag_exfiltrated` 이벤트를 asset별로 그룹핑해 표시. 상태: safe/accessed/exfiltrated/blocked.
- 유출 발생 시 해당 자산의 AssetMap 노드에도 마젠타 테두리 오버레이(교차 강조).

---

## 7. Instructor Console (역할 제한)

### `InstructorConsole.tsx`
- role !== "instructor"면 라우트 자체를 렌더링하지 않음(App.tsx의 역할 라우팅에서 차단,
  **프론트 숨김은 보조 수단, 실제 차단은 백엔드 인증**).
- 시나리오 시작/종료, 이벤트 수동주입, 점수조정 폼 — 24번 문서(Instructor Console API)의
  엔드포인트에 대응.
- `AuditLogView.tsx`: `/instructor/audit` 테이블, 최신순, actor/action/reason 컬럼.

---

## 8. Replay

### `useReplay.ts`
```typescript
function useReplay(scenarioId: string) {
  // GET /replay/events 전체 로드 후 배속 재생 타이머로 이벤트를 하나씩 rangeStore에 push
  // 재생 중에는 useEventStream(라이브 WS)을 구독 해제하고 이 훅의 타이머가 대신 이벤트를 공급
}
```
- 배속(1/2/4/8x): `setInterval` 간격을 이벤트 간 실제 시간차/배속으로 계산.
- 스크러버: 특정 timestamp로 점프 시 그 시점까지의 이벤트를 한번에 replay해 상태 재구성 후 재생 재개.

---

## 9. 역할별 뷰 분리 (07번 문서 2절)

### `App.tsx`
```typescript
function App() {
  const role = useRangeStore(s => s.role); // 로그인/토큰에서 결정, 프론트는 표시만
  switch (role) {
    case "red": return <RedView />;
    case "blue": return <BlueView />;
    case "observer": return <ObserverView />;
    case "instructor": return <InstructorView />;
  }
}
```
**중요(반복 강조)**: API 응답 자체가 역할별로 스코프 제한되어야 한다(예: Red 토큰으로
`/config/patches` 호출 시 403 또는 빈 응답). 프론트가 컴포넌트를 안 그리는 것만으로는
치팅 방지가 안 됨 — 이건 24번 문서(Instructor API)와 04번 문서 인증 부분에서 백엔드가 처리.

---

## 10. 마일스톤

| 마일스톤 | 내용 | 완료 판정 | 상태 |
|---|---|---|---|
| M6.0 | api/ 계층(types, client, useEventStream, useScores) | WS 연결 + 콘솔에 이벤트 로그 출력 | ✅ 구현 완료(client.ts, rangeStore.ts) |
| M6.1 | AssetMap + useAssetState | curl 공격 → 노드 상태 실시간 전환 | ✅ 구현 완료. deriveAssetState 로직은 node로 실제 실행 검증(공격/침해/복구/무관이벤트 4케이스) |
| M6.2 | EventTimeline + ScoreBoard | 이벤트/점수 실시간 반영, 필터 동작 | ✅ 구현 완료. ScoreBoard는 카운트업+누적 스파크라인을 라이브러리 없이 순수 SVG로 구현 |
| M6.3 | PatchStatus + FlagTracker | 패치 토글 → 매트릭스 갱신, 유출 → 마젠타 경보 | ✅ 구현 완료 |
| M6.4 | Instructor Console(24번 API 완성 후) | 시나리오 시작/종료, audit 조회 | ✅ 구현 완료(24번 문서의 Instructor API와 실제 연동) |
| M6.5 | Replay | 종료된 훈련 4배속 재생, 스크러버 점프 | ⬜ 계획만(다음 단계) |
| M6.6 | 역할별 뷰 | Red/Blue/Observer 별 노출 정보 차이 확인 | 🟡 프론트 전용 구현(역할 스위처, 화면 노출 차등). **백엔드 스코프 인증은 아직 없음** — README에 한계 명시 |

**TS/TSX 검증 한계**: 개발 샌드박스에 npm 레지스트리 접근이 막혀 있어 `npm install`/`tsc` 타입체크는
못 했다. 대신 (1) 모든 파일의 괄호 균형 정적 검사 통과 (2) 핵심 순수 로직(deriveAssetState)은
node로 직접 실행해 4가지 케이스 검증 완료. 실제 GCP 환경에서 `npm install && npm run build`로
최종 확인 필요.
