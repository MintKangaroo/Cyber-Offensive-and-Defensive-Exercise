# EDR Console (프론트엔드)

## 디자인 방향

**CYBER RANGE COMMAND SYSTEM 공유 디자인 시스템**(`@cyber-range/command-system`)을 채택했다.
독자 Tailwind 팔레트를 제거하고 공유 토큰(`tokens.css`)·컴포넌트(`Button`·`StatusBadge`·
`EmptyState`)로 통일해 Command Tower·다른 워크스페이스와 같은 시각 언어를 쓴다. 시그니처인
**프로세스 트리(`pstree`식 `├─`/`└─` 커넥터)** 는 그대로 — 데이터 구조 자체가 정체성이라는
원칙은 유지하고 색만 공유 토큰으로 옮겼다. EDR 고유 레이아웃(3단 워크스페이스·호스트 목록·
프로세스 탐색기·탐지 카드)만 `src/index.css`에 공유 토큰 기반으로 남겼다(하드코딩 색상 0).

- **심각도(보존)**: 문자열 5단계 critical/high/medium/low/info 라벨 그대로, 색상만 5개 구분되는
  공유 톤으로 매핑(`severity.ts`): critical→critical·high→warning·medium→intelligence·
  low→operational·info→neutral. 색만으로 구분하지 않고 텍스트 라벨을 항상 병행.
- **동작 보존**: 전송 계층(`api/client.ts`·`types.ts`) 불변 — 호스트/프로세스/알림 폴링(5s)·WS
  재연결 백오프·격리(Isolate/Unisolate)·프로세스 종료(Kill)의 사유 필수·감사 기록·비동기
  KillCommand 처리(에이전트 다음 폴링 실행). 온라인/격리 점 펄스는 `prefers-reduced-motion` 존중.
- **테스트**: `severity.test.ts`(순수 매핑) + `dashboard.test.tsx`(HostList 격리·AlertsPanel Kill·
  ProcessTree 렌더, vitest+testing-library). CI specialist-dashboards 잡이 `--if-present`로 실행.

## 구조

```
console/
├─ src/api/types.ts       # 백엔드 응답 타입(services/edr/api/main.py와 1:1 대응)
├─ src/api/client.ts      # fetch 래퍼 + WS 실시간 알림 훅 + 폴링 훅
├─ src/components/
│  ├─ HostList.tsx        # 호스트 목록 + Isolate/Unisolate(사유 입력 필수)
│  ├─ ProcessTree.tsx     # 프로세스 트리(시그니처 컴포넌트), flagged pid 하이라이트
│  └─ AlertsPanel.tsx     # 알림 목록 + Kill Process(사유 입력 필수)
└─ src/App.tsx            # 3단 레이아웃(호스트 | 프로세스 | 탐지)
```

## 백엔드 연동 지점

- `GET /edr/hosts` + `GET /config/quarantine` — 호스트 목록에 격리 상태 병합
- `GET /edr/hosts/{asset}/processes` — 프로세스 트리(5초 폴링)
- `GET /edr/alerts` + `WS /edr/ws` — 알림은 폴링과 실시간 스트림을 병합해 중복 제거
- `POST /edr/hosts/{asset}/isolate|unisolate` — 사유 필수(빈 문자열이면 버튼 비활성화)
- `POST /edr/hosts/{asset}/process/{pid}/kill` — 사유 필수, 응답의 `warning` 필드를 그대로 노출
  (백엔드가 "이름은 서버와 같지만 pid가 달라 진행함" 같은 경고를 줄 수 있음)

## 실행

```bash
cd services/edr/console
npm install
VITE_EDR_BACKEND_URL=http://localhost:8080 VITE_CONFIG_SERVICE_URL=http://localhost:8030 npm run dev
```

## 알려진 제약 / 다음 단계

- Kill Process 확인 후 실제 종료까지는 에이전트의 다음 폴링 주기(최대 5초)가 걸린다.
  UI에서 "완료됨"으로 바로 표시하지 않고 `warning`/커맨드 id만 보여주는 이유가 이것 —
  실제 완료 여부는 `GET /edr/hosts/{asset}/kill-commands`로 폴링해서 상태(`done`/`failed`)를
  확인해야 한다. 다음 단계로 이 목록을 AlertsPanel 하단에 타임라인으로 노출하면 좋다.
- 역할별 접근 제어(Red/관전자는 Isolate/Kill 버튼 자체가 안 보여야 함, 07번 문서 2절)는
  아직 이 프론트엔드에 반영되지 않음 — 백엔드 인증과 함께 다음 단계에서 추가.
