# EDR Console (프론트엔드)

## 디자인 방향

풀사이즈 Falcon UI를 흉내내는 대신, "터미널을 들여다보는 오퍼레이터"라는 핵심 경험 하나에
집중했다. 시그니처는 **프로세스 트리를 실제 `pstree` 출력처럼 `├─`/`└─` 커넥터 문자로
그리는 것** — 별도 장식 없이 데이터 구조 자체가 시각적 정체성이 되게 했다.

- **팔레트**: 베이스 `#0B0F14`(거의 검정), 패널 `#131920`, 보더 `#1F2933`.
  심각도는 critical `#FF3B3B` / high `#FF8A3D` / medium `#FFD23D` / info `#3DA9FC`,
  온라인 상태 `#3DDC84`. 색만으로 구분하지 않고 텍스트 라벨(critical/high 등)을 항상 병행.
- **타이포**: 데이터(프로세스명, pid, cmdline)는 전부 IBM Plex Mono. UI 라벨/헤더는
  IBM Plex Sans. 이 콘솔은 "코드를 읽는 도구"이므로 모노스페이스가 장식이 아니라 기능이다.
- **모션**: 온라인/격리 상태 점만 은은하게 펄스. 그 외 애니메이션 없음(`prefers-reduced-motion`
  존중). 경보가 뜰 때마다 요란하게 움직이면 진짜 경보 상황에서 오히려 방해가 된다.

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
