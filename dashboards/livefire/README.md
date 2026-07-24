# Live Fire Dashboard (프론트엔드)

## 디자인 방향 (02번 문서 그대로 실현)

전술 지휘통제(command-center) HUD. Red팀/Blue팀 대립을 색으로 인코딩하되 항상 텍스트/아이콘
병행(접근성):
- **팔레트**: 베이스 `#0A0E1A`, 패널 `#111725`, 보더 `#1E2A3F`. Red `#F5A623`(앰버)/`#FF4D4D`(경보),
  Blue `#22D3EE`(시안), 유출경보 `#E84BC9`(마젠타), 복구 `#34D399`.
- **타이포**: 헤더/라벨은 Rajdhani(전술 지오메트릭 느낌), 데이터(자산명/이벤트/점수)는
  JetBrains Mono.
- **시그니처**: AssetMap의 실시간 피격 펄스 애니메이션 하나에 모션을 집중(그 외는 절제).
  DMZ→자산 연결선이 공격 중일 때만 흐르는 점선 애니메이션으로 활성화.

## 구조 (23번 문서 그대로)

```
src/
├─ api/{types,client}.ts       # 백엔드 4개 서비스(Event Collector/Scoring/Config/Instructor) 연동
├─ store/rangeStore.ts         # zustand: 이벤트버퍼(500건)/자산상태 파생/역할/일시정지
├─ components/
│  ├─ AssetMap/AssetMap.tsx    # SVG 자산지도(시그니처 컴포넌트)
│  ├─ Timeline/EventTimeline.tsx
│  ├─ Score/ScoreBoard.tsx     # 카운트업 + 누적 스파크라인(라이브러리 없이 순수 SVG)
│  ├─ PatchStatus/PatchMatrix.tsx
│  ├─ FlagTracker/FlagList.tsx
│  └─ Instructor/InstructorConsole.tsx  # 시나리오 시작/종료, 점수조정, audit 조회
└─ App.tsx                      # 역할 스위처 + 3단 레이아웃
```

## 백엔드 연동 지점

- `WS /ws`(Event Collector 8010) — 실시간 이벤트, 지수 백오프 재연결
- `GET /events`(8010) — 최초 로드시 최근 이벤트로 자산상태 복원
- `GET /scores`, `/scores/history`(Scoring Engine 8020) — 3~5초 폴링
- `GET /config/patches`(Config Service 8030) — 5초 폴링
- `POST /instructor/*`(Instructor API 8050) — 전부 사유 필수, 실패 시 화면에 에러 노출

## 실행

(이 리포를 만든 개발 샌드박스는 npm 레지스트리 접근이 막혀 있어 `npm install`을 여기서
확인하지 못했다 — 실제 GCP 환경에서는 정상 설치될 것. TS/TSX 파일은 괄호 균형 등 정적
검사만 통과 확인했고, 타입체크는 `npm install` 후 `tsc -b`로 확인할 것.)

```bash
cd dashboards/livefire
npm install
VITE_EVENT_COLLECTOR_URL=http://localhost:8010 \
VITE_SCORING_ENGINE_URL=http://localhost:8020 \
VITE_CONFIG_SERVICE_URL=http://localhost:8030 \
VITE_INSTRUCTOR_API_URL=http://localhost:8050 \
npm run dev
```

## 역할 전환 (임시, MVP)

지금은 헤더의 역할 스위처 버튼으로 화면에서 직접 전환한다(인증 붙기 전까지의 임시 방편).
**주의**: Red 역할일 때 PatchStatus/FlagTracker를 프론트에서 숨기는 건 UX 편의일 뿐,
실제 정보 차단은 백엔드 인증(24번 문서 4절의 역할별 JWT 확장)이 붙어야 완전해진다 —
지금 상태에서 Red가 개발자도구로 API를 직접 호출하면 Blue 정보도 그대로 보인다.

## 다음 단계 (23번 문서 대비 남은 것)

- **Replay**: `GET /replay/events` 기반 배속 재생(useReplay 훅) — 아직 없음.
- **역할별 백엔드 스코프**: 위 "역할 전환" 항목 참고, 아직 프론트 전용.
- **AssetMap 상세 패널**: 노드 클릭 시 하단에 자산명만 표시 중, 해당 자산의 취약점/이벤트
  상세를 보여주는 패널로 확장 필요.
- **PatchMatrix의 checking 상태**: 토글 직후 낙관적 "checking" 표시(23번 문서 5절) 미구현,
  현재는 다음 폴링까지 이전 상태 그대로 보임.
