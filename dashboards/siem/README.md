# SIEM Dashboard (프론트엔드)

## 디자인 방향

**CYBER RANGE COMMAND SYSTEM 공유 디자인 시스템**(`@cyber-range/command-system`)을 채택했다.
독자 Tailwind 팔레트를 제거하고 공유 토큰(`tokens.css`)·컴포넌트(`Panel`·`StatusBadge`·
`EmptyState`·`ErrorState`·`Button`·`WorkspaceBar`)로 통일해 Command Tower·다른 워크스페이스와
같은 시각 언어를 쓴다. SIEM 고유 레이아웃(분석가 셸·로그 툴바·탐지/커버리지 리스트)만
`src/index.css`에 공유 토큰 기반으로 남겼다(하드코딩 색상 0).

- **심각도(보존)**: 숫자 0~4와 라벨 INFO/LOW/MEDIUM/HIGH/CRITICAL·필터 임계값(2/3/4)은 그대로.
  색상만 공유 톤으로 매핑(`severity.ts`의 `severityTone`): INFO→neutral·LOW→operational·
  MEDIUM→intelligence·HIGH→warning·CRITICAL→critical (5단계 모두 구분됨).
- **동작 보존**: 전송 계층(`api/client.ts`·`types.ts`)은 그대로 — 폴링 주기(알림/소스 5s·
  커버리지 15s)·WS 재연결 백오프·베이스URL 해석·탐지 라이프사이클(open→ack→closed).
- **테스트**: `severity.test.ts`(순수 매핑) + `dashboard.test.tsx`(뷰 통합, vitest+testing-library).
  CI specialist-dashboards 잡이 `npm run test --if-present`로 자동 실행.

## 구조

```
src/
├─ api/{types,client}.ts   # SIEM API(8040) 연동, WS 알림/로그 스트림
└─ components/
   ├─ Discover/            # 전문검색 + 필터(소스/심각도) 로그 테이블
   ├─ Alerts/               # 알림 목록 + 상태 변경(open/ack/closed)
   ├─ SourceHealth/         # 소스별 최종수신시각/상태
   └─ AttackCoverage/       # MITRE ATT&CK 기술별 탐지 커버리지
```

## 실행

(EDR/Live Fire와 동일하게 이 개발 샌드박스는 npm 레지스트리가 막혀 있어 `npm install`을
확인 못했다 — 실제 GCP 환경에서 정상 설치될 것.)

```bash
cd dashboards/siem
npm install
VITE_SIEM_API_URL=http://localhost:8040 npm run dev
```

## 다음 단계

- Alerts의 mitre 필드는 백엔드가 JSON 문자열로 저장하므로 프론트에서 매번 파싱한다 —
  백엔드에서 배열로 직접 내려주도록 API 응답 포맷을 개선하면 더 깔끔해진다.
- Discover에 시간 범위 필터(time_from/time_to)가 아직 없음 — SearchQuery는 이미 지원하므로
  UI만 추가하면 됨.
