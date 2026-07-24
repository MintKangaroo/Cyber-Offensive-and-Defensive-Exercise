# SIEM Dashboard (프론트엔드)

## 디자인 방향

Live Fire(전술 HUD)·EDR(터미널 SOC)과 톤을 의도적으로 다르게 잡았다 — SIEM은
"정보 밀도가 최우선인 로그 분석 도구"다. 화려한 애니메이션 대신 표/리스트 밀도와
스캔 속도에 집중.

- **팔레트**: 베이스 `#0A1119`, 패널 `#0E1620`, 보더 `#22303F`. 심각도는
  info `#5FA8D3` → medium `#D9A441` → high `#E0703A` → critical `#D64545`, 정상 `#3FBF7F`.
- **타이포**: IBM Plex Mono(데이터) + IBM Plex Sans(라벨). Live Fire의 Rajdhani, EDR의
  JetBrains Mono와 겹치지 않게 폰트 자체도 구분.

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
