---
version: 1
slug: "dashboards-livefire-ops"
primary_target: "dashboards/livefire-ops"
related_targets: []
---

## Direction contract

THESIS: 이 서피스는 **국가 기반시설 라이브파이어 현황**을 소유한다 — 나라의 시설들이 공격받는 방사형
"현황" 아레나에서 타깃 시설로 드릴다운해 작전 콘솔로 조작한다. 거부하는 것: CTF 플래그제출 UI, 그리고
두 번 실패한 스킨(제너릭 SOC 패널 그리드 / AI 네온 사이버펑크 글로우).

OWN-WORLD: 플랫폼 다크 토큰 위의 **CCE 방송 작전 언어** — 딥 네이비 스페이스(#050a15/#091120),
**레드↔블루 듀얼리티**(레드=공격/Red-team, 시안/블루=방어/시스템), **브래킷 HUD**([ … ]+코너틱),
**타이머 3종**(TIME REMAINING·NEXT ATTACK·PATCH COUNT) LED 패널, 하어라인 보더 플랫 패널,
글로우/비네트/그레인/스캔라인 금지, 드로운 SVG 아이콘(이모지 금지). 서체: NanumSquare(한글 헤딩) +
JetBrains Mono(데이터) + Saira Condensed(라틴 액센트). 시그니처: 방사형 돔 아레나 + 시설 노드 성좌
(주황=공격중/시안=방어/초록=패치/레드=활성타깃+링) + 레이더 스윕.

STORY: 작전자는 11섹터가 라이브파이어 받는 현황(아레나)을 보고 → 타깃 시설 노드를 골라 → 그 시설의
작전 콘솔(OT 침투맵 + 시설별 물리 트윈: 발전소=단선도·터빈·레지스터 / 병원=바이탈·펌프·PACS /
상수도=펌프·배수지)로 드릴다운 → 킬체인(자격증명→측면이동→목표) 실행 → 실 트윈 물리/이벤트가 실제로
움직임 → 스코어·Solve Log·타이머가 확인.

FIRST VIEWPORT (현황 아레나): 상단 타이틀바(CCE 브랜드 + ROUND/SECTORS/LIVE); 중앙 방사형 돔 아레나 +
시설 노드 성좌 + 활성타깃 링; 좌상단 타이머3종 오버레이; 좌하단 스코어보드 TOP5; 우측 Solve Log;
하단 active-strike 티커. 1차 액션 = 시설 노드 선택(→ 시설 콘솔 드릴다운).

FORM: CCE식 방사형 라이브파이어 현황 보드 + 플랫 시설별 작전 콘솔; 사용자 제공 CCE 2025 Live Fire
레퍼런스 + EVE/Tulip/GridEx 조사에서 파생. Position: 사용자-핀 방향(roll보다 우선). seed: none (unavailable)

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
