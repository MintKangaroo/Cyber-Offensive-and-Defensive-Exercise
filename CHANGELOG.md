# 변경 이력 (Changelog)

형식: [Keep a Changelog](https://keepachangelog.com/), 버전: [SemVer](https://semver.org/).

## [Unreleased]
### Added
- **P0-3 영속성**: event/scoring/config/siem/edr/instructor/noc/portal/range_control 상태를 named
  볼륨(`DATA_DIR=/data`)으로 백업 → force-recreate/crash-replace 생존. 크래시복구 스모크
  (`SMOKE_CRASH_RECOVERY=1`) 추가.
- **저장소 위생**: LICENSE(Apache-2.0), SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, `.env.example`,
  `scripts/gen_secrets.sh`.
- **실전 운영(P1 #9/#10/#11)**: Range Control 서비스(8055) — Match 레지스트리·Reset/Snapshot/
  Drift/Verify-Baseline·Safety Control(긴급정지·격리 상태). 교관 콘솔 UI.
- **멀티테넌트**: 매치별 물리 트윈 셋(11섹터, `deploy_match.sh`)·매치별 플래그 회전·관전자 지연
  큐(`/events/delayed`)·매치 vhost(`match_proxy` 8088). (docs/MULTI-TENANT.md)
- **Red/Blue Portal**: 챌린지 목록·아티팩트·제출·채점·스코어보드·CTF 시각화. 팀 드롭다운.
- **챌린지**: BACnet/Foundation Fieldbus/EtherNet-IP·CIP/S7comm/MQTT-Sparkplug red+blue(69종,
  12대 OT 프로토콜). ProcessImpact 패널·vitest.
- **문서**: docs/GAP_ANALYSIS.md(코드 실측 갭 분석), docs/writeups/(공방 가이드·답지), docs/TEAMS.md.

### Fixed
- 원격 접속(WSL/Tailscale): 대시보드 hostname 기반 백엔드 연결 + CORS 확장.

## [1.0.0] - 이전
- 초기 플랫폼: 11 ICS/OT 섹터 트윈·EDR·SIEM·시나리오 엔진·Live Fire·AAR·RBAC·CTF 챌린지.
