# NET-005 방어 노트 (Blue)

## 무슨 일이 있었나
공격자가 닫힌 포트들을 정해진 순서로 두드려(port knocking) 숨겨진 SSH 접근을 열었다
(ATT&CK **T1205** Traffic Signaling). 방화벽 로그에는 보호 포트 접속 직전 일련의 drop이 남는다.

## 탐지
- **drop→allow 상관**: 한 IP가 짧은 시간에 닫힌 포트 여러 개(drop)를 순서대로 친 직후 보호
  포트에 성공 접속(allow)하면 노킹 의심.
- 비정상 포트 스윕과 달리 **정해진 순서**가 반복되면 노킹 시그니처.

## 완화
- 노킹 같은 "security by obscurity" 대신 **Single Packet Authorization(SPA)** + MFA VPN 사용.
- 관리 포트는 기본 비노출(제로트러스트), 접근은 인증 게이트웨이 경유.
