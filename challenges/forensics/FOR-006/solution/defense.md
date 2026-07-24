# FOR-006 방어 노트 (Blue)

## 무슨 일이 있었나
공격자가 crontab에 `*/5 * * * * curl ... | bash` 항목을 심어 5분마다 C2에서 페이로드를
받아 실행하는 지속성을 확보했다(ATT&CK **T1053** Scheduled Task/Job).

## 탐지
- **cron 무결성 감시**: `/etc/crontab`, `/etc/cron.*`, 사용자 crontab 변경을 FIM으로 모니터링.
- **의심 패턴**: cron 명령에 `curl|bash`, `wget|sh`, base64 디코드, 외부 도메인 호출.
- 아웃바운드 이벤트와 상관: cron 실행 시각에 맞춘 주기적 외부 접속.

## 완화
- cron/at 편집 권한 최소화, 무결성 기준선(baseline) 관리.
- egress 필터링으로 페이로드 다운로드/콜백 차단, 알려지지 않은 도메인 차단.
