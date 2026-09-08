# WEB-025 방어 — SSRF(클라우드 메타데이터) 차단

## 취약점
인스턴스 상태 수집기가 사용자 URL 을 목적지 검증 없이 서버가 대신 fetch 한다. 공격자가
`http://127.0.0.1:8131/latest/meta-data/iam/security-credentials/<role>`(또는 169.254.169.254 의
IMDS)를 지정하면 서버가 대신 호출해 IAM 임시 자격증명(flag)이 유출된다.

## 패치 (`PATCH_WEB_025=true`)
- fetch 대상 호스트를 DNS 해석 후 **루프백/사설/링크로컬(169.254.0.0/16)/예약 대역이면 거부**.
- 메타데이터 접근은 IMDSv2(토큰 필수)·hop-limit·네트워크 정책으로 이중 차단, 허용 도메인 allowlist.

## 탐지 관점(blue)
- 수집 파라미터가 169.254.169.254·metadata.google.internal·루프백을 가리키는 요청 경보.
