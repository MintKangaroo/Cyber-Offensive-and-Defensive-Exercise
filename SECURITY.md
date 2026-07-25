# 보안 정책 (Security Policy)

## ⚠️ 이 저장소는 의도적으로 취약합니다

Cyber Range Platform은 **공격·방어 훈련용**으로, **의도적으로 취약한 서비스**(SQLi/RCE/명령주입/
SSRF/인증우회/OT 사보타주 등 60여 종)와 **하드코딩된 기본 자격증명**을 포함합니다.

> **절대 인터넷/신뢰되지 않은 네트워크에 노출하지 마세요.**
> 격리된 훈련 네트워크(폐쇄망, 랩 VLAN, 로컬 VM, Tailscale tailnet 등)에서만 실행하세요.

### 안전 운영 수칙
- 트윈은 `internal:true` 네트워크로 egress·cross-team 차단(설계). `range_control` `GET /safety/status`
  로 containment를 확인하세요.
- 프로덕션 실행 시 `.env`에 **모든 토큰을 설정**하고(`OBSERVER_READ_ENFORCE=true`) dev 무인증
  경로를 닫으세요(`./scripts/gen_secrets.sh`).
- `.env`/시크릿을 커밋하지 마세요(`.gitignore` 처리됨).
- 훈련 종료 후 `range_control /ranges/{id}/reset` 으로 초기화하세요.
- 공용 클라우드에 띄운다면 방화벽/보안그룹으로 접근을 화이트리스트하세요.

## 취약점 신고 (플랫폼 자체의 비의도적 취약점)
훈련용으로 **의도된** 취약점이 아니라, 플랫폼 코드/인프라 자체의 **비의도적** 보안 문제
(예: 격리 우회, 인증 우회, 컨트롤 플레인 RCE, 시크릿 유출)를 발견하면:

1. **공개 이슈로 올리지 마세요.**
2. 저장소 관리자에게 비공개로 연락하거나 GitHub Security Advisory(비공개)로 신고하세요.
3. 재현 절차·영향·가능하면 패치 제안을 포함해 주세요.

의도된 취약점과 비의도된 취약점을 구분하려면 `shared/vuln_catalog.json`(의도된 취약점 카탈로그)을
참고하세요. 여기에 없는 취약점이 플랫폼을 위협한다면 신고 대상입니다.

## 지원 범위
최신 `main` 브랜치만 보안 수정을 받습니다.
