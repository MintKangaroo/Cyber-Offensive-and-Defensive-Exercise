# Patch Console

Blue팀이 취약점을 Ansible 플레이북으로 "실제 운영처럼" 패치하는 콘솔.
자세한 설계는 `docs/19_ansible_patch_console_and_noc_spec.md` 참고.

## 구조

```
patch_console/
├─ inventory.yml            # 트윈 컨테이너만 대상(호스트 확장 금지)
├─ whitelist.py              # vuln_id -> playbook 명시적 매핑(경로조합 금지)
├─ playbooks/
│  ├─ patch_GS-001.yml       # 구현됨(예시)
│  ├─ patch_GS-002.yml       # 구현됨(예시, 시크릿 로테이션 포함)
│  └─ patch_*.yml            # 나머지 12개는 아래 패턴으로 동일하게 작성
└─ api/main.py                # FastAPI: /patch/apply /patch/status /patch/available
```

## 나머지 플레이북 작성 패턴

모든 `patch_*.yml`은 두 단계만 수행한다:
1. **대상 검증**: `docker inspect`로 컨테이너 라벨이 예상과 일치하는지 확인(오적용 방지).
2. **Config Service 호출**: `POST /instructor/patch/toggle`로 해당 asset·vuln_id를 patched=true로.

취약점별로 다른 점은 2단계 전에 넣는 "그럴듯한 연출" 태스크뿐이다(예: GS-002는 시크릿 로테이션
연출, PP-003은 subprocess 배열화 버전 배포 연출). 실제 안전 로직은 트윈 코드의 `patched()` 분기에
이미 구현되어 있으므로, 플레이북은 "그 경로를 켜는" 신호를 보내는 역할만 한다.

## 실행

```bash
pip install ansible ansible-runner fastapi uvicorn httpx
export INSTRUCTOR_TOKEN="<교관 토큰>"
uvicorn services.patch_console.api.main:app --port 8060
```

```bash
curl -X POST http://localhost:8060/patch/apply \
  -H "Content-Type: application/json" \
  -d '{"vuln_id":"GS-001","team_id":"team_alpha","reason":"SQLi patch after detection"}'
```

## 안전장치 체크리스트

- [ ] whitelist.py에 없는 vuln_id는 항상 400 (테스트: 임의 문자열/경로탈출 문자열로 확인)
- [ ] inventory.yml에 호스트 SSH 대상이 없음(컨테이너 connection만)
- [ ] Patch Console API는 Blue/교관 역할 토큰만 허용(Red 접근 차단)
- [ ] ansible-runner 실행이 infra/hardening 프로파일과 동일한 격리 컨테이너에서 수행
- [ ] 모든 실행이 patch_runs 테이블(audit)에 기록됨
