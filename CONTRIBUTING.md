# 기여 가이드 (Contributing)

## 개발 환경
```bash
cp .env.example .env && ./scripts/gen_secrets.sh   # 시크릿 생성
docker compose up -d                               # 코어 스택
# 대시보드(dev): 각 dashboards/*/ 및 services/edr/console 에서 npm install && npm run dev
```

## 필수 검증 (PR 전에 로컬에서 반드시 통과)
```bash
python3 -m pytest tests/ -q                         # 백엔드/계약 유닛 테스트
bash infra/challenge_qa/run_all.py 또는 scripts/validate_challenges.sh   # 챌린지 QA
bash scripts/smoke_test.sh                           # 통합 스모크(도커 스택 필요)
(cd dashboards/livefire && npm test && npm run build)  # 프론트 유닛/빌드
```
CI(`.github/workflows/ci.yml`)가 unit/challenges/dashboard/integration 4잡을 돌립니다. **깨진 채로
PR 금지.**

## 작업 규칙 (세션 규칙에 준함)
- 한 번에 한 논리 단위. 커밋을 작게 쪼개고 **커밋 메시지에 근거**를 남긴다.
- 변경 전 관련 **테스트를 먼저** 쓰고(실패 확인) 구현한다.
- **계약(스키마/엔드포인트)을 바꾸면 같은 커밋에서 `CONTRACTS.md`를 갱신**한다.
- README/문서에 기능을 적을 때는 **실제 실행 출력**을 근거로만("구현했다"가 아니라 "실행하면 이렇게").
- `scripts/smoke_test.sh`와 챌린지 QA가 계속 통과해야 한다. 깨지면 그 자리에서 고치거나 롤백.

## 새 챌린지 추가
`challenges/<category>/<ID>/`에 `challenge.yaml` + `deploy/`(생성기) + `grader/`(red_grader.py 또는
blue_grader.py) + `writeup.md`. 검증: `python3 infra/challenge_qa/schema_validate.py --challenge <ID>`
와 artifact_solve/detection_solve. 팀별 HMAC 동적 플래그를 쓴다(정답 공유 방지).

## 새 트윈/섹터 추가
`shared/ics_twin.py`의 `make_ics_twin` 팩토리로 섹터 트윈을 만들고, `safe_probe.py`·SIEM 규칙·
`vuln_catalog.json`을 함께 갱신한다.
