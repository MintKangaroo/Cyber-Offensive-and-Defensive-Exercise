# 인수인계 — Windows Claude Code 로 이어가기

**작성일**: 2026-11-17 · **대상**: 이 저장소를 Windows 의 Claude Code 에서 계속 작업할 다음 세션.
**현재 머신**: WSL2(Linux) 에서 개발해 옴. 운영 지침의 권위는 여전히 [`CLAUDE.md`](CLAUDE.md) 다 — 그 절대
규칙(실행해서 확인·실패 숨기지 않기·UNVERIFIED 표기·메모리 제약·결함1=브랜치+회귀테스트·feature→PR→CI
green→squash merge)은 플랫폼과 무관하게 그대로 적용된다. 이 문서는 **Windows 이전 시 달라지는 부분만** 다룬다.

---

## 0. 현재 상태 한눈에 (이 문서 작성 시점)

- 브랜치 `main`, HEAD `ba05e20`, **열린 PR 0개**, CI 14잡 green.
- 백엔드 테스트 **905 passed / 6 skipped**(skip = PostgreSQL HA, 로컬 DB 없음 — CI 는 postgres 로 통과).
- `dashboards/livefire-ops` vitest **52 passed**, `tsc --noEmit` OK.
- 라이브파이어 작전 콘솔(`dashboards/livefire-ops`)의 **모든 라이브 축 E2E 검증 완료**(상세: 그 폴더 README).
- **남은 후보 1개**: 48~72h 정식 소크(환경 바운드 — 장시간 실행 필요, 코드로 완결 불가).

> 이 저장소 자체(코드·`CLAUDE.md`·`HANDOFF.md`·각 README)는 git 으로 Windows 에 그대로 따라온다.
> 아래 **§1 가 가장 중요** — 안 따라오는 것, 그리고 깨지는 것.

---

## 1. ⚠️ 따라오지 않는 것 / 깨지는 것 (먼저 읽기)

### 1-1. Claude Code 자동 메모리는 **머신 로컬** — 안 따라온다
지난 세션들의 상세 이력(#122~#155, 라이브파이어 콘솔 전 과정)은 **이 Linux 머신의**
`~/.claude/projects/-home-mintkangaroo-Project-Cyber-offensive-Defense-Project/memory/` 에만 있다.
Windows 의 Claude Code 는 `%USERPROFILE%\.claude\...` 아래에 **프로젝트 경로가 달라 다른 해시 폴더**를 쓰므로,
새 세션은 이 이력을 **전혀 모른 채** 시작한다.

**가져가는 법 (택1)**:
- (권장) Windows 에서 이 프로젝트로 Claude Code 를 **한 번 실행**해 해당 `...\.claude\projects\<해시>\memory\`
  폴더가 생기게 한 뒤, 위 Linux `memory/` 폴더의 `*.md` 파일을 그 안으로 복사한다.
- 또는 복사하지 않아도 된다 — **이 문서 + [`CLAUDE.md`](CLAUDE.md) + [`HANDOFF.md`](HANDOFF.md) + 각
  README 가 핵심 맥락을 담고 있어** 새 세션이 "맹인"으로 시작하진 않는다. 메모리는 편의일 뿐 권위가 아니다
  (권위 = 코드·테스트·`audit/100~103`·`CLAUDE.md`·README).

### 1-2. `.gitattributes` 가 없다 → bash 스크립트 **CRLF 오염 위험**
저장소에 `.gitattributes` 가 없고 `scripts/`·`infra/` 에 bash 스크립트가 6개 있다(`smoke_test.sh`,
`validate_challenges.sh`, `loadtest/soak/run_soak.sh` 등). Windows git 기본 `core.autocrlf=true` 로 클론하면
이 스크립트들이 **CRLF 로 바뀌어 `bash: \r` 오류**로 깨진다.

**예방 (클론 전에)**:
```powershell
git config --global core.autocrlf input    # 체크아웃 시 LF 유지
```
이미 클론했고 깨졌다면: `git config core.autocrlf input` 후 `git rm --cached -r . && git reset --hard`.
근본 해결로 리포에 `.gitattributes`(`*.sh text eol=lf` 등)를 추가하는 PR 을 내는 것도 좋다(미완 과제).

### 1-3. 셸: **WSL2 또는 Git Bash 를 쓸 것** (PowerShell/cmd 는 마찰 큼)
이 프로젝트의 검증 워크플로는 bash 전제다(heredoc, `until … sleep` 루프, `make`, `*.sh`, 인라인
`VAR=val cmd`). 가장 매끄러운 순서:
1. **(최선) Windows 의 WSL2 안에서 Claude Code 실행** — 지금까지의 환경과 동일. 거의 아무것도 안 바뀐다.
2. **(차선) 네이티브 Windows + Git Bash** 를 Claude Code 셸로 사용 — 대부분의 bash 명령이 동작.
3. PowerShell/cmd 단독 — heredoc·`pkill`·`free`·`ss`·`until` 루프가 전부 깨짐. 권장하지 않음.

---

## 2. 명령 변환표 (네이티브 Windows 에서 필요할 때)

| 용도 | 지금까지(Linux/WSL) | 네이티브 Windows |
|---|---|---|
| 파이썬 | `python3 -m …` | `python -m …` 또는 `py -3 -m …` |
| 테스트 | `python3 -m pytest tests/ -q` | `python -m pytest tests/ -q` (동일) |
| 메모리 확인 | `free -h` | WSL 이면 그대로. 네이티브는 작업관리자 / `systeminfo` |
| 포트 점유 확인 | `ss -ltnp \| grep :8206` | `netstat -ano \| findstr :8206` |
| 프로세스 찾기 | `pgrep -af uvicorn` | `tasklist \| findstr python` |
| 프로세스 종료 | `pkill -f "uvicorn services.X"` | `netstat -ano\|findstr :PORT` 로 PID 찾고 `taskkill /F /PID <PID>` |
| 인라인 환경변수 | `MODBUS_PORT=15206 VAR=y uvicorn …` | PowerShell: `$env:MODBUS_PORT=15206; uvicorn …` / Git Bash: 동일 |
| 대기 루프 | `until ! gh pr checks N \| grep pending; do sleep 20; done` | Git Bash 필요(PowerShell 불가) |

> **포트/메모리 규율은 그대로**: 검증할 때만 필요한 포트 하나(또는 작은 번들)를 잠깐 올리고 **즉시 내린다**.
> OOM 위험 보이면 멈추고 보고. 트윈을 `MODBUS_ENABLED=1` 로 띄울 땐 `MODBUS_PORT` 를 비표준(예: 15206)으로
> 줘 502 바인드 충돌을 피한다(게이지 sim loop 는 502 바인드 실패해도 돈다).

---

## 3. 최초 셋업 (Windows, WSL2 권장 기준)

```bash
# 1) 저장소 (이미 있으면 생략). CRLF 예방 설정을 먼저:
git config --global core.autocrlf input
git clone <this-repo-url>            # 원격: GitHub MintKangaroo/Cyber-Offensive-and-Defensive-Exercise
cd cyber-range-platform              # 작업 루트(= 이 문서가 있는 폴더)

# 2) 파이썬 의존성 (python 3.10+; 지금까지 3.10.12)
python3 -m pip install -r requirements.txt -r requirements-dev.txt

# 3) 대시보드 의존성 (node 18+; 지금까지 node 22 / npm 10). 각 대시보드 폴더에서:
cd dashboards/livefire-ops && npm ci && cd -

# 4) gh CLI 인증 (PR 워크플로용)
gh auth login

# 5) Docker Desktop (WSL2 백엔드 권장) — 풀스택/통합 E2E 용. 평소엔 미기동.
```

### 검증 명령 (`CLAUDE.md` 와 동일, 플랫폼 무관)
```bash
python3 -m pytest tests/ -q                       # 백엔드 유닛+계약 (도커 불필요) → 905 passed / 6 skip
bash scripts/validate_challenges.sh               # 챌린지 130종 (bash 필요)
cd dashboards/livefire-ops && npm test && npx tsc --noEmit   # 콘솔 vitest + 타입체크
make rehearsal   # 무인 리허설(서브셋 기동→완주); 끝나면 make rehearsal-down   (bash/make 필요)
```
라이브파이어 콘솔 E2E 재현(번들 띄워 실제 공방 확인)하는 구체 명령은 `dashboards/livefire-ops/README.md` 참조.

---

## 4. 작업 규율 (재확인 — `CLAUDE.md` 권위)

- **실행해서 확인**. "될 것 같다" 금지. 모든 판정에 명령+출력 근거. 검증 안 된 건 UNVERIFIED 로 표기.
- **결함 1건 = 브랜치 1개 + 회귀테스트 ≥1**. `main` 직접 푸시·태그·강제 푸시는 승인 후에만.
  워크플로: feature 브랜치 → 커밋 → push → `gh pr create` → **CI green** → `gh pr merge --squash`.
- **메모리 제약**: 전체 스택(75+ 컨테이너)을 한 번에 올리지 않는다. 필요한 서비스 묶음만 잠깐 up→down.
- 커밋/PR 꼬리표(Co-Authored-By / Claude-Session / Generated with…)는 **세션마다 하네스가 주는 값**을 쓴다
  — 이 문서의 특정 세션 링크를 하드코딩하지 말 것.
- 다른 프로젝트(pentagi / Quant_RL_Trading 등)는 건드리지 않는다.

---

## 5. 지금까지의 작업 맥락 (이어받기용 요약)

현 최우선 스레드 = **Red 경험을 2단 CCE 라이브파이어로 재설계**(①방사형 현황 아레나 + ②시설별 작전 콘솔),
신규 서피스 `dashboards/livefire-ops`. 미감 = CCE 방송톤(네이비·레드/블루 듀얼·브래킷 HUD·타이머 3종·플랫).
SOC 모니터링 대시보드는 **별도 프로젝트** 담당(여기선 Blue 탐지·패치 메커닉만).

**콘솔 라이브 축 — 전부 E2E 검증 완료**(각 축 회귀 테스트로 고정):
- 물리 트윈 게이지: 발전소·수도·병원 풀 스트라이크 + 6확장 트윈 통일 텔레메트리. **확장 5섹터(LNG·철도·
  공항·데이터센터·스마트팩토리)도 `POST /api/command` 로 브라우저발 ACTUAL 게이지 파국까지 라이브**
  (2단 킬체인: lateral=cmd overdrive → objective=SIS BYPASS; 파국은 SIS 선-우회를 요구).
- 타이머 3종(`phase_clock` 1Hz) · 채점/스코어보드/Solve Log(Red 전경로 + Blue 전경로:
  patch_verified · detection_success **+dwell 보너스** · block_success · asset_recovered) · 다팀 스코어보드 ·
  아레나 활동량 stat(Patch Count·공격·방어 `scores` 집계).

**최근 세션(2026-11-09~17) 머지분**:
- `#152` (`e798d7f`) 탐지 dwell-time 보너스 라이브 — collector enrichment + scoring decay 2서비스 경로.
- `#153` (`2e9ee65`) 아레나 활동량 stat 라이브 배선(정적 가짜값 제거, 첫 프런트 결함 수정).
- `#154` (`b71d6e1`) 확장 트윈 `POST /api/command` 신설 → 브라우저발 ACTUAL 게이지 파국(승인 백엔드 기능).
- `#155` (`ba05e20`) 상위 README 현황 반영(문서).

**남은 것**:
- 48~72h 정식 소크(`SOAK_DURATION_SEC=28800 bash loadtest/soak/run_soak.sh` 외 장시간) — **환경 바운드**.
- (미완 과제 후보) `.gitattributes` 추가로 CRLF 영구 방지(§1-2).
- nuclear/telecom/satellite 는 통일 트윈 미존재 → 라이브 배선 없음(아레나 노드 표시만) — 의도된 한계.

---

## 6. 빠른 체크 (Windows 에서 처음 열었을 때)

1. `git status` → clean, `git log --oneline -1` → `ba05e20` 근처인지. `gh pr list` → 열린 PR 확인.
2. `python3 -m pytest tests/ -q` → **905 passed / 6 skip** 나오면 백엔드 OK.
3. `cd dashboards/livefire-ops && npm ci && npm test` → **52 passed** 나오면 콘솔 OK.
4. bash 스크립트가 `\r` 오류 내면 §1-2 (CRLF) 로.
5. 메모리 이력이 필요하면 §1-1 로 Linux 머신의 `memory/` 복사.
