# 구축 환경 가이드 — GCP + Claude Code로 실제 빌드하기

> 다음 주 실제 빌드 세션을 위한 실행 가이드. "어떤 환경에, 어떻게 준비하고, 어떤 순서로
> Claude Code에 시킬지"를 구체적으로 정리했다.

---

## 1. 서버 사양 (재확인 + 이번 프로젝트 반영)

지금까지 EDR·Config Service·Ansible 패치 콘솔까지 추가되면서 컴포넌트가 더 늘었다.
개발/빌드 단계와 실제 운영 단계를 나눠서 잡는 걸 추천한다.

### 1.1 빌드/개발용 (Claude Code가 직접 작업할 머신)

**`e2-standard-8` (8 vCPU / 32GB RAM) / 100GB SSD** 권장.

이유:
- Claude Code + Docker Compose로 10개 가까운 서비스(트윈 3 + event_collector + scoring_engine +
  config_service + edr_backend + noc_monitor + EDR 콘솔 dev server)를 동시에 띄우고 재빌드를
  반복하게 된다.
- `docker compose up --build`를 여러 번 반복할 것이므로 이미지 빌드 캐시가 쌓여 디스크를 예상보다
  빨리 먹는다 — 32GB RAM, 100GB면 여유 있게 작업 가능.
- Claude Code 자체는 가볍지만, 여러 서비스의 로그를 동시에 보면서 디버깅할 때 메모리 여유가
  작업 속도에 직결된다.

### 1.2 이후 실제 훈련/시연용 (필요시 별도 인스턴스로 분리)

이전에 답변드린 규모별 표 그대로 유효:
- 개발/데모: 4 vCPU / 8GB
- 소규모 훈련(1~4팀): 8 vCPU / 16GB
- 본격 대회(8~16팀): 16~32 vCPU / 64GB, 다중 노드 권장

**지금 단계에서는 1.1의 빌드용 인스턴스 하나로 충분하다.** 실제 훈련을 돌릴 때 별도 인스턴스로
승격하면 된다.

---

## 2. GCP 인스턴스 준비

```bash
# 이미지: Ubuntu 24.04 LTS 권장 (Docker 공식 설치 스크립트가 가장 안정적으로 도는 배포판)
gcloud compute instances create cyber-range-build \
  --zone=asia-northeast3-a \
  --machine-type=e2-standard-8 \
  --image-family=ubuntu-2404-lts-amd64 \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=100GB \
  --boot-disk-type=pd-ssd
```

**방화벽**: 빌드 단계에서는 외부 포트를 열 필요가 없다(SSH만). 대시보드/콘솔을 브라우저로
확인하려면 SSH 터널로 충분하다:
```bash
gcloud compute ssh cyber-range-build -- -L 8001:localhost:8001 -L 8010:localhost:8010 \
  -L 8020:localhost:8020 -L 8030:localhost:8030 -L 8080:localhost:8080 -L 5173:localhost:5173
```
(포트가 늘어날 때마다 `-L`만 추가하면 됨. 굳이 GCP 방화벽 룰을 열어 외부 노출할 필요 없음 —
어차피 트윈들은 의도적으로 취약하므로 인터넷에 노출하면 안 된다.)

---

## 3. 서버 안 소프트웨어 준비

```bash
# 1) Docker + Compose plugin
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

# 2) Python 3.11+ (Ubuntu 24.04는 기본 3.12 포함)
python3 --version   # 3.11+ 확인
sudo apt-get install -y python3-pip python3-venv

# 3) Node.js 20 LTS (EDR 콘솔 프론트엔드 빌드용)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# 4) Ansible (패치 콘솔용)
sudo apt-get install -y ansible

# 5) Claude Code CLI
#    - 이미 GCP 환경에 npm 커스텀 글로벌 prefix로 설치해두신 방식 그대로 사용
npm install -g @anthropic-ai/claude-code   # 실제 패키지명은 설치 시점 문서 확인

# 6) tmux (세션 유지 - 모바일 Termius로 접속하는 기존 워크플로우와 동일)
sudo apt-get install -y tmux
```

**psutil 빌드 의존성** (EDR 에이전트가 컨테이너 안에서 psutil을 쓰므로, 컨테이너 이미지에도
필요하지만 로컬 개발 편의를 위해 호스트에도):
```bash
sudo apt-get install -y gcc python3-dev
```

---

## 4. 리포지토리 구성 (통합 작업 — Claude Code에게 가장 먼저 시킬 일)

지금까지 코드가 두 곳에 나뉘어 있다 (`cyber-range/`, `cyber-range-contracts/`). **첫 세션에서
가장 먼저 할 일은 이 둘을 17번 문서 구조로 통합하는 것**이다.

```bash
mkdir -p ~/cyber-range-platform && cd ~/cyber-range-platform
git init
mkdir -p contracts platform siem dashboards scenarios challenges infra docs
```

Claude Code에게 줄 첫 프롬프트(예시):
```
/mnt/user-data/uploads 아래에 cyber-range.zip과 cyber-range-contracts.zip을 올려뒀어.
17_repo_structure_and_impl.md 문서 구조대로 두 압축을 풀어서 하나의 리포로 합쳐줘.
platform/ 디렉토리명은 python의 platform 모듈과 충돌하니 services/로 유지해줘.
import 경로가 깨지는 부분(사실상 shared.* 계열)은 전부 고치고, 문법 검증까지 해줘.
```

이 통합 작업이 끝나야 이후 모든 `docker-compose.yml` 빌드 컨텍스트가 단순해진다
(`INTEGRATION.md`에 있던 "두 리포를 형제 디렉토리로" 방식은 임시방편이었다).

---

## 5. 빌드 순서 (마일스톤 — 이 순서로 Claude Code에 세션을 나눠 진행 권장)

### M0 — 통합 + 계약 검증 (반나절)
- 4절의 리포 통합
- `pip install -r requirements.txt` (contracts + cyber-range 양쪽 병합)
- `python tests/test_contracts.py` 통과 확인 — **이게 실패하면 다음 단계로 넘어가지 말 것**
- `python infra/ci/secret_scan.py --path .` 통과 확인

### M1 — 코어 플랫폼 기동 (반나절~1일)
- `docker compose up --build` 로 트윈 3종 + event_collector + scoring_engine + config_service +
  edr_backend까지 전부 뜨는지 확인
- 스모크 테스트:
  ```bash
  curl localhost:8001/health && curl localhost:8002/health && curl localhost:8003/health
  curl localhost:8010/health && curl localhost:8020/health
  curl localhost:8030/health && curl localhost:8080/health
  ```
- `python shared/safe_probe.py` 로 취약점 5+5+4종이 전부 vulnerable로 나오는지 확인
- Config Service 패치 토글 → 트윈이 5초 내 반영하는지 확인(이전 대화의 curl 예시 그대로)

### M2 — EDR + Config Service 연동 검증 (반나절)
- `curl localhost:8080/edr/hosts` 로 3개 트윈이 online으로 잡히는지
- PP-003 커맨드인젝션 curl 시연 → `curl localhost:8080/edr/alerts` 에 EDR-001/002 알림 확인
- Isolate 액션 테스트 → 해당 트윈이 503 반환하는지 확인

### M3 — 시나리오 엔진 (1일)
- `scenarios/single/*.yaml` 로드 테스트
- 단일 킬체인 시나리오 하나를 curl로 순서대로 공격해서 stage_completed 이벤트와 chain_bonus가
  올바르게 나오는지 확인

### M4 — EDR 콘솔 프론트엔드 (반나절)
```bash
cd services/edr/console
npm install       # 이제 실제 네트워크 있는 환경이라 정상 설치됨
npm run dev
```
- SSH 터널로 `localhost:5173` 접속해 호스트 목록/프로세스 트리/알림이 실제로 뜨는지 확인
- Isolate/Kill 버튼 실제 동작 확인

### M5 — SIEM 코어 (01번 문서, 아직 코드 없음 — 다음 큰 작업)
- Ingestion(syslog 서버) + 트윈 구조화 로그 파서부터 시작
- 이 프로젝트에서 가장 큰 미착수 영역이므로 별도 세션으로 분리 권장

### M6 — 대시보드(Live Fire, NOC) 프론트엔드
- 02·07번 문서 기반, EDR 콘솔과 톤은 다르게(전술 HUD 계열)

---

## 6. Claude Code 세션 운영 팁 (기존 워크플로우 기반)

- **tmux 세션 분리**: `tmux new -s build` 로 메인 세션, 필요시 `docker compose logs -f` 를
  별도 tmux 창(`Ctrl+b c`)에서 계속 띄워두고 Claude Code가 작업하는 동안 실시간으로 로그 확인.
- **09번 문서(팀 에이전트 역할)를 매 세션 시작 시 첨부**: Claude Code에게 "지금 B2(Platform
  Backend Engineer) 역할로 작업해줘, 담당 범위는 services/core, services/config_service야"처럼
  역할을 명시하면 범위 이탈 없이 작업한다.
- **한 세션 = 한 마일스톤**: 위 M0~M6을 세션 단위로 끊어서 진행. 매 세션 끝에 "이 마일스톤의
  DoD(각 문서 맨 아래 Definition of Done)를 실제로 curl/pytest로 확인해줘"까지 시켜서 다음
  세션으로 넘어가기 전에 검증을 끝내둘 것.
- **INSTRUCTOR_TOKEN 등 비밀값**: `.env` 파일 하나로 관리하고 `.gitignore`에 추가.
  ```bash
  echo "INSTRUCTOR_TOKEN=$(openssl rand -hex 16)" > .env
  echo ".env" >> .gitignore
  ```
- **한글 IME 이슈**: 기존에 겪으신 터미널 한글 입력 문제는 Claude Code 자체 대화에는 영향
  없음(웹/앱 인터페이스로 프롬프트 작성 시). SSH 터미널에서 직접 vi/nano로 파일 편집할 때만
  해당하므로, 가능하면 파일 편집은 Claude Code에게 맡기고 터미널은 명령 실행/로그 확인 용도로만.

---

## 7. 흔히 막히는 지점 (미리 대비)

| 증상 | 원인 | 대응 |
|---|---|---|
| `docker compose up` 시 `platform` 모듈 관련 import 에러 | 통합 과정에서 디렉토리명이 `platform/`으로 되돌아감 | `services/`로 통일했는지 확인(README에 명시된 이슈) |
| EDR Agent가 프로세스를 못 봄(process_count=0) | 컨테이너 기본 권한 문제 | Dockerfile에 `psutil` 설치 확인, 컨테이너가 자기 자신의 pid 네임스페이스 안 프로세스는 기본적으로 보임 — 안 보이면 psutil 설치 여부 우선 확인 |
| Config Service 토글해도 트윈이 안 바뀜 | ConfigClient 폴링 주기(4초) 전이거나 CONFIG_SERVICE_URL 오타 | 5~10초 대기 후 재확인, docker-compose의 환경변수 오타 확인 |
| npm install이 403/네트워크 에러 | 이 문서 작성 환경(샌드박스)과 달리 실제 GCP엔 네트워크가 있으니 정상 설치돼야 함 — 방화벽 이슈면 GCP의 egress 규칙 확인 | `curl https://registry.npmjs.org` 로 사전 확인 |
| psutil 컴파일 실패 | gcc/python3-dev 미설치 | 3절의 빌드 의존성 설치 |

---

## 8. 다음 주 진행 순서 요약 (체크리스트)

```
[ ] GCP e2-standard-8 인스턴스 생성 (asia-northeast3 등 원하는 리전)
[ ] Docker, Python, Node, Ansible, Claude Code CLI, tmux 설치
[ ] cyber-range.zip / cyber-range-contracts.zip 업로드
[ ] Claude Code 세션 1: 리포 통합(4절) + M0 계약 검증
[ ] Claude Code 세션 2: M1 코어 플랫폼 기동 + 스모크 테스트
[ ] Claude Code 세션 3: M2 EDR 연동 검증
[ ] Claude Code 세션 4: M3 시나리오 엔진
[ ] Claude Code 세션 5: M4 EDR 콘솔 프론트엔드 (npm install 정상 동작 확인)
[ ] 이후: M5(SIEM) / M6(대시보드) 별도 스프린트로 분리
```
