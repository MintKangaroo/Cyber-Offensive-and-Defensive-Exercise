# EDR 콘솔 (팔콘 스타일) — Claude Code 빌드 프롬프트

> Blue팀이 각 트윈("호스트")의 프로세스/네트워크 행위를 실시간으로 보고,
> 의심 프로세스를 탐지하고, 호스트를 격리(isolate)하는 EDR(Endpoint Detection & Response) 콘솔.
> CrowdStrike Falcon의 핵심 UX(센서 → 클라우드 콘솔 → 탐지 → 대응)를 훈련 규모로 재현한다.

---

## 1. 범위와 현실적 조정

풀사이즈 Falcon(커널 드라이버 센서, 클라우드 규모 그래프 DB, 위협 인텔 피드)을 그대로 만들 수는
없다. 대신 **핵심 UX 루프**를 그대로 가져온다:

```
경량 센서(Agent) → 프로세스/네트워크 텔레메트리 수집 → EDR 백엔드(클라우드 콘솔 역할)
   → 행위 기반 탐지(IOC/이상행위 룰) → 알림 → Blue팀이 프로세스 트리 확인 → 대응(격리/프로세스 종료)
```

각 트윈 컨테이너 = Falcon의 "호스트/센서 설치 대상"에 대응.

---

## 2. 아키텍처

```
Ground Station 컨테이너          Power Plant 컨테이너         Defense Network 컨테이너
  └─ EDR Agent (sidecar)           └─ EDR Agent                └─ EDR Agent
        │ (5초 주기 프로세스/연결 스냅샷)
        ▼
                    EDR Backend (services/edr/)
                    ├─ Telemetry Ingest (스냅샷 diff -> 프로세스 시작/종료 이벤트)
                    ├─ Detection Rules (행위 기반 IOC)
                    ├─ Host Registry (호스트 상태: online/isolated)
                    └─ API (/edr/hosts, /edr/processes, /edr/alerts, /edr/isolate)
                                │
                                ▼
                    EDR Console (React 대시보드)
                    ├─ Host List (Falcon의 "Host management")
                    ├─ Process Tree Viewer (Falcon의 "Process Explorer")
                    ├─ Detections (Falcon의 "Detections" 페이지)
                    └─ Response Actions: Isolate Host / Kill Process(화이트리스트)
```

---

## 3. EDR Agent (센서)

### 3.1 수집 항목
- **프로세스**: pid, ppid, name, cmdline, 시작시각, 소유자
- **네트워크 연결**: 프로세스별 outbound/listen 소켓(psutil)
- **파일(선택, MVP는 생략 가능)**: 특정 감시 경로(/tmp, /app)의 신규 파일 생성

### 3.2 구현
- `psutil`로 5초마다 전체 프로세스 스냅샷 → 이전 스냅샷과 diff → `process_started`/`process_ended` 이벤트 생성.
- 각 프로세스의 네트워크 연결도 함께 수집해 `network_connection` 이벤트로.
- EDR Backend가 죽어있어도 에이전트 자체는 절대 죽지 않음(best-effort, 짧은 타임아웃 — 트윈 안전원칙과 동일).

### 3.3 배치
- 별도 컨테이너가 아니라 **트윈 컨테이너 안에서 백그라운드 스레드**로 실행(sidecar 컨테이너로 분리해도
  되지만, MVP는 트윈 프로세스에 통합해 배포 복잡도를 낮춘다).
- `main.py`의 FastAPI startup 이벤트에서 에이전트 스레드를 시작.

---

## 4. EDR Backend

### 4.1 텔레메트리 처리
- 에이전트가 보낸 스냅샷을 이전 스냅샷과 비교(서버 측에서도 이중 diff, 에이전트 diff 유실 대비).
- 신규 프로세스 → `process_started` 저장 + 탐지 규칙 평가.
- 프로세스 소멸 → `process_ended` 저장(존속시간 계산에 사용).

### 4.2 탐지 규칙 (행위 기반 IOC — 초기 세트)
```yaml
- id: EDR-001
  name: "Web server spawning shell"
  logic: "parent process가 uvicorn/python(FastAPI 트윈)인데 child가 sh/bash/nc인 경우"
  severity: critical
  # PP-003 커맨드인젝션이 성공하면 정확히 이 패턴이 발생 -> 실시간 탐지 가능

- id: EDR-002
  name: "Suspicious reverse-shell-like command line"
  logic: "cmdline에 'bash -i', '/dev/tcp/', 'nc -e', 'python -c socket' 등 패턴"
  severity: critical

- id: EDR-003
  name: "Unexpected outbound connection from twin process"
  logic: "트윈 프로세스가 allowlist(event_collector, config_service 등) 밖 목적지로 outbound"
  severity: high
  # Reverse Connection Simulator(C2) 탐지에도 활용 가능

- id: EDR-004
  name: "Process injection indicator (경량 휴리스틱)"
  logic: "동일 pid의 실행파일 경로가 시작 시점과 다르게 바뀜(간이 탐지, 실제 인젝션 탐지는 더 정교한 기법 필요)"
  severity: medium
```
이 규칙들은 06번 탐지 콘텐츠 문서의 앱/네트워크 규칙과 상호보완적이다 — SIEM은 로그 기반,
EDR은 프로세스/호스트 기반으로 같은 공격을 다른 각도에서 잡는다.

### 4.3 API
```
GET  /edr/hosts                     -> [{asset, status(online/isolated/offline), last_seen, process_count}]
GET  /edr/hosts/{asset}/processes   -> 현재 프로세스 트리(부모-자식 구조)
GET  /edr/hosts/{asset}/timeline    -> 해당 호스트의 프로세스 시작/종료 이력
GET  /edr/alerts                    -> 탐지 알림 목록(severity, rule_id, process 정보)
POST /edr/hosts/{asset}/isolate     -> Config Service의 quarantine 토글 호출(교관/Blue 권한)
POST /edr/hosts/{asset}/unisolate
POST /edr/process/{pid}/kill        -> 화이트리스트된 pid만(안전장치, 아래 5절)
WS   /edr/ws                        -> 실시간 프로세스/알림 스트림
```

---

## 5. 안전장치 (Kill Process 액션의 위험성) — 구현 완료

**문제 1**: Blue팀에게 "프로세스 킬" 권한을 주면, 트윈 컨테이너의 핵심 프로세스(uvicorn 자체)를
실수로 죽여 서비스를 마비시킬 수 있다.

**문제 2 (설계 중 발견하고 수정)**: 처음에는 보호 대상을 프로세스 **이름**(uvicorn/python3)으로
판별했으나, 공격자가 `python3 -c "<reverse shell>"` 형태로 악성 프로세스를 띄우면 이름이 서버와
똑같아서 정당한 kill까지 막히는 결함이 있었다. 이름이 아니라 **에이전트가 스스로 보고하는 자기
자신의 pid(server_pid)** 를 유일한 보호 기준으로 바꿔서 해결했다 — 실제로 "이름은 같지만 pid가
다른 악성 프로세스는 정상적으로 kill 허용, 진짜 서버 pid는 항상 거부"되는 것을 검증했다.

**해결 (구현 완료)**:
- Kill 대상은 **자체 탐지로 flagged_pids에 등록된 pid만** 허용(임의 pid kill 금지).
- `hosts.server_pid`(에이전트가 `os.getpid()`로 자가 보고)와 일치하면 무조건 403 거부.
- 실제 종료는 EDR Backend가 즉시 실행하지 않고 **kill_commands 큐**에 넣고, 해당 트윈 컨테이너
  내부의 EDR Agent가 폴링해 자기 프로세스 공간에서 `psutil.Process.terminate()`(SIGTERM) →
  3초 내 미종료 시 `.kill()`(SIGKILL)로 승격 실행한다. 실제 자식 프로세스로 종료/SIGKILL 승격
  경로 전부 실행 검증했다.
- Kill 액션도 audit log에 기록(누가 어떤 pid를 죽였는지, 결과가 done/failed인지).

---

## 6. Isolate Host = Config Service Quarantine 연동

EDR 콘솔의 "Isolate Host" 버튼은 새 메커니즘을 만들지 않고, **이미 구현된 Config Service의
`/instructor/quarantine`을 호출**한다(연결 관계는 04번/config_service 코드 참고). 트윈은 격리
상태면 `/health`를 제외한 모든 요청에 503을 반환한다(host isolation 시뮬레이션) — 이미
구현되어 있으므로 EDR Backend는 이 엔드포인트를 호출하기만 하면 된다.

---

## 7. Falcon과의 대응표 (컨셉 매핑, UX 설계 참고용)

| Falcon 개념 | 이 프로젝트의 대응 |
|---|---|
| Sensor | EDR Agent(트윈 내 백그라운드 스레드) |
| Falcon Cloud | EDR Backend |
| Host Management | GET /edr/hosts |
| Process Explorer | GET /edr/hosts/{asset}/processes (트리 뷰) |
| Detections | GET /edr/alerts (IOC 규칙 기반) |
| Network Containment(호스트 격리) | POST /edr/hosts/{asset}/isolate → Config Service quarantine |
| IOA(Indicator of Attack) | EDR-001~004 행위 기반 규칙 |
| Falcon Fusion(SOAR 자동화) | (확장 여지) 특정 IOA 발생 시 자동 isolate — 다음 단계 제안 |

---

## 8. Definition of Done

- PP-003(커맨드 인젝션) 익스플로잇 성공 → EDR-001/002 규칙이 실시간 알림 발생 → Blue팀이
  콘솔에서 프로세스 트리로 uvicorn→sh 관계를 확인.
- Blue팀이 "Isolate Host" 클릭 → 해당 트윈이 /health 제외 전부 503 → 이후 Red 요청 전부 실패.
- Kill Process는 화이트리스트(탐지된 프로세스만) 밖 pid 요청 시 400, server_pid 요청 시 403.
- **Kill Process가 실제로 프로세스를 종료시킴**: kill_commands 큐 → 에이전트 폴링 → SIGTERM →
  (3초 내 미종료 시) SIGKILL 승격 → ack. 실제 자식 프로세스로 종료/승격 양쪽 경로 실행 검증 완료.
- 이름이 서버와 같아도(예: 공격자의 python3 리버스쉘) pid가 다르면 정상적으로 kill되고,
  진짜 서버 프로세스는 flagged 되어도 항상 보호됨을 검증.
- 모든 isolate/kill 액션이 audit log에 기록.

## 9. 다음 단계 제안 (확장)

- **자동 대응(Falcon Fusion 대응)**: EDR-001(critical) 발생 시 교관 개입 없이 자동 isolate하는
  옵션(대회 룰에 따라 on/off).
- **위협 인텔 매칭**: 알려진 공격 도구 해시/문자열 패턴 데이터베이스와 대조(간이 버전).
- **파일 무결성 모니터링**: 트윈 핵심 파일 변조 탐지(설정 파일 해시 비교).
