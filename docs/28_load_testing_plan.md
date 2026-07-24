# 부하 테스트 계획 — 상세 실행 사양

> 지금까지 전부 기능 검증 위주였다. 실제 훈련(특히 8~16팀 규모)에서 시스템이 버티는지는
> 별도로 검증해야 한다. 도구/시나리오/임계치를 구체적으로 정했다.

---

## 1. 도구 선택

**k6** 권장 (Locust보다 가볍고 CI에 넣기 쉬움, JS로 시나리오 작성).
```bash
sudo apt-get install -y k6   # 또는 공식 저장소 추가 후 설치
```

---

## 2. 테스트 대상별 시나리오

### 2.1 트윈 엔드포인트 부하 (동시 팀 공격 시뮬레이션)

```javascript
// loadtest/k6/twin_attack_load.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  scenarios: {
    concurrent_teams: {
      executor: 'per-vu-iterations',
      vus: 16,              // 16팀 동시
      iterations: 50,       // 팀당 50회 요청
      maxDuration: '5m',
    },
  },
  thresholds: {
    http_req_duration: ['p(95)<500'],   // 95%가 500ms 이내
    http_req_failed: ['rate<0.01'],      // 실패율 1% 미만
  },
};

export default function () {
  const teamId = `team_${__VU}`;
  const res = http.get(`http://localhost:8001/api/telemetry?sensor_id=SOL-PANEL-1`, {
    headers: { 'X-Team-Id': teamId },
  });
  check(res, { 'status 200': (r) => r.status === 200 });
  sleep(Math.random() * 2);
}
```
**임계치 근거**: 트윈은 SQLite 기반 경량 서비스라 500ms를 넘기면 뭔가 잘못된 것(N+1 쿼리,
락 경합 등)으로 간주.

### 2.2 Event Collector 수집/브로드캐스트 부하

```javascript
// loadtest/k6/event_collector_ingest.js
import http from 'k6/http';

export const options = {
  scenarios: {
    high_eps: {
      executor: 'constant-arrival-rate',
      rate: 200,             // 초당 200 이벤트 (16팀 x 다수 노이즈 상정)
      timeUnit: '1s',
      duration: '3m',
      preAllocatedVUs: 50,
    },
  },
  thresholds: {
    http_req_duration: ['p(99)<200'],
  },
};

export default function () {
  http.post('http://localhost:8010/events', JSON.stringify({
    event_id: `${__VU}-${__ITER}-${Date.now()}`,
    event_type: 'red_attack_started', actor: 'red', target_asset: 'ground_station',
    vuln_id: 'GS-001', phase: 'initial_access', team_id: `team_${__VU % 16}`,
  }), { headers: { 'Content-Type': 'application/json' } });
}
```
**별도 확인**: WS 브로드캐스트 팬아웃 — 동시 대시보드 접속자 수(관전자 포함 20~30명 상정)를
시뮬레이션하는 WS 클라이언트 부하는 k6의 xk6-websockets 확장 또는 별도 Node 스크립트로.

### 2.3 SIEM 수집 처리량 (22번 문서 M5 완성 후)

```javascript
// loadtest/k6/siem_ingest.js — syslog는 HTTP가 아니므로 별도 UDP 부하 스크립트 필요
```
```python
# loadtest/syslog_flood.py (k6가 UDP를 잘 못 다루므로 별도 파이썬 스크립트)
import socket, time

def flood(host="localhost", port=514, eps=500, duration_sec=60):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interval = 1.0 / eps
    end = time.time() + duration_sec
    msg = b"<134>1 2026-07-11T00:00:00Z host app - - - test syslog message"
    sent = 0
    while time.time() < end:
        sock.sendto(msg, (host, port))
        sent += 1
        time.sleep(interval)
    print(f"sent={sent}")
```
**측정 대상**: `ingestion/syslog_server.py`의 드롭 카운터(`/sources/health`)가 0에 가까운지,
저장 지연(ingested_at - timestamp)이 SLA 이내인지.

### 2.4 EDR Agent 폴링 부하
- 트윈 1개당 프로세스 수가 비정상적으로 늘어나는 상황(예: fork bomb류 공격 시도, 08번
  안전장치의 `pids_limit`이 실제로 막아주는지 이 부하테스트로 같이 검증)을 시뮬레이션.
```bash
# 컨테이너 안에서(테스트 환경에서만!) pids_limit이 걸려있는지 확인
docker exec pp_twin sh -c 'for i in $(seq 1 200); do sleep 100 & done; sleep 1; ps aux | wc -l'
```
**기대값**: `pids_limit: 64`(하드닝 오버레이 적용 시) 근처에서 fork 실패가 나야 함 —
숫자가 그 이상으로 안 늘어나면 하드닝이 정상 작동.

---

## 3. 임계치 요약표

| 대상 | 지표 | 임계치 |
|---|---|---|
| 트윈 API | p95 응답시간 | < 500ms |
| 트윈 API | 실패율 | < 1% |
| Event Collector | p99 응답시간 | < 200ms |
| Event Collector | WS 팬아웃 지연 | < 1s (이벤트 발생~클라이언트 수신) |
| SIEM ingestion | drop rate | < 0.1% (EPS 200 기준) |
| SIEM 검색 | 응답시간 | < 500ms (1만건 기준, 22번 문서 3절과 동일 기준) |
| EDR pids_limit | fork bomb 시 프로세스 수 | 설정값(64) 근처에서 상한 |

---

## 4. 실행 순서

```bash
mkdir -p loadtest/k6
# 1) 단일 트윈 부하
k6 run loadtest/k6/twin_attack_load.js
# 2) Event Collector 부하
k6 run loadtest/k6/event_collector_ingest.js
# 3) SIEM syslog 플러딩(M5 완성 후)
python3 loadtest/syslog_flood.py --eps 500 --duration 60
# 4) 결과를 21번 문서의 서버 사양 표와 대조 -> 필요시 e2-standard-8 -> 16으로 상향 결정
```

## 5. 언제 하는 게 맞나

**빌드 마일스톤 M1(코어 플랫폼 기동) 직후 1차, M5(SIEM) 완성 후 2차**로 나눠서 진행 권장.
너무 일찍(플랫폼이 안정화되기 전) 부하테스트를 하면 기능 버그와 성능 문제가 섞여 원인 파악이
어려워진다.
