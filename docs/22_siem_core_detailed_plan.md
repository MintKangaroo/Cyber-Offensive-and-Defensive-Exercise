# SIEM 코어 — 상세 구현 계획 (01번 문서의 실행 사양)

> 01번 문서(개요/아키텍처)를 실제로 코드 짤 수 있는 수준까지 쪼갰다.
> 파일 경로, 함수 시그니처, 데이터 흐름, 각 모듈의 완료 판정 테스트까지 명시.

---

## 0. 디렉토리 (services/siem/ 하위, 17번 구조 기준)

```
services/siem/
├─ ingestion/
│  ├─ syslog_server.py
│  └─ file_tailer.py
├─ parsers/
│  ├─ base.py
│  ├─ twin.py
│  ├─ suricata.py
│  ├─ zeek.py
│  └─ pfsense.py
├─ enrich/
│  ├─ geoip.py
│  └─ asset_tag.py
├─ storage/
│  ├─ sqlite_backend.py      # storage_interface.StorageBackend 구현체(MVP)
│  └─ opensearch_backend.py  # 동일 인터페이스, 운영 승격용(스텁으로 시작)
├─ detection/
│  ├─ engine.py
│  ├─ sigma_loader.py
│  ├─ rules/                 # YAML 규칙 파일들(06번 문서 20종)
│  └─ noise_generator.py
├─ api/
│  └─ main.py
└─ Dockerfile
```

---

## 1. Ingestion — 정확한 함수 시그니처

### `ingestion/syslog_server.py`
```python
async def start_udp_syslog(host: str, port: int, queue: asyncio.Queue) -> None:
    """asyncio.DatagramProtocol 기반 UDP 514 수신. 각 datagram을 RawLogLine으로 큐에 push."""

async def start_tcp_syslog(host: str, port: int, queue: asyncio.Queue) -> None:
    """asyncio.start_server. RFC6587 프레이밍(octet-counting + non-transparent 개행) 둘 다 지원.
    프레이밍 판별: 첫 바이트가 숫자면 octet-counting, 아니면 개행 구분으로 폴백."""

@dataclass
class RawLogLine:
    source_ip: str
    raw_text: str
    received_at: float
    transport: str  # "udp" | "tcp" | "file"
```

**드롭 카운터**: 큐가 `maxsize` 도달 시 `queue.put_nowait()` 실패 → `drop_counter[source_ip] += 1`,
이 카운터를 `api/main.py`의 `/sources/health`가 노출.

### `ingestion/file_tailer.py`
```python
async def tail_file(path: str, source_type: str, queue: asyncio.Queue, poll_interval: float = 0.5) -> None:
    """logrotate 대응: inode 변경 감지 시 파일 재오픈. 파일 없으면 존재할 때까지 대기(에러로 죽지 않음)."""
```
대상: Suricata `eve.json`, Zeek `logs/current/*.log`, 트윈의 구조화 access log(5절 참고).

---

## 2. Parsers — 레지스트리 패턴

### `parsers/base.py`
```python
from typing import Protocol
from shared.siem_schema import NormalizedEvent

class Parser(Protocol):
    source_type: str
    def parse(self, raw: RawLogLine) -> NormalizedEvent | None:
        """실패 시 None 반환(호출부가 raw 그대로 저장 + parse_error 태그)."""

_REGISTRY: dict[str, Parser] = {}

def register(parser: Parser) -> None: ...
def get_parser(source_type: str) -> Parser | None: ...
def parse_any(raw: RawLogLine) -> NormalizedEvent:
    """소스 판별(포트/파일경로 매핑) -> 해당 파서 -> 실패 시 fallback 파서(raw 그대로 감싸기)."""
```

### `parsers/twin.py` (가장 먼저 구현 — 이미 구조화 JSON이라 제일 쉬움)
```python
def parse_twin_log(raw: RawLogLine) -> NormalizedEvent:
    """트윈이 남기는 JSON 한 줄(예: {"ts":...,"asset":...,"endpoint":...,"status":...,"vuln_id":...})을
    NormalizedEvent로 매핑. severity는 status>=500 -> 3, 401/403 -> 2, 200 -> 0 매핑표 사용."""
```
**선행 작업**: 트윈이 지금은 Live Fire 이벤트만 쏘고 있음. SIEM용 구조화 access log를 남기도록
트윈 코드에 `logging.info(json.dumps({...}))` 한 줄을 각 엔드포인트에 추가해야 함(05번 문서에서
이미 예시 포맷 제시함). **이 작업이 SIEM 전체의 선행조건**이므로 M5의 첫 세션에서 처리.

### `parsers/suricata.py`
```python
def parse_suricata_eve(raw: RawLogLine) -> NormalizedEvent:
    """eve.json 한 줄(JSON) 파싱. event_type 필드로 분기:
    - "alert" -> signature, signature_id, alert.severity(1~3) -> SEVERITY_MAP 역산
    - "flow"  -> network.bytes/packets/direction
    - "dns"/"http" -> category="network", message에 쿼리/URL 요약"""
```

### `parsers/zeek.py`
```python
def parse_zeek_line(raw: RawLogLine, log_type: str) -> NormalizedEvent:
    """log_type: "conn"|"dns"|"http"|"ssl"|"notice". 탭 구분 필드는 zeek의 #fields 헤더 라인을
    먼저 읽어 컬럼명 매핑을 캐싱해두고 이후 라인들을 그 매핑으로 파싱."""
```

### `parsers/pfsense.py`
```python
def parse_pfsense_filterlog(raw: RawLogLine) -> NormalizedEvent:
    """CSV 필드(rule#,sub#,anchor,tracker,iface,reason,action,dir,...). action="block"/"pass" ->
    NormalizedEvent.action 매핑, severity: block=2, pass=0."""
```

**완료 판정(각 파서)**: `tests/fixtures/<source>_sample.log` 1건씩 → `parse()` 호출 →
NormalizedEvent 필드 전부 채워짐(손실 없음) → pytest 케이스로 고정.

---

## 3. Storage — 인터페이스 구현

### `storage/sqlite_backend.py`
```python
class SqliteBackend(StorageBackend):
    def __init__(self, db_path: str): ...
    async def index(self, event: NormalizedEvent) -> None:
        """FTS5 가상테이블(message, raw_json)과 일반 컬럼 테이블을 함께 씀."""
    async def search(self, query: SearchQuery) -> list[NormalizedEvent]:
        """query.text가 있으면 FTS MATCH, 없으면 일반 WHERE. 필터(source_type/asset/severity_min/시간)
        전부 AND 결합."""
    async def aggregate(self, field: str, query: SearchQuery) -> dict[str, int]:
        """GROUP BY {field} COUNT(*)."""
```
스키마:
```sql
CREATE TABLE events (
  event_id TEXT PRIMARY KEY, timestamp REAL, ingested_at REAL,
  source_type TEXT, source_ip TEXT, asset TEXT, severity INTEGER,
  category TEXT, action TEXT, signature TEXT, signature_id TEXT,
  mitre TEXT, trace_id TEXT, vuln_id TEXT, team_id TEXT,
  message TEXT, raw TEXT, tags TEXT
);
CREATE VIRTUAL TABLE events_fts USING fts5(message, raw, content='events', content_rowid='rowid');
```

**완료 판정**: 10,000건 합성 이벤트 삽입 후 텍스트검색 응답 500ms 이내(로컬 SSD 기준).

---

## 4. Detection Engine

### `detection/engine.py`
```python
class Rule(BaseModel):
    id: str
    title: str
    severity: int
    mitre: list[str]
    source_type: str | list[str]
    kind: Literal["match", "threshold", "sequence"]
    match: dict | None = None
    threshold: ThresholdSpec | None = None
    sequence: list[dict] | None = None

class ThresholdSpec(BaseModel):
    group_by: str          # "src.ip" 등 dot-path
    condition: str         # "distinct(dst.port) >= 15"
    window_sec: int

class DetectionEngine:
    def __init__(self, rules: list[Rule]): ...
    async def evaluate(self, event: NormalizedEvent) -> list[Alert]:
        """3가지 kind별 평가기 호출. threshold/sequence는 슬라이딩 윈도우 상태를
        group_by 키별 deque(maxlen 없음, window_sec으로 오래된 것 제거)에 보관."""

def eval_match(event, rule) -> bool: ...
def eval_threshold(event, rule, state: dict) -> bool: ...
def eval_sequence(event, rule, state: dict) -> bool:
    """상태: {group_key: [진행중인 step_index, 마지막 매치 시각]}. 순서대로 매치되면 진행,
    within_sec 초과 시 리셋."""
```

**완료 판정**: 06번 문서 20종 규칙 각각에 대해 "매치되는 이벤트 시퀀스 1개" + "매치 안 되는
이벤트 시퀀스 1개"를 pytest 픽스처로 만들어 전부 통과.

### `detection/sigma_loader.py`
```python
def load_sigma_yaml(path: str) -> Rule:
    """Sigma 표준 서브셋만 지원(detection/condition/timeframe/logsource). 미지원 필드는
    ValueError 대신 warnings.warn으로 알리고 최대한 변환, 완전히 불가능하면 스킵 + 로그."""
```

### `detection/noise_generator.py`
```python
class NoiseGenerator:
    def __init__(self, eps: float, source_ips: list[str]): ...
    async def run_forever(self, queue: asyncio.Queue) -> None:
        """정상 로그인 성공/텔레메트리 조회/헬스체크 패턴을 eps 비율로 큐에 주입.
        업무시간대(9~18시) 가중치 적용."""
```

---

## 5. 트윈 구조화 로그 (선행 작업, 이미 5절에서 언급)

각 트윈 엔드포인트 끝에 한 줄 추가(예: ground_station의 `/api/telemetry`):
```python
import logging
siem_logger = logging.getLogger("siem_access")
siem_logger.info(json.dumps({
    "ts": time.time(), "asset": ASSET_NAME, "endpoint": "/api/telemetry",
    "status": 200, "src_ip": request.client.host, "vuln_id": "GS-001",
    "team_id": x_team_id, "trace_id": trace_id, "ua": request.headers.get("user-agent"),
}))
```
로그는 stdout으로(컨테이너 로그) 또는 `/var/log/twin_access.log` 파일로 — `file_tailer.py`가
후자를 참조하도록 docker-compose volume 마운트 필요.

---

## 6. API

### `api/main.py`
```
GET  /search              -> SqliteBackend.search(SearchQuery(**query_params))
GET  /alerts              -> DB의 alerts 테이블 조회, ?status=open|ack|closed
POST /alerts/{id}         -> status 변경(ack/closed), 사유 없어도 됨(교관 조작 아님)
GET  /stats               -> aggregate(source_type), aggregate(severity), top signature 10개
GET  /sources/health      -> 소스별 last_seen, drop_count(ingestion에서 공유)
GET  /detection/attack-coverage -> 전체 rules의 mitre 태그 집계 -> {tactic: {technique: [rule_ids]}}
WS   /ws/logs             -> storage.index() 호출 직후 브로드캐스트
WS   /ws/alerts           -> engine.evaluate()가 alert 생성 시 브로드캐스트
```

---

## 7. Live Fire 연동 (07번 문서와 정합)

```python
# detection/engine.py 의 evaluate() 마지막에
if PUSH_TO_LIVEFIRE and alert.severity >= 2:
    await event_client.emit_event(
        event_type="blue_detection_success", actor="blue",
        target_asset=event.asset, vuln_id=event.vuln_id,
        matched_event_id=event.trace_id,   # 04번 문서의 dwell time 계산에 씀
        metadata={"rule_id": alert.rule_id, "mitre": alert.mitre},
    )
```

---

## 8. 마일스톤 (기존 M5를 세분화)

| 세부 마일스톤 | 내용 | 완료 판정 | 상태 |
|---|---|---|---|
| M5.0 | 트윈 구조화 로그 추가(5절) | 3개 트윈 access.log에 JSON 한 줄씩 실제로 남음 | ✅ 구현+검증 완료 |
| M5.1 | contracts + storage(SQLite) + twin 파서 + file_tailer + 최소 API | `/search`로 트윈 로그 조회 성공 | ✅ 구현+검증 완료 |
| M5.2 | ingestion(syslog UDP/TCP) + pfsense 파서 | pfsense 더미 syslog 전송 → `/search`에서 조회 | ✅ 구현+검증 완료. UDP/TCP(octet-counting+개행 프레이밍 둘 다) 실제 소켓 통신으로 확인 |
| M5.3 | Suricata/Zeek 파서 + file_tailer 확장 | 샘플 eve.json/zeek 로그 → 파싱 성공 | ✅ 파서 구현+검증 완료(Zeek 헤더캐싱 로직 실행 확인). 실제 Suricata/Zeek 사이드카는 26번 문서 M-Net에서 추가 예정 — 경로는 이미 준비됨(현재는 파일 없으면 대기) |
| M5.4 | Detection engine(단순+임계) + 규칙 10종 | 앱계층 공격 curl → `/alerts`에 알림 | ✅ 구현+검증 완료. match/threshold(edge-trigger) 실제 실행, 앱계층 10종 + 네트워크계층 5종 = 15종 룰 로드 확인 |
| M5.5 | 시퀀스 규칙 + Live Fire 연동 | 킬체인 curl 시퀀스 → 단일 critical 알림 + Blue 점수 반영 | ✅ 구현+검증 완료. 시퀀스 2종(순서강제+시간초과리셋 포함) 실행 검증, `blue_detection_success` Live Fire 연동 코드 작성(trace_id로 dwell time 계산 재료 전달) |
| M5.6 | Sigma 로더 + ATT&CK 커버리지 + 노이즈 생성기 | 커뮤니티 Sigma 룰 1개 임포트 성공, 노이즈 on시 EPS 확인 | ✅ 구현+검증 완료. Sigma 로더 3케이스(정상변환/실패스킵/부분지원) 검증, 노이즈 생성기 실제 이벤트 생성+업무시간 가중치 확인 |

**전체 17개 규칙(앱계층 10 + 네트워크계층 5 + 시퀀스 2)을 통합 로드해 ID 중복 없음과
오탐 없음을 실제로 확인**했다. C2 비콘(주기성) 탐지는 현재 엔진의 3종 kind로 표현이
안 되어 `detection/beacon_detection_note.md`에 필요한 4번째 kind(periodicity) 설계를
솔직하게 남겨뒀다 — 다음 세션에서 엔진을 확장할 것.

**구현 파일 요약**:
- `ingestion/syslog_server.py` — UDP + TCP(RFC6587 두 프레이밍) 수신, 드롭카운터
- `parsers/{suricata,zeek,pfsense,base}.py` — 소스별 파서 + 레지스트리
- `detection/engine.py` — Rule/Alert 데이터클래스, match/threshold/sequence 평가기(pydantic 비의존)
- `detection/rules/*.yaml` — 17개 규칙
- `detection/sigma_loader.py` — Sigma 서브셋 로더
- `detection/noise_generator.py` — 배경 노이즈 생성기
- `storage/alert_store.py` — 알림 저장소(pydantic 비의존)
- `api/main.py` — 전체 통합(ingestion+parsing+detection+Live Fire 연동+API)
