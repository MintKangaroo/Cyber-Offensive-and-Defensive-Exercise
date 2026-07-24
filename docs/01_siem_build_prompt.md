# Cyber Range SIEM — Claude Code 멀티에이전트 빌드 프롬프트

> 이 문서는 Claude Code가 읽고 곧바로 구현에 착수할 수 있도록 작성된 **빌드 사양 + 에이전트 분업 프롬프트**입니다.
> Live Fire 공방 플랫폼과는 **분리된 독립 SIEM**으로, 디지털 트윈/Suricata/Zeek/pfSense의 syslog를 자체 수집·정규화·탐지·시각화합니다.
> 두 시스템은 느슨하게 연동됩니다(공통 이벤트 버스). 상세 연동 규약은 마지막 "Live Fire 연동" 절 참고.

---

## 0. 한 줄 정의

**트윈 + 네트워크 보안장비(Suricata/Zeek/pfSense)의 syslog를 UDP/TCP/TLS로 수집해 정규화(ECS 유사 스키마)하고, 상관분석 규칙으로 탐지 알림을 생성하며, 실시간 SIEM 대시보드로 보여주는 자체 SIEM.**

MVP 목표: ELK/Wazuh 없이도 동작하는 경량 SIEM 코어. 이후 Wazuh를 데이터 소스 중 하나로 흡수 가능한 구조.

---

## 1. 아키텍처 개요

```
                          ┌──────────────────────────────────────────┐
  [Digital Twins] ─syslog─┤                                          │
  [Suricata eve.json]─────┤   Ingestion Layer (Collectors)           │
  [Zeek conn/dns/http]────┤   - Syslog UDP/TCP/TLS (RFC5424/3164)     │
  [pfSense filterlog]─────┤   - JSON/eve tail (filebeat 대체)         │
                          └───────────────┬──────────────────────────┘
                                          │  raw event
                                          ▼
                          ┌──────────────────────────────────────────┐
                          │   Normalization Layer (Parsers)          │
                          │   - source별 파서 → 공통 스키마(ECS-lite) │
                          │   - GeoIP/asset enrichment                │
                          └───────────────┬──────────────────────────┘
                                          │  normalized event
                                          ▼
                    ┌─────────────────────┴───────────────────┐
                    ▼                                          ▼
      ┌──────────────────────────┐              ┌──────────────────────────┐
      │  Storage (OpenSearch/     │              │  Detection Engine        │
      │  SQLite+FTS MVP)          │◀────query────│  - 규칙(YAML/Sigma-lite)  │
      │  - 원본+정규화 보관         │              │  - 상관/임계/시퀀스 규칙   │
      └───────────┬──────────────┘              │  - MITRE ATT&CK 매핑      │
                  │                              └───────────┬──────────────┘
                  │                                          │ alert
                  ▼                                          ▼
      ┌──────────────────────────────────────────────────────────────────┐
      │   API Layer (FastAPI)  /search /alerts /stats /ws                 │
      └───────────────────────────────┬──────────────────────────────────┘
                                      ▼
      ┌──────────────────────────────────────────────────────────────────┐
      │   SIEM Dashboard (React) — 로그 탐색 / 탐지 알림 / 소스 헬스        │
      └──────────────────────────────────────────────────────────────────┘
```

---

## 2. 기술 스택 (고정)

- **수집/파싱/API**: Python 3.11, FastAPI, asyncio (syslog 서버는 `asyncio.DatagramProtocol` / `start_server`)
- **저장소**: MVP는 SQLite (FTS5 전문검색) → 운영은 OpenSearch. 저장 계층은 인터페이스로 추상화해 교체 가능하게.
- **큐(선택)**: MVP는 asyncio.Queue, 운영 확장 시 Redis Streams / Kafka
- **프론트**: React + TypeScript + TailwindCSS, 차트는 recharts, 실시간은 WebSocket
- **배포**: docker-compose (기존 Live Fire compose와 별도 파일, 공통 네트워크만 공유)

---

## 3. 에이전트 분업 (멀티에이전트 빌드)

> 각 에이전트는 자신의 디렉토리와 인터페이스 계약만 지키면 병렬로 작업 가능.
> **계약(스키마/엔드포인트)은 Agent 0가 먼저 확정**하고 나머지가 그 위에서 구현.

### Agent 0 — Architect / Contract Owner
**책임**: 전체 리포 구조, 공통 이벤트 스키마(ECS-lite) 확정, 저장소 인터페이스 정의, docker-compose 뼈대.
**산출물**:
- `siem/shared/schema.py` — 정규화 이벤트 Pydantic 모델 (아래 4절 스키마)
- `siem/shared/storage_interface.py` — `StorageBackend` 추상클래스 (`index()`, `search()`, `aggregate()`)
- `siem/docker-compose.siem.yml`
- `siem/README.md` (실행법)
**완료 기준**: 나머지 에이전트가 import할 수 있는 스키마/인터페이스가 고정됨.

### Agent 1 — Ingestion Engineer (수집)
**책임**: syslog 수신 서버 + 파일 tail 수집기.
**산출물**:
- `siem/ingestion/syslog_server.py` — UDP(514)/TCP/TLS 동시 수신, RFC5424·RFC3164 프레이밍 처리
- `siem/ingestion/file_tailer.py` — Suricata `eve.json`, Zeek `conn.log` 등 tail -f 방식 수집
- 수신 raw 이벤트를 `asyncio.Queue`(또는 Redis Stream)로 밀어넣음
**주의**:
- syslog 프레이밍: TCP는 octet-counting과 non-transparent framing 둘 다 지원
- backpressure: 큐가 가득 차면 드롭 카운터 증가시키고 소스 헬스에 반영(무한 버퍼 금지)
- 소스 IP → asset 매핑 테이블 참조

### Agent 2 — Normalization Engineer (파싱/정규화)
**책임**: source별 파서로 raw → 공통 스키마 변환 + enrichment.
**산출물**:
- `siem/parsers/base.py` — 파서 레지스트리(소스 타입별 등록)
- `siem/parsers/suricata.py` — eve.json alert/flow/dns/http 파싱, `alert.signature`, `alert.category`, `alert.signature_id` 추출
- `siem/parsers/zeek.py` — conn/dns/http/ssl 로그 파싱
- `siem/parsers/pfsense.py` — filterlog CSV 필드 파싱(pass/block, 방향, src/dst, port, proto)
- `siem/parsers/twin.py` — 디지털 트윈 access log 파싱(엔드포인트/상태코드/취약점 id)
- `siem/enrich/geoip.py`, `siem/enrich/asset.py` — GeoIP·자산 태깅
**완료 기준**: 각 소스 샘플 로그 1건이 공통 스키마로 손실 없이 변환됨(테스트 픽스처 포함).

### Agent 3 — Detection Engineer (탐지/상관분석)
**책임**: 규칙 엔진 + 룰셋 + MITRE 매핑.
**산출물**:
- `siem/detection/engine.py` — 규칙 평가 루프(정규화 이벤트 스트림 구독)
- `siem/detection/rules/*.yaml` — Sigma-lite 규칙(아래 6절 예시)
- 규칙 타입 3종: (a) 단순 매칭, (b) 임계(threshold: N events in T sec), (c) 시퀀스(A→B→C 순서)
- alert 생성 시 `blue_detection_success` 이벤트를 Live Fire Event Collector로 전달(옵션)
**완료 기준**: 6절 예시 규칙이 실제 트윈 공격 트래픽에서 알림을 발생시킴.

### Agent 4 — API Engineer
**책임**: 검색/알림/통계/실시간 API.
**산출물**: `siem/api/main.py`
- `GET /search` — 전문검색 + 필터(시간범위, source, severity, asset, ATT&CK)
- `GET /alerts` — 탐지 알림 목록/상세, 상태(open/ack/closed) 변경
- `GET /stats` — 소스별 EPS(events/sec), severity 분포, top signatures
- `GET /sources/health` — 소스별 마지막 수신시각, 드롭 카운트, 상태
- `WS /ws/logs`, `WS /ws/alerts` — 실시간 스트림
**완료 기준**: 대시보드가 이 API만으로 모든 화면을 그릴 수 있음.

### Agent 5 — Frontend Engineer (SIEM 대시보드)
**책임**: SIEM 전용 대시보드(별도 앱).
**산출물**: `siem/dashboard/` (React)
- 화면: Discover(로그탐색), Alerts(탐지), Source Health, Analytics
- 상세 UX는 별도 문서 `siem_dashboard_spec.md` 참고
**완료 기준**: 실시간 로그 tail + 알림 배지 + 검색이 동작.

---

## 4. 공통 이벤트 스키마 (ECS-lite) — Agent 0 확정

```python
class NormalizedEvent(BaseModel):
    event_id: str                 # ULID (시간정렬 가능)
    timestamp: datetime           # 이벤트 발생 시각(파싱된 것)
    ingested_at: datetime         # 수집 시각
    source_type: str              # "suricata" | "zeek" | "pfsense" | "twin" | "syslog"
    source_ip: str | None         # 로그를 보낸 장비 IP
    host: str | None              # 관련 호스트명
    asset: str | None             # "ground_station" | "power_plant" | "defense_network" | "dmz"
    severity: int                 # 0(info)~4(critical) 정규화
    category: str                 # "network" | "intrusion" | "firewall" | "auth" | "web" ...
    action: str | None            # "allowed" | "blocked" | "alert" | "detected"
    src: NetEndpoint | None       # {ip, port, geo, asn}
    dst: NetEndpoint | None
    network: dict                 # {protocol, bytes, packets, direction}
    signature: str | None         # 탐지 시그니처 이름(Suricata alert 등)
    signature_id: str | None
    mitre: list[str]              # ["T1190", "T1046"] 등
    message: str                  # 사람이 읽는 요약
    raw: dict                     # 원본 로그(감사/디버깅용)
    tags: list[str]
```

**설계 노트**
- ULID를 event_id로 쓰면 시간정렬 + 중복제거 둘 다 해결(정렬키 겸용).
- `raw`는 항상 보존(원본 무결성). 정규화 실패해도 raw는 저장하고 `parse_error` 태그 부여.
- severity 정규화 매핑표를 파서별로 명시(예: pfSense block=2, Suricata sig severity 1→4).

---

## 5. 소스별 수집 상세

| 소스 | 방식 | 포트/경로 | 핵심 필드 |
|---|---|---|---|
| Digital Twins | syslog(앱 로거) 또는 access log tail | UDP 514 / `access.log` | endpoint, status, vuln_id, team_id |
| Suricata | eve.json tail | `/var/log/suricata/eve.json` | alert.signature, flow, http, dns |
| Zeek | 로그 tail | `/opt/zeek/logs/current/*.log` | conn/dns/http/ssl/notice |
| pfSense | remote syslog | UDP 514 (facility local0) | filterlog: act, dir, proto, src/dst |

**트윈 로그 강화 제안(추천)**: 지금 트윈들은 `emit_event()`로 Live Fire 이벤트만 쏘는데, SIEM용으로 **구조화 access 로그(JSON 한 줄)**도 별도로 남기게 하면 좋습니다. 예:
```json
{"ts":"...","asset":"ground_station","endpoint":"/api/telemetry","status":200,"src_ip":"10.0.0.5","vuln_id":"GS-001","team_id":"team_alpha","ua":"curl/8"}
```
→ Suricata가 못 잡는 애플리케이션 레이어 공격(IDOR, 논리취약점)을 SIEM이 탐지할 수 있게 됨.

---

## 6. 탐지 규칙 예시 (Sigma-lite, Agent 3)

```yaml
# rules/twin_sqli_probe.yaml
id: TWIN-SQLI-001
title: Ground Station Telemetry SQL Injection Attempt
severity: 3
mitre: [T1190]
source_type: twin
match:
  endpoint: "/api/telemetry"
  raw.query_contains: ["'", "UNION", "--", "OR 1=1"]
action_on_match: alert

# rules/port_scan_threshold.yaml
id: NET-SCAN-001
title: Horizontal Port Scan Detected
severity: 2
mitre: [T1046]
source_type: [zeek, pfsense]
threshold:
  group_by: src.ip
  condition: distinct(dst.port) >= 15
  window_sec: 60
action_on_match: alert

# rules/kill_chain_sequence.yaml
id: SEQ-KILLCHAIN-001
title: Multi-stage Attack (recon -> exploit -> exfil)
severity: 4
mitre: [T1046, T1190, T1041]
sequence:
  - match: {category: "network", signature_contains: "scan"}
  - match: {asset: "ground_station", raw.status: 200, endpoint_contains: "/api/"}
  - match: {event_type: "flag_exfiltrated"}
  within_sec: 300
  group_by: src.ip
action_on_match: alert_critical
```

**추천 규칙 세트(초기 탑재용)**: 포트스캔, 브루트포스(동일 src의 401 연속), SQLi/경로순회 패턴, 오픈릴레이 악용, PLC 미인증 쓰기, C2 비콘 주기성(동일 간격 outbound), pfSense 차단 급증.

---

## 7. Live Fire 연동 (느슨한 결합)

- SIEM은 독립 실행되지만, **탐지 알림이 발생하면** Live Fire의 Event Collector(`POST /events`)로 `blue_detection_success` / `blue_block_success` 이벤트를 보낼 수 있음(옵션 플래그 `PUSH_TO_LIVEFIRE=true`).
- 이때 Scoring Engine이 Blue 팀 탐지 점수(+20)/차단 점수(+30)를 자동 적립 → **"탐지했는가"가 점수로 연결**되어 훈련 완결성이 올라감.
- 반대로 SIEM은 Live Fire의 시나리오 시작/종료 이벤트를 구독해 대시보드에 "현재 진행 중 시나리오" 컨텍스트를 표시할 수 있음.

---

## 8. 개발 순서 (에이전트 병렬 + 마일스톤)

- **M1**: Agent 0 스키마/인터페이스 → Agent 1 syslog 수신 + Agent 2 트윈/pfSense 파서 → SQLite 저장 → `/search` 동작
- **M2**: Agent 2 Suricata/Zeek 파서 + Agent 3 단순/임계 규칙 → `/alerts` 동작
- **M3**: Agent 4 실시간 WS + Agent 5 Discover/Alerts 화면
- **M4**: 시퀀스 규칙 + Live Fire 연동(탐지→점수) + Source Health
- **M5**: OpenSearch 백엔드 어댑터 교체 옵션, 성능/EPS 벤치

---

## 9. 완료(Definition of Done)

- 트윈에 curl로 SQLi 한 번 → SIEM Discover에 로그가 뜨고 → Alerts에 TWIN-SQLI-001 알림이 뜨고 → (옵션) Live Fire Blue 점수 +20.
- 4개 소스(twin/suricata/zeek/pfsense) 전부 Source Health에서 green.
- 재시작 후에도 저장된 로그/알림이 유지됨.
