"""
SIEM API (22번 문서 6절, M5.1~M5.6 통합)
==========================================
M5.1: /search, /sources/health (트윈 구조화 로그)
M5.2: syslog UDP 수신(pfsense)
M5.3: Suricata/Zeek 파일 tail (사이드카는 26번 문서에서 추가 예정, 경로는 미리 준비)
M5.4: Detection Engine(match/threshold) + 규칙 로드
M5.5: 시퀀스 규칙 + Live Fire 연동(blue_detection_success 발행)
M5.6: Sigma 로더, ATT&CK 커버리지, 노이즈 생성기

실행: uvicorn services.siem.api.main:app --port 8040
"""
from __future__ import annotations
import asyncio
import glob
import os
import time
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

import sys
sys.path.append(str(Path(__file__).parent.parent.parent.parent))
from shared.storage_interface import SearchQuery  # noqa: E402
from services.siem.storage.sqlite_backend import SqliteBackend  # noqa: E402
from services.siem.storage.alert_store import AlertStore  # noqa: E402
from services.siem.parsers.base import parse_any  # noqa: E402
from services.siem.parsers.twin import parse_twin_log_line  # noqa: E402
from services.siem.ingestion.file_tailer import tail_multiple  # noqa: E402
from services.siem.ingestion.syslog_server import start_udp_syslog, drop_counters  # noqa: E402
from services.siem.detection.engine import Rule, DetectionEngine  # noqa: E402
from services.siem.detection.noise_generator import NoiseGenerator  # noqa: E402

APP_DIR = Path(__file__).parent
DB_PATH = os.environ.get("SIEM_DB_PATH", str(APP_DIR / "siem.db"))
ALERT_DB_PATH = os.environ.get("SIEM_ALERT_DB_PATH", str(APP_DIR / "siem_alerts.db"))
LOG_DIR = Path(os.environ.get("SIEM_LOG_DIR", "/var/log/siem"))
RULES_DIR = Path(os.environ.get("SIEM_RULES_DIR", str(Path(__file__).parent.parent / "detection" / "rules")))
TWIN_ASSETS = ["ground_station", "power_plant", "defense_network"]
SYSLOG_UDP_PORT = int(os.environ.get("SYSLOG_UDP_PORT", "1514"))  # 514는 root 권한 필요, 기본은 비특권 포트
EVENT_COLLECTOR_URL = os.environ.get("EVENT_COLLECTOR_URL", "http://event_collector:8010")
PUSH_TO_LIVEFIRE = os.environ.get("PUSH_TO_LIVEFIRE", "true").lower() == "true"
NOISE_ENABLED = os.environ.get("SIEM_NOISE_ENABLED", "false").lower() == "true"
NOISE_EPS = float(os.environ.get("SIEM_NOISE_EPS", "2.0"))

app = FastAPI(title="SIEM API (M5 통합)")

# SIEM 대시보드(로컬 dev 5175 등)가 브라우저에서 직접 /search·/alerts·/stats를 조회하므로 CORS 필요.
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
app.add_middleware(
    CORSMiddleware, allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)
backend = SqliteBackend(DB_PATH)
alert_store = AlertStore(ALERT_DB_PATH)

_source_health: dict[str, dict] = {}
_ws_log_clients: set[WebSocket] = set()
_ws_alert_clients: set[WebSocket] = set()
_syslog_queue: asyncio.Queue = asyncio.Queue(maxsize=5000)


def _load_rules() -> list[Rule]:
    import yaml
    rules: list[Rule] = []
    for path in sorted(glob.glob(str(RULES_DIR / "*.yaml"))):
        with open(path) as f:
            docs = yaml.safe_load(f) or []
        for d in docs:
            rules.append(Rule(
                id=d["id"], title=d["title"], severity=d["severity"],
                mitre=d.get("mitre", []), source_type=d.get("source_type"),
                kind=d.get("kind", "match"), match=d.get("match"),
                threshold_group_by=d.get("threshold_group_by"),
                threshold_condition=d.get("threshold_condition"),
                threshold_window_sec=d.get("threshold_window_sec", 60),
                sequence_steps=d.get("sequence_steps"),
                sequence_group_by=d.get("sequence_group_by", "src.ip"),
                sequence_within_sec=d.get("sequence_within_sec", 300),
                periodicity_group_by_src=d.get("periodicity_group_by_src", "src.ip"),
                periodicity_group_by_dst=d.get("periodicity_group_by_dst", "dst.ip"),
                periodicity_min_observations=d.get("periodicity_min_observations", 5),
                periodicity_jitter_threshold=d.get("periodicity_jitter_threshold", 0.1),
                periodicity_window_sec=d.get("periodicity_window_sec", 3600),
                periodicity_allowlist_dst=d.get("periodicity_allowlist_dst", []),
            ))
    return rules


detection_engine = DetectionEngine(_load_rules())


def _touch_source_health(key: str, error: bool = False) -> None:
    info = _source_health.setdefault(key, {"last_seen": None, "lines_ingested": 0, "parse_errors": 0})
    if error:
        info["parse_errors"] += 1
    else:
        info["last_seen"] = time.time()
        info["lines_ingested"] += 1


async def _broadcast(clients: set[WebSocket], payload: dict) -> None:
    dead = set()
    for ws in clients:
        try:
            if ws.client_state == WebSocketState.CONNECTED:
                await ws.send_json(payload)
        except Exception:
            dead.add(ws)
    clients.difference_update(dead)


async def _process_event(event) -> None:
    """정규화된 이벤트 하나를 저장 + 탐지평가 + 알림처리 + 브로드캐스트."""
    await backend.index(event)
    await _broadcast(_ws_log_clients, {"type": "log", "event": event.model_dump(mode="json")})

    alerts = detection_engine.evaluate(event.model_dump(mode="json"))
    for alert in alerts:
        alert_store.save(alert.rule_id, alert.title, alert.severity, alert.mitre,
                         alert.timestamp, alert.detail, alert.matched_event)
        await _broadcast(_ws_alert_clients, {
            "type": "alert", "rule_id": alert.rule_id, "title": alert.title,
            "severity": alert.severity, "mitre": alert.mitre, "detail": alert.detail,
        })
        if PUSH_TO_LIVEFIRE:
            asyncio.create_task(_push_detection_to_livefire(alert, event))


async def _push_detection_to_livefire(alert, event) -> None:
    """22번 문서 7절: 탐지 성공을 Live Fire의 blue_detection_success로 전달 -> Blue 점수 연결."""
    payload = {
        "event_id": f"siem-detect-{alert.rule_id}-{int(alert.timestamp*1000)}",
        "event_type": "blue_detection_success",
        "actor": "blue",
        "target_asset": event.asset or "unknown",
        "team_id": event.team_id or "default",
        "vuln_id": event.vuln_id,
        "matched_event_id": event.trace_id,  # 04번 문서 dwell time 계산의 재료(trace_id로 상관)
        "metadata": {"rule_id": alert.rule_id, "mitre": alert.mitre, "siem_severity": alert.severity},
    }
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(f"{EVENT_COLLECTOR_URL}/events", json=payload)
    except httpx.HTTPError:
        pass  # Event Collector 다운이어도 SIEM 자체 탐지/저장은 계속 동작


async def _on_twin_log_line(path: str, line: str) -> None:
    asset = Path(path).stem.replace("_access", "")
    key = f"twin:{asset}"
    event = parse_twin_log_line(line)
    if event is None:
        _touch_source_health(key, error=True)
        return
    _touch_source_health(key)
    await _process_event(event)


async def _on_network_log_line(source_type: str, source_key: str, line: str,
                               asset: Optional[str] = None, zeek_log_type: Optional[str] = None) -> None:
    key = f"{source_type}:{source_key}"
    event = parse_any(source_type, line, zeek_log_type=zeek_log_type)
    if event is None:
        return  # Zeek 헤더/코멘트 라인 등 정상 스킵(에러 아님)
    if asset:
        event.asset = asset  # IP->asset 매핑 대신, 사이드카가 어느 트윈에 붙어있는지로 직접 태깅(26번 문서 1절 netns 공유 방식)
    _touch_source_health(key)
    await _process_event(event)


async def _syslog_consumer_loop() -> None:
    """pfsense(및 향후 다른 syslog 소스) 큐를 소비해 파싱+처리."""
    while True:
        line = await _syslog_queue.get()
        event = parse_any("pfsense", line.raw_text)
        if event is not None:
            _touch_source_health("pfsense:syslog")
            await _process_event(event)


async def _noise_loop() -> None:
    async def on_noise(noise_event) -> None:
        # 노이즈는 twin 소스 형태로 흘려 실제 트래픽과 동일 파이프라인(탐지엔진 포함)을 통과시킨다
        line = (f'{{"ts": {noise_event.timestamp}, "asset": "{noise_event.asset}", '
               f'"endpoint": "{noise_event.endpoint}", "status": {noise_event.status}, '
               f'"src_ip": "{noise_event.src_ip}", "team_id": "{noise_event.team_id}"}}')
        event = parse_twin_log_line(line)
        if event is not None:
            await _process_event(event)

    gen = NoiseGenerator(base_eps=NOISE_EPS, on_event=on_noise)
    await gen.run_forever()


@app.on_event("startup")
async def startup():
    # M5.1: 트윈 구조화 로그
    twin_paths = [str(LOG_DIR / f"{a}_access.log") for a in TWIN_ASSETS]
    asyncio.create_task(tail_multiple(twin_paths, _on_twin_log_line))

    # M5.2: pfsense syslog(UDP)
    await start_udp_syslog("0.0.0.0", SYSLOG_UDP_PORT, _syslog_queue)
    asyncio.create_task(_syslog_consumer_loop())

    # M5.3: Suricata/Zeek 파일 tail — 26번 문서의 실제 배치 방식(자산별 서브디렉토리:
    # /var/log/siem/{asset}/eve.json, /var/log/siem/{asset}/{log_type}.log)과 정합.
    # 사이드카가 아직 없으면 file_tailer가 파일이 생길 때까지 안전하게 대기한다.
    from services.siem.ingestion.file_tailer import tail_file

    async def _tail_suricata(asset: str, p: str):
        async def handler(line: str):
            await _on_network_log_line("suricata", f"{asset}_suricata", line, asset=asset)
        await tail_file(p, handler)

    async def _tail_zeek(asset: str, log_type: str, p: str):
        async def handler(line: str):
            await _on_network_log_line("zeek", f"{asset}_zeek_{log_type}", line, asset=asset, zeek_log_type=log_type)
        await tail_file(p, handler)

    for asset in TWIN_ASSETS:
        asset_dir = LOG_DIR / asset
        asyncio.create_task(_tail_suricata(asset, str(asset_dir / "eve.json")))
        for lt in ["conn", "dns", "http", "ssl", "notice"]:
            asyncio.create_task(_tail_zeek(asset, lt, str(asset_dir / f"{lt}.log")))

    # M5.6: 노이즈 생성기(옵션)
    if NOISE_ENABLED:
        asyncio.create_task(_noise_loop())


@app.get("/health")
def health():
    return {"status": "ok", "service": "siem_api", "rules_loaded": len(detection_engine.rules)}


@app.get("/search")
async def search(
    text: Optional[str] = None,
    source_type: Optional[str] = None,
    asset: Optional[str] = None,
    severity_min: Optional[int] = None,
    mitre: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
):
    query = SearchQuery(
        text=text, source_type=source_type, asset=asset,
        severity_min=severity_min, mitre=mitre, limit=limit, offset=offset,
    )
    events = await backend.search(query)
    total = await backend.count(query)
    return {"total": total, "returned": len(events), "events": [e.model_dump(mode="json") for e in events]}


@app.get("/alerts")
def get_alerts(status: Optional[str] = None, severity_min: Optional[int] = None, limit: int = 100):
    return {"alerts": alert_store.list_alerts(status=status, severity_min=severity_min, limit=limit)}


@app.post("/alerts/{alert_id}")
def update_alert(alert_id: str, status: str):
    if status not in ("open", "ack", "closed"):
        return {"error": "status must be open|ack|closed"}
    ok = alert_store.update_status(alert_id, status)
    return {"updated": ok}


@app.get("/stats")
async def stats():
    all_query = SearchQuery(limit=1)
    by_source = await backend.aggregate("source_type", all_query)
    by_severity = alert_store.stats_by_severity()
    top_sigs = alert_store.top_signatures()
    return {"events_by_source": by_source, "alerts_by_severity": by_severity, "top_signatures": top_sigs}


@app.get("/sources/health")
def sources_health():
    now = time.time()
    result = {}
    for key, info in _source_health.items():
        last_seen = info["last_seen"]
        result[key] = {
            **info,
            "status": "green" if (last_seen and now - last_seen < 30) else "red",
            "seconds_since_last": (now - last_seen) if last_seen else None,
        }
    result["pfsense:udp_drops"] = {"dropped_total": drop_counters.total()}
    return {"sources": result}


@app.get("/detection/attack-coverage")
def attack_coverage():
    """22번 문서 6절: 로드된 규칙들의 mitre 태그를 집계해 커버리지 매트릭스 생성."""
    coverage: dict[str, list[str]] = {}
    for rule in detection_engine.rules:
        for technique in rule.mitre:
            coverage.setdefault(technique, []).append(rule.id)
    return {"technique_coverage": coverage, "total_rules": len(detection_engine.rules)}


@app.websocket("/ws/logs")
async def ws_logs(websocket: WebSocket):
    await websocket.accept()
    _ws_log_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _ws_log_clients.discard(websocket)


@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await websocket.accept()
    _ws_alert_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _ws_alert_clients.discard(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8040)
