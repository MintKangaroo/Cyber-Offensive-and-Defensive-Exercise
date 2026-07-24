"""
각 트윈(ground_station/power_plant/defense_network)이 Event Collector로
이벤트를 발행할 때 쓰는 경량 클라이언트.

- Best-effort: Event Collector가 죽어있어도 트윈 서비스 자체는 절대 죽지 않아야 하므로
  전부 try/except로 감싸고 짧은 타임아웃을 씁니다.
- team_id는 요청 헤더(X-Team-Id)에서 가져오며 없으면 "default".
"""

import os
import time
import requests

EVENT_COLLECTOR_URL = os.environ.get("EVENT_COLLECTOR_URL", "http://event_collector:8010")
_TIMEOUT = 1.5


def emit_event(
    event_id: str,
    event_type: str,
    actor: str,
    target_asset: str,
    vuln_id: str | None = None,
    phase: str | None = None,
    team_id: str = "default",
    scenario_id: str = "default",
    metadata: dict | None = None,
    trace_id: str | None = None,
    matched_event_id: str | None = None,
    challenge_id: str | None = None,
) -> None:
    payload = {
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": time.time(),
        "actor": actor,
        "team_id": team_id,
        "scenario_id": scenario_id,
        "target_asset": target_asset,
        "vuln_id": vuln_id,
        "phase": phase,
        "trace_id": trace_id,
        "matched_event_id": matched_event_id,
        "challenge_id": challenge_id,
        "metadata": metadata or {},
    }
    try:
        requests.post(f"{EVENT_COLLECTOR_URL}/events", json=payload, timeout=_TIMEOUT)
    except requests.exceptions.RequestException:
        # Event Collector 다운 시에도 트윈 서비스 자체 응답은 지연/실패하면 안 됨
        pass
