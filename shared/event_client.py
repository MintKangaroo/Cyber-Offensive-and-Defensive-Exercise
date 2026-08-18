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
# 매치별 트윈 셋(P3): 이 트윈이 발행하는 이벤트의 기본 파티션 키. per-match 배포 시
# MATCH_SCENARIO_ID=match_x 를 주면 scenario_id 미지정 호출이 전부 자동으로 매치에 태깅된다
# (코어 3섹터처럼 호출부마다 scenario_id를 안 넘겨도 매치별 이벤트/점수 격리가 적용됨).
_DEFAULT_SCENARIO = os.environ.get("MATCH_SCENARIO_ID", "default")
# 감사 3.3: 팀 귀속을 서버측(배포 env)에서 결정. per-team 트윈 배포는 TEAM_ID 를 주입하며,
# 그 경우 요청 헤더(X-Team-Id)에서 흘러온 team_id 인자를 무시하고 이 값을 강제한다
# (공격자가 헤더로 타 팀에 공격을 귀속시키는 조작 차단). 미설정(dev/공용)이면 인자값 사용.
_FIXED_TEAM = os.environ.get("TEAM_ID", "").strip()


def emit_event(
    event_id: str,
    event_type: str,
    actor: str,
    target_asset: str,
    vuln_id: str | None = None,
    phase: str | None = None,
    team_id: str = "default",
    scenario_id: str | None = None,
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
        "team_id": _FIXED_TEAM or team_id,   # 감사 3.3: 배포 env가 있으면 서버측 값 강제
        "scenario_id": scenario_id if scenario_id is not None else _DEFAULT_SCENARIO,
        "target_asset": target_asset,
        "vuln_id": vuln_id,
        "phase": phase,
        "trace_id": trace_id,
        "matched_event_id": matched_event_id,
        "challenge_id": challenge_id,
        "metadata": metadata or {},
    }
    try:
        # 감사 3.1: 내부 S2S 토큰(SERVICE_TOKEN 미설정 dev면 빈 헤더).
        from shared.service_auth import service_headers
        requests.post(f"{EVENT_COLLECTOR_URL}/events", json=payload,
                      headers=service_headers(), timeout=_TIMEOUT)
    except requests.exceptions.RequestException:
        # Event Collector 다운 시에도 트윈 서비스 자체 응답은 지연/실패하면 안 됨
        pass
