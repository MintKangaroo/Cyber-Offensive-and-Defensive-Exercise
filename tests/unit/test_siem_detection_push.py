"""SIEM '탐지 성공 → blue_detection_success 발행' 회귀 — Blue 탐지 점수가 켜지는 바로 그 경계.

라이브파이어 콘솔의 DEFENSE 열/방어 Solve Log 는, 공격이 SIEM 규칙에 걸렸을 때 SIEM 이
event_collector 로 밀어넣는 `blue_detection_success` 이벤트에서 출발한다. 그 이벤트를 만드는
유일한 곳은 services/siem/api/main.py 의 _push_detection_to_livefire 이고(:188), 그 함수는
detection_engine.evaluate 가 돌려준 Alert 하나당 EVENT_COLLECTOR_URL/events 로 POST 한다(:203).

기존 테스트 커버리지의 공백(실측 매핑으로 확인):
  - test_dead_rules_revival / test_siem_engine 은 detection_engine.evaluate 까지만 본다(Alert 생성).
  - test_scoring_engine 은 "blue_detection_success 가 들어오면 +20" 을 본다(scoring 쪽).
  - test_scores_publish 는 event_collector 가 awarded 를 scores 로 발행하는 걸 본다.
  → 그 사이의 연결고리, 즉 "SIEM 이 매칭한 Alert → 정확한 blue_detection_success payload 를
     event_collector 로 POST" 하는 _push_detection_to_livefire 는 어떤 유닛도 검증하지 않았다.
     이 함수가 event_type 을 바꾸거나 actor/target_asset/vuln_id 필드를 떨구면 전 테스트가
     통과한 채로 콘솔 DEFENSE 열이 조용히 멈춘다(탐지 라이브 E2E 로 실증한 바로 그 경로).

이 테스트는 실제 트윈 access-log 한 줄을 실제 파서(parse_twin_log_line)로 정규화하고 실제
규칙엔진(detection_engine)에 태워 Alert 를 얻은 뒤, _push_detection_to_livefire 의 POST 를
가로채 payload 계약(event_type/actor/target_asset/team_id/vuln_id/matched_event_id/metadata)을
고정한다. 즉 "로그 라인 → 규칙 매칭 → 발행" 전 체인을 유닛 수준에서 묶는다.
"""
import asyncio
import json
import os
import time

os.environ.setdefault("RBAC_ALLOW_INSECURE_DEV", "true")

import pytest

from services.siem.api import main as siem
from services.siem.parsers.twin import parse_twin_log_line


# 실 트윈(power_plant)이 미인증 PLC 쓰기(PP-001) 때 남기는 access-log 한 줄과 동일한 형태.
# 라이브 E2E 에서 /var/log/siem/power_plant/power_plant_access.log 에 실제로 찍힌 라인이다.
def _twin_log_line(vuln_id="PP-001", trace="8274c8321ddc51b0"):
    return json.dumps({
        "ts": time.time(), "asset": "power_plant", "endpoint": "/api/plc/write",
        "method": "POST", "status": 200, "src_ip": "127.0.0.1",
        "vuln_id": vuln_id, "team_id": "default", "trace_id": trace,
        "ua": "pytest", "latency_ms": 12.3,
    })


class _FakeClient:
    """httpx.AsyncClient 대체: POST 를 가로채 저장하거나, 주입된 예외를 던진다."""
    captured: list = []

    def __init__(self, *a, raise_exc=None, **k):
        self._raise = raise_exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, json=None, headers=None):
        type(self).captured.append({"url": url, "json": json, "headers": headers})
        if self._raise is not None:
            raise self._raise


@pytest.fixture
def capture_post(monkeypatch):
    _FakeClient.captured = []
    monkeypatch.setattr(siem.httpx, "AsyncClient", lambda *a, **k: _FakeClient(*a, **k))
    monkeypatch.setattr(siem, "service_headers", lambda: {})  # 외부 S2S 토큰 무해화
    return _FakeClient.captured


def _match_alert(vuln_id="PP-001"):
    """실 파서 + 실 규칙엔진으로 Alert 를 얻는다(파서→규칙 체인도 함께 고정)."""
    event = parse_twin_log_line(_twin_log_line(vuln_id=vuln_id))
    assert event is not None and event.vuln_id == vuln_id
    alerts = siem.detection_engine.evaluate(event.model_dump(mode="json"))
    return event, alerts


def test_pp001_log_line_matches_plc_write_rule():
    """파서→규칙엔진: PP-001 access 로그가 TWIN-PLC-WRITE-001 규칙에 실제로 매칭된다."""
    _event, alerts = _match_alert("PP-001")
    rule_ids = {a.rule_id for a in alerts}
    assert "TWIN-PLC-WRITE-001" in rule_ids, f"PP-001 이 PLC 쓰기 규칙에 안 걸림: {rule_ids}"


def test_benign_line_produces_no_twin_match():
    """vuln_id 없는 평범한 라인은 TWIN-* 매칭을 만들지 않는다(과탐 방지)."""
    event = parse_twin_log_line(json.dumps({
        "ts": time.time(), "asset": "power_plant", "endpoint": "/health",
        "method": "GET", "status": 200, "src_ip": "127.0.0.1",
        "vuln_id": None, "team_id": "default", "trace_id": "x",
    }))
    alerts = siem.detection_engine.evaluate(event.model_dump(mode="json"))
    assert not any(a.rule_id == "TWIN-PLC-WRITE-001" for a in alerts)


def test_detection_pushes_blue_event_with_console_contract(capture_post):
    """매칭된 Alert → event_collector/events 로 blue_detection_success 1건 POST.
    payload 가 scoring(blue_detection_success→detection_success +20) + 콘솔(actor/target_asset)
    계약과 정확히 일치해야(드리프트 차단)."""
    event, alerts = _match_alert("PP-001")
    alert = next(a for a in alerts if a.rule_id == "TWIN-PLC-WRITE-001")

    asyncio.run(siem._push_detection_to_livefire(alert, event))

    assert len(capture_post) == 1, "매칭 1건이면 정확히 1건 발행해야"
    call = capture_post[0]
    assert call["url"].endswith("/events")
    p = call["json"]
    # scoring 이 detection_success(+20)로 채점하는 트리거 문자열
    assert p["event_type"] == "blue_detection_success"
    # 콘솔 App.tsx 가 scores 라우팅에 쓰는 필드(actor!=='red' → DEFENSE)
    assert p["actor"] == "blue"
    assert p["target_asset"] == "power_plant"
    assert p["team_id"] == "default"
    assert p["vuln_id"] == "PP-001"
    # dwell-time 상관을 위해 원 공격 trace_id 를 matched_event_id 로 실어야(event_collector 가 조인)
    assert p["matched_event_id"] == event.trace_id
    # 규칙 출처/심각도 메타(아레나 StrikeLog·AAR 용)
    assert p["metadata"]["rule_id"] == "TWIN-PLC-WRITE-001"
    assert p["metadata"]["siem_severity"] == alert.severity
    assert "T0836" in p["metadata"]["mitre"]


def test_push_is_best_effort_on_collector_down(capture_post, monkeypatch):
    """event_collector 다운(HTTPError)이어도 _push 는 삼키고 SIEM 을 죽이지 않는다."""
    import httpx
    monkeypatch.setattr(
        siem.httpx, "AsyncClient",
        lambda *a, **k: _FakeClient(*a, raise_exc=httpx.ConnectError("down"), **k))
    event, alerts = _match_alert("PP-001")
    alert = next(a for a in alerts if a.rule_id == "TWIN-PLC-WRITE-001")
    # 예외가 전파되면 실패(함수가 httpx.HTTPError 를 삼켜야 한다)
    asyncio.run(siem._push_detection_to_livefire(alert, event))
