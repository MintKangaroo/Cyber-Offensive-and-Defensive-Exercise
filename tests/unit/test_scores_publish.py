"""event_collector 'scores 토픽 발행' 회귀 — 라이브 스코어보드/SolveLog 가 켜지는 바로 그 분기.

라이브파이어 콘솔의 스코어보드/점수/SolveLog 는 event_collector 가 /stream 으로 흘리는 scores
토픽을 구독해 움직인다. scores 프레임을 만드는 유일한 곳은 _post_scoring 이다: scoring_engine
/score/ingest 가 200 + awarded 를 돌려줄 때만 _publish_durable("scores", {...}) 한다
(services/event_collector/main.py:622-630).

기존 테스트는 (1) scorer 의 HTTP 응답까지만 보거나(test_scoring_engine), (2) 포워더를
monkeypatch 로 스텁(test_service_scope) 하므로, "awarded ⇒ scores 발행" 인과와 그 프레임의
payload shape(프런트가 읽는 team_id/actor/category/points)는 어떤 유닛도 검증하지 않았다 →
_post_scoring 이 발행 키를 바꾸거나 분기를 끊어도 전 테스트 통과하고 콘솔 스코어보드가 조용히 멈춘다.
이 테스트는 (발전소 라이브 채점 E2E 로 실증한) 그 분기를 고정한다.
"""
import asyncio
import os

os.environ.setdefault("RBAC_ALLOW_INSECURE_DEV", "true")

import pytest

from services.event_collector import main as ec


class _Resp:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


class _Client:
    def __init__(self, resp):
        self._resp = resp
        self.calls = []

    async def post(self, url, json=None, headers=None):
        self.calls.append({"url": url, "json": json})
        if isinstance(self._resp, Exception):
            raise self._resp
        return self._resp


@pytest.fixture
def capture(monkeypatch):
    """_publish_durable 호출을 가로채고 외부 S2S 헤더는 무해화."""
    published: list = []
    monkeypatch.setattr(ec, "_publish_durable", lambda topic, data: published.append((topic, data)))
    monkeypatch.setattr(ec, "service_headers", lambda: {})
    return published


def _payload():
    return {"team_id": "default", "actor": "red", "scenario_id": "S1",
            "event_type": "red_objective_success", "metadata": {"match_id": "M1"}}


def _run_post_scoring(monkeypatch, resp):
    client = _Client(resp)
    monkeypatch.setattr(ec, "_get_scoring_client", lambda: client)
    ok, err = asyncio.run(ec._post_scoring(_payload()))
    return ok, err, client


def test_awarded_publishes_scores_frame_with_console_contract(monkeypatch, capture):
    """200 + awarded → scores 프레임 1건 발행, payload 가 콘솔 계약(team_id/actor/category/points)과 일치."""
    ok, err, client = _run_post_scoring(
        monkeypatch, _Resp(200, {"awarded": True, "category": "objective", "points": 100}))

    assert (ok, err) == (True, None)
    assert client.calls and client.calls[0]["url"].endswith("/score/ingest")
    assert len(capture) == 1, "awarded 면 scores 토픽을 정확히 1건 발행해야"
    topic, data = capture[0]
    assert topic == "scores"
    # 프런트(App.tsx)가 읽는 필드가 정확히 이 이름/값으로 실려야(드리프트 차단)
    assert data["team_id"] == "default"
    assert data["actor"] == "red"
    assert data["category"] == "objective"
    assert data["points"] == 100
    assert data["scenario_id"] == "S1"
    assert data["match_id"] == "M1"      # metadata.match_id 승격
    assert "timestamp" in data


def test_not_awarded_does_not_publish(monkeypatch, capture):
    """200 이지만 awarded=False(멱등 재공격/비채점 이벤트) → scores 발행 없음(과점수 방지)."""
    ok, err, _ = _run_post_scoring(
        monkeypatch, _Resp(200, {"awarded": False, "category": None, "points": 0}))
    assert (ok, err) == (True, None)
    assert capture == [], "awarded=False 면 scores 를 발행하면 안 됨"


def test_non_200_does_not_publish(monkeypatch, capture):
    """scoring 비정상(5xx) → scores 발행 없음, (False, 'HTTP n') 반환(상위에서 DLQ 스풀)."""
    ok, err, _ = _run_post_scoring(monkeypatch, _Resp(503, {}))
    assert ok is False and err == "HTTP 503"
    assert capture == []


def test_transport_error_does_not_publish(monkeypatch, capture):
    """전송 예외 → 발행 없음, (False, 예외명) 반환(무손실: 상위가 DLQ 스풀)."""
    import httpx
    ok, err, _ = _run_post_scoring(monkeypatch, httpx.ConnectError("down"))
    assert ok is False and err == "ConnectError"
    assert capture == []
