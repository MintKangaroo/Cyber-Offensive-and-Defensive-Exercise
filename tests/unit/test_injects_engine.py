"""
인젝트 엔진(P1-4 전면 구현) 계약 고정.
============================================
캠페인 = 순서가 정해진 인젝트 시나리오. 엔진이 시간·조건에 따라 자동 발사한다.
  - 시간 예약(at_sec): elapsed 경과 시 발사.
  - 트리거(answered): 선행 인젝트가 응답되면 후속 발사.
  - 에스컬레이션(deadline_missed): 마감 놓치면 후속(재촉) 인젝트 발사.
순수함수를 직접 검증(결정적) + 발사 파이프라인 하나를 TestClient로 종단 검증.
"""
import os
import tempfile

# TestClient import 전에 격리된 DB 경로 + dev(무토큰) 모드 보장.
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="injects-engine-")
for _k in ("RBAC_TOKENS", "INSTRUCTOR_TOKEN", "RED_TOKEN", "BLUE_TOKEN",
           "OBSERVER_TOKEN", "AUTH_JWT_SECRET", "OBSERVER_READ_ENFORCE"):
    os.environ.pop(_k, None)
os.environ["RBAC_ALLOW_INSECURE_DEV"] = "true"  # fail-closed rbac(감사 1.6)에서 dev 무토큰 통과

import pytest
from fastapi.testclient import TestClient

from services.injects.engine import (
    InjectState, TRIGGER_EVENTS, resolve_spec, spec_is_due, compute_due,
    state_from_inject, campaign_progress,
)


# ---------------------------------------------------------------- 순수 함수: 시간 예약
def test_scheduled_due_only_after_offset():
    specs = [{"spec_id": "a", "at_sec": 0}, {"spec_id": "b", "at_sec": 60}]
    assert compute_due(specs, elapsed_sec=0, states={}) == ["a"]
    assert compute_due(specs, elapsed_sec=59, states={}) == ["a"]
    assert compute_due(specs, elapsed_sec=60, states={}) == ["a", "b"]


def test_already_fired_not_due_again():
    specs = [{"spec_id": "a", "at_sec": 0}]
    states = {"a": InjectState(fired=True)}
    assert compute_due(specs, elapsed_sec=100, states=states) == []


def test_compute_due_preserves_order_deterministic():
    specs = [{"spec_id": "x", "at_sec": 0}, {"spec_id": "y", "at_sec": 0},
             {"spec_id": "z", "at_sec": 0}]
    assert compute_due(specs, 5, {}) == ["x", "y", "z"]


# --------------------------------------------------------------- 순수 함수: 트리거(응답)
def test_trigger_answered_fires_only_after_parent_answered():
    specs = [{"spec_id": "p", "at_sec": 0},
             {"spec_id": "c", "trigger": {"after": "p", "on": "answered"}}]
    # 부모 발사됐지만 미응답 → 후속 대기
    st = {"p": InjectState(fired=True, answered=False)}
    assert compute_due(specs, elapsed_sec=1000, states=st) == []
    # 부모 응답됨 → 후속 발사
    st = {"p": InjectState(fired=True, answered=True)}
    assert compute_due(specs, elapsed_sec=1000, states=st) == ["c"]


def test_trigger_waits_until_parent_fired():
    specs = [{"spec_id": "c", "trigger": {"after": "p", "on": "answered"}}]
    # 부모 상태 자체가 없음(아직 발사 안 됨) → 후속 발사 안 함
    assert compute_due(specs, elapsed_sec=9999, states={}) == []


# ---------------------------------------------------------- 순수 함수: 에스컬레이션(마감)
def test_deadline_missed_fires_escalation():
    specs = [{"spec_id": "p", "at_sec": 0},
             {"spec_id": "esc", "trigger": {"after": "p", "on": "deadline_missed"}}]
    # 마감 전 → 대기
    st = {"p": InjectState(fired=True, deadline_missed=False)}
    assert compute_due(specs, 10, st) == []
    # 마감 놓침 + 미응답 → 에스컬레이션 발사
    st = {"p": InjectState(fired=True, deadline_missed=True)}
    assert compute_due(specs, 10, st) == ["esc"]


def test_deadline_missed_but_answered_no_escalation():
    specs = [{"spec_id": "esc", "trigger": {"after": "p", "on": "deadline_missed"}}]
    # 늦게라도 응답했으면 에스컬레이션 발사 안 함
    st = {"p": InjectState(fired=True, deadline_missed=True, answered=True)}
    assert compute_due(specs, 10, st) == []


def test_unknown_trigger_event_never_fires():
    specs = [{"spec_id": "c", "trigger": {"after": "p", "on": "bogus"}}]
    st = {"p": InjectState(fired=True, answered=True, deadline_missed=True)}
    assert compute_due(specs, 10, st) == []


def test_trigger_events_constant():
    assert set(TRIGGER_EVENTS) == {"answered", "deadline_missed"}


# ------------------------------------------------------------------- state_from_inject
def test_state_from_inject_answered():
    st = state_from_inject(deadline_at=100, response_at=90, now=200)
    assert st.fired and st.answered and not st.deadline_missed


def test_state_from_inject_missed():
    st = state_from_inject(deadline_at=100, response_at=None, now=150)
    assert st.fired and not st.answered and st.deadline_missed


def test_state_from_inject_pending():
    st = state_from_inject(deadline_at=100, response_at=None, now=50)
    assert st.fired and not st.answered and not st.deadline_missed


# -------------------------------------------------------------------------- resolve_spec
def test_resolve_spec_from_library():
    lib = {"tpl1": {"channel": "media", "from": "기자", "subject": "s", "body": "b",
                    "deadline_min": 15, "rubric": [{"criterion": "x", "max": 5}]}}
    out = resolve_spec({"spec_id": "a", "template_id": "tpl1"}, lib)
    assert out["channel"] == "media" and out["sender"] == "기자"
    assert out["deadline_min"] == 15 and out["rubric"][0]["max"] == 5


def test_resolve_spec_inline_overrides_template():
    lib = {"tpl1": {"channel": "media", "subject": "orig", "deadline_min": 15}}
    out = resolve_spec({"spec_id": "a", "template_id": "tpl1", "subject": "custom",
                        "deadline_min": 5}, lib)
    assert out["subject"] == "custom" and out["deadline_min"] == 5


def test_resolve_spec_inline_only():
    out = resolve_spec({"spec_id": "a", "channel": "exec", "sender": "CEO",
                        "subject": "hi", "body": "yo"}, {})
    assert out["channel"] == "exec" and out["deadline_min"] == 30  # 기본값


# --------------------------------------------------------------------- campaign_progress
def test_campaign_progress():
    specs = [{"spec_id": "a"}, {"spec_id": "b"}]
    prog = campaign_progress(specs, ["t1", "t2"], {"t1": {"a": "INJ-1"}})
    assert prog["total"] == 4 and prog["fired"] == 1 and prog["pct"] == 25


# =============================================================== 종단(TestClient) 파이프라인
@pytest.fixture()
def client():
    from services.injects import main as inj
    c = TestClient(inj.app)
    c.post("/admin/reset")
    yield c
    c.post("/admin/reset")


def test_campaign_load_and_scheduled_tick(client):
    """예시 캠페인 로드 → 과거 시작 → tick 시 시간 예약 인젝트가 발사된다."""
    import time
    r = client.post("/injects/campaign", json={
        "use_example": True, "team_ids": ["blue"], "start_time": time.time() - 1000})
    assert r.status_code == 200, r.text
    cid = r.json()["campaign_id"]

    fired = client.post("/injects/tick", json={"campaign_id": cid}).json()
    spec_ids = {f["spec_id"] for f in fired["injects"]}
    # 언론(at 0) + 경영(at 60) 은 발사, 규제(경영 응답 후) 는 대기.
    assert {"media", "exec"} <= spec_ids
    assert "regulator" not in spec_ids
    # 인박스에 실제 배달됐는지 확인.
    inbox = client.get("/injects/inbox", params={"team_id": "blue"}).json()
    assert inbox["count"] >= 2


def test_trigger_answered_then_escalation_pipeline(client):
    """마감 0분 스펙 → 첫 tick 발사 → 다음 tick 마감초과 에스컬레이션 → 응답 후 규제 트리거."""
    specs = [
        {"spec_id": "brief", "channel": "exec", "sender": "CEO", "subject": "3줄 요약",
         "body": "지금.", "deadline_min": 0, "at_sec": 0,
         "rubric": [{"criterion": "요약", "max": 10}]},
        {"spec_id": "brief-esc", "channel": "exec", "sender": "이사회", "subject": "재촉",
         "body": "즉시 보고", "deadline_min": 5,
         "trigger": {"after": "brief", "on": "deadline_missed"}},
        {"spec_id": "reg", "channel": "regulator", "sender": "규제기관", "subject": "통보",
         "body": "신고 여부?", "deadline_min": 45,
         "trigger": {"after": "brief", "on": "answered"}},
    ]
    cid = client.post("/injects/campaign", json={
        "name": "custom", "team_ids": ["blue"], "specs": specs}).json()["campaign_id"]

    # tick1: brief 발사(마감=지금).
    f1 = client.post("/injects/tick", json={"campaign_id": cid}).json()
    ids1 = {f["spec_id"]: f["inject_id"] for f in f1["injects"]}
    assert set(ids1) == {"brief"}

    # tick2: brief 마감 초과(now>deadline) → 에스컬레이션 발사.
    f2 = client.post("/injects/tick", json={"campaign_id": cid}).json()
    esc = [f for f in f2["injects"] if f["spec_id"] == "brief-esc"]
    assert esc and esc[0]["reason"] == "deadline_missed"

    # brief 에 응답 → tick3 에서 규제(answered 트리거) 발사.
    client.post(f"/injects/{ids1['brief']}/respond",
                json={"team_id": "blue", "response_text": "복구중"})
    f3 = client.post("/injects/tick", json={"campaign_id": cid}).json()
    assert {"reg"} <= {f["spec_id"] for f in f3["injects"]}

    # 상태: 3개 스펙 모두 발사 완료.
    status = client.get("/injects/campaign/status", params={"campaign_id": cid}).json()
    prog = status["campaigns"][0]["progress"]
    assert prog["fired"] == 3 and prog["total"] == 3


def test_campaign_validation_rejects_bad_trigger(client):
    r = client.post("/injects/campaign", json={
        "team_ids": ["blue"],
        "specs": [{"spec_id": "a", "channel": "exec",
                   "trigger": {"after": "nope", "on": "answered"}}]})
    assert r.status_code == 400
