"""
인젝트 캠페인 저작 검증(shared.injects_campaign) + Scenario Studio 통합 테스트.

핵심 계약: 저작 검증기의 '에러'는 런타임이 거부하는 조건의 상위집합이어야 한다.
런타임(services/injects/main.py load_campaign)이 400 으로 막는 것:
  - spec_id 누락, 중복 spec_id, trigger.after 미존재, trigger.on 무효.
이들이 모두 campaign_issues 에서 error 로 잡히는지 확인한다.
"""
from __future__ import annotations

from shared.injects_campaign import (
    CHANNELS,
    TRIGGER_EVENTS,
    campaign_issues,
    rubric_issues,
)


def _codes(issues, level=None):
    return {i["code"] for i in issues if level is None or i["level"] == level}


def _valid_campaign():
    return {
        "name": "ransomware-crisis",
        "specs": [
            {"spec_id": "media", "template_id": "media-press-call", "at_sec": 0},
            {
                "spec_id": "exec",
                "channel": "exec",
                "subject": "3-line status",
                "body": "Board call in 10 minutes.",
                "deadline_min": 10,
                "rubric": [{"criterion": "Scope/ETA/impact", "max": 15}],
            },
            {
                "spec_id": "regulator",
                "template_id": "regulator-notice",
                "trigger": {"after": "exec", "on": "answered"},
            },
        ],
    }


# ---- constants are single-sourced (runtime re-exports these) ----

def test_constants_match_runtime_reexports():
    from services.injects.engine import TRIGGER_EVENTS as engine_events
    from services.injects.model import CHANNELS as model_channels

    assert engine_events is TRIGGER_EVENTS
    assert model_channels is CHANNELS
    assert set(TRIGGER_EVENTS) == {"answered", "deadline_missed"}
    assert {"media", "exec", "regulator", "legal"} <= set(CHANNELS)


# ---- a well-formed campaign has no errors ----

def test_valid_campaign_has_no_errors():
    issues = campaign_issues(_valid_campaign())
    assert not _codes(issues, "error"), issues


def test_valid_campaign_with_known_library_ids_no_warnings_on_template():
    issues = campaign_issues(
        _valid_campaign(),
        library_ids={"media-press-call", "regulator-notice", "exec-ciso-brief"},
    )
    assert "unknown_template" not in _codes(issues)


# ---- superset-of-runtime error conditions ----

def test_missing_spec_id_is_error():
    c = {"name": "c", "specs": [{"channel": "media", "subject": "s", "body": "b"}]}
    assert "spec_id" in _codes(campaign_issues(c), "error")


def test_duplicate_spec_id_is_error():
    c = {
        "name": "c",
        "specs": [
            {"spec_id": "a", "subject": "s", "body": "b"},
            {"spec_id": "a", "subject": "s", "body": "b"},
        ],
    }
    assert "duplicate_spec" in _codes(campaign_issues(c), "error")


def test_trigger_after_missing_is_error():
    c = {
        "name": "c",
        "specs": [
            {"spec_id": "a", "subject": "s", "body": "b",
             "trigger": {"after": "ghost", "on": "answered"}},
        ],
    }
    assert "trigger_after" in _codes(campaign_issues(c), "error")


def test_trigger_on_invalid_is_error():
    c = {
        "name": "c",
        "specs": [
            {"spec_id": "a", "subject": "s", "body": "b"},
            {"spec_id": "b", "subject": "s", "body": "b",
             "trigger": {"after": "a", "on": "sometime"}},
        ],
    }
    assert "trigger_on" in _codes(campaign_issues(c), "error")


def test_self_trigger_is_error():
    c = {
        "name": "c",
        "specs": [
            {"spec_id": "a", "subject": "s", "body": "b",
             "trigger": {"after": "a", "on": "answered"}},
        ],
    }
    assert "self_trigger" in _codes(campaign_issues(c), "error")


# ---- authoring-quality checks (warnings, never change execution) ----

def test_forward_trigger_is_warning_not_error():
    c = {
        "name": "c",
        "specs": [
            {"spec_id": "a", "subject": "s", "body": "b",
             "trigger": {"after": "b", "on": "answered"}},
            {"spec_id": "b", "subject": "s", "body": "b"},
        ],
    }
    issues = campaign_issues(c)
    assert "forward_trigger" in _codes(issues, "warning")
    assert "trigger_after" not in _codes(issues, "error")


def test_unknown_template_is_warning_when_library_known():
    c = {"name": "c", "specs": [{"spec_id": "a", "template_id": "nope"}]}
    assert "unknown_template" in _codes(campaign_issues(c, library_ids={"real"}), "warning")


def test_unknown_channel_is_warning():
    c = {"name": "c", "specs": [{"spec_id": "a", "channel": "carrier-pigeon",
                                 "subject": "s", "body": "b"}]}
    assert "unknown_channel" in _codes(campaign_issues(c), "warning")


def test_inline_spec_without_subject_body_warns():
    c = {"name": "c", "specs": [{"spec_id": "a"}]}
    codes = _codes(campaign_issues(c), "warning")
    assert "empty_inject" in codes
    assert "no_rubric" in codes


def test_template_spec_without_rubric_does_not_warn_no_rubric():
    c = {"name": "c", "specs": [{"spec_id": "a", "template_id": "media-press-call"}]}
    assert "no_rubric" not in _codes(campaign_issues(c))


# ---- numeric field errors ----

def test_bad_deadline_and_at_sec_are_errors():
    c = {
        "name": "c",
        "specs": [
            {"spec_id": "a", "subject": "s", "body": "b", "deadline_min": 0},
            {"spec_id": "b", "subject": "s", "body": "b", "at_sec": -5},
        ],
    }
    codes = _codes(campaign_issues(c), "error")
    assert "bad_deadline" in codes
    assert "bad_at_sec" in codes


# ---- rubric shape ----

def test_rubric_requires_criterion_and_positive_max():
    issues = rubric_issues([{"criterion": "", "max": 0}, {"max": 5}, "nope"], "x")
    codes = {i["code"] for i in issues}
    assert "rubric_criterion" in codes
    assert "rubric_max" in codes
    assert "rubric_item" in codes


def test_rubric_must_be_list():
    assert rubric_issues({"criterion": "a", "max": 3}, "x")[0]["code"] == "rubric_shape"


# ---- structural guards ----

def test_non_mapping_campaign_is_error():
    assert campaign_issues(["not", "a", "map"])[0]["code"] == "campaign_shape"


def test_empty_specs_is_error():
    assert "campaign_specs" in _codes(campaign_issues({"name": "c", "specs": []}), "error")


def test_missing_name_is_error():
    assert "campaign_name" in _codes(
        campaign_issues({"specs": [{"spec_id": "a", "template_id": "t"}]}), "error"
    )


# ---- Scenario Studio integration: embedded campaign flows through validate() ----

def test_studio_validate_flags_embedded_campaign_error():
    from services.scenario_engine import studio

    src = """
scenario:
  id: CRISIS-DRILL-01
  name: Crisis comms drill
  target_asset: power_plant
  time_limit_sec: 1800
  stages:
    - stage: 1
      name: Observe
      objective_event: red_attack_started
      match: {}
      points: 10
      is_final: true
  blue_objectives:
    - name: Detect
      match_event: blue_detection_success
      points: 10
  injects_campaign:
    name: crisis
    specs:
      - spec_id: media
        template_id: media-press-call
      - spec_id: media
        template_id: exec-ciso-brief
"""
    report = studio.validate(src)
    doc = report["documents"][0]
    codes = {i["code"] for i in doc["issues"]}
    assert "duplicate_spec" in codes
    assert report["ok"] is False


def test_studio_validate_accepts_valid_embedded_campaign():
    from services.scenario_engine import studio

    src = """
scenario:
  id: CRISIS-DRILL-02
  name: Crisis comms drill
  target_asset: power_plant
  time_limit_sec: 1800
  stages:
    - stage: 1
      name: Observe
      objective_event: red_attack_started
      match: {}
      points: 10
      is_final: true
  blue_objectives:
    - name: Detect
      match_event: blue_detection_success
      points: 10
  injects_campaign:
    name: crisis
    specs:
      - spec_id: media
        template_id: media-press-call
        at_sec: 0
      - spec_id: regulator
        template_id: regulator-notice
        trigger: {after: media, on: answered}
"""
    report = studio.validate(src)
    assert report["ok"] is True, report["documents"][0]["issues"]
