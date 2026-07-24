"""
SIEM 탐지엔진 _event_epoch 유닛 테스트 (M5 버그 회귀 방지)
==========================================================
회귀: NormalizedEvent.model_dump(mode="json")를 거치면 timestamp가 ISO 문자열이 되고,
threshold/sequence 윈도우 연산(`ts - window_sec`)이 `str - int` TypeError로 탐지를 죽였다.
_event_epoch가 float/ISO/datetime/None/쓰레기를 모두 float로 흡수해야 한다.
"""
import time
from datetime import datetime, timezone
from services.siem.detection.engine import _event_epoch


def test_epoch_from_float():
    assert _event_epoch({"timestamp": 1700000000.5}) == 1700000000.5


def test_epoch_from_int():
    assert _event_epoch({"timestamp": 1700000000}) == 1700000000.0


def test_epoch_from_iso_string():
    """M5 회귀: ISO 문자열도 epoch float로."""
    dt = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    got = _event_epoch({"timestamp": dt.isoformat()})
    assert abs(got - dt.timestamp()) < 1e-6


def test_epoch_from_iso_z_suffix():
    got = _event_epoch({"timestamp": "2024-01-01T00:00:00Z"})
    expected = datetime(2024, 1, 1, tzinfo=timezone.utc).timestamp()
    assert abs(got - expected) < 1e-6


def test_epoch_from_datetime_object():
    dt = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    assert abs(_event_epoch({"timestamp": dt}) - dt.timestamp()) < 1e-6


def test_epoch_none_falls_back_to_now():
    got = _event_epoch({})
    assert abs(got - time.time()) < 5   # 대략 현재시각


def test_epoch_garbage_string_falls_back():
    got = _event_epoch({"timestamp": "not-a-date"})
    assert abs(got - time.time()) < 5


def test_epoch_result_supports_arithmetic():
    """실제 사용처: ts - window_sec 연산이 TypeError 없이 되어야 함."""
    ts = _event_epoch({"timestamp": "2024-01-01T00:00:00+00:00"})
    assert isinstance(ts - 60, float)
