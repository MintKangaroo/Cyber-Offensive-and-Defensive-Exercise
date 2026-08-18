"""
죽은 탐지 룰 복구 발화 테스트 (감사 4.5)
=========================================
- SEQ-KILLCHAIN-001: step3가 존재하지 않는 필드(event_type)라 절대 발화 못 하던 것을
  관측 가능한 필드로 교정 → 스캔→트윈공격→트윈후속 시퀀스가 발화하는지.
- NET-C2-BEACON-001: allowlist가 서비스명이라 무효 + 내부 하트비트 오탐 →
  외부 IP 주기연결은 발화하고, 내부(사설 IP) 주기연결은 발화하지 않는지.
"""
from services.siem.detection.engine import Rule, DetectionEngine, _is_private_or_local_ip


def _seq_rule():
    return Rule(
        id="SEQ-KILLCHAIN-001", title="killchain", severity=4, mitre=[],
        kind="sequence", sequence_group_by="src.ip", sequence_within_sec=300,
        sequence_steps=[{"category": "network"}, {"source_type": "twin"}, {"source_type": "twin"}],
    )


def _beacon_rule():
    return Rule(
        id="NET-C2-BEACON-001", title="beacon", severity=4, mitre=[],
        kind="periodicity", periodicity_group_by_src="src.ip", periodicity_group_by_dst="dst.ip",
        periodicity_min_observations=5, periodicity_jitter_threshold=0.1,
        periodicity_window_sec=3600, periodicity_allowlist_dst=[],
    )


def _ev(t, **kw):
    e = {"timestamp": t, "src": {"ip": "172.16.9.9"}, "dst": {"ip": "8.8.8.8"}}
    e.update(kw)
    return e


def test_seq_killchain_fires_after_fix():
    eng = DetectionEngine([_seq_rule()])
    src = {"ip": "172.16.9.9"}
    assert eng.evaluate({"timestamp": 1.0, "category": "network", "src": src}) == []
    assert eng.evaluate({"timestamp": 2.0, "source_type": "twin", "src": src}) == []
    alerts = eng.evaluate({"timestamp": 3.0, "source_type": "twin", "src": src})
    assert any(a.rule_id == "SEQ-KILLCHAIN-001" for a in alerts), "killchain 시퀀스가 발화해야 함"


def test_beacon_fires_on_external_regular_interval():
    eng = DetectionEngine([_beacon_rule()])
    fired = []
    for i in range(8):  # 60초 간격 규칙적 연결(jitter≈0) → 비콘
        fired += eng.evaluate(_ev(1000.0 + i * 60))
    assert any(a.rule_id == "NET-C2-BEACON-001" for a in fired), "외부 주기연결은 비콘 발화"


def test_beacon_suppressed_for_internal_dst():
    eng = DetectionEngine([_beacon_rule()])
    fired = []
    for i in range(8):  # 동일 패턴이지만 목적지가 내부(사설 IP) → allowlist(오탐 방지)
        fired += eng.evaluate(_ev(1000.0 + i * 60, dst={"ip": "172.18.0.5"}))
    assert not any(a.rule_id == "NET-C2-BEACON-001" for a in fired), "내부 하트비트는 비콘 아님"


def test_private_ip_helper():
    assert _is_private_or_local_ip("172.18.0.5") is True
    assert _is_private_or_local_ip("10.0.0.1") is True
    assert _is_private_or_local_ip("127.0.0.1") is True
    assert _is_private_or_local_ip("event_collector") is True   # 비-IP는 내부 취급(오탐 방지)
    assert _is_private_or_local_ip("8.8.8.8") is False     # 외부 IP
