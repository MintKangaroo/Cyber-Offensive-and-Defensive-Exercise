"""
플랫폼 관측성(P2-5) 순수 로직 계약 고정.
- Prometheus 노출 형식 렌더(HELP/TYPE/라벨 이스케이프)
- 서비스 health 응답 → 게이지 매핑(up, scrape latency, 숫자 필드)
"""
from services.observability.metrics import render_prometheus, health_to_samples, Sample


def test_render_basic_with_help_and_type():
    out = render_prometheus([
        Sample("cr_service_up", {"service": "auth"}, 1, "Service up", "gauge"),
    ])
    assert "# HELP cr_service_up Service up" in out
    assert "# TYPE cr_service_up gauge" in out
    assert 'cr_service_up{service="auth"} 1' in out


def test_help_type_emitted_once_per_metric():
    out = render_prometheus([
        Sample("cr_up", {"service": "a"}, 1, "up", "gauge"),
        Sample("cr_up", {"service": "b"}, 0, "up", "gauge"),
    ])
    assert out.count("# TYPE cr_up gauge") == 1
    assert out.count("# HELP cr_up up") == 1
    assert 'cr_up{service="a"} 1' in out and 'cr_up{service="b"} 0' in out


def test_label_value_escaped():
    out = render_prometheus([
        Sample("m", {"note": 'a"b\\c'}, 1, "h", "gauge"),
    ])
    # 따옴표·백슬래시 이스케이프
    assert r'note="a\"b\\c"' in out


def test_no_labels_renders_bare():
    out = render_prometheus([Sample("cr_scrape_total", {}, 42, "n", "counter")])
    assert "cr_scrape_total 42" in out


def test_health_to_samples_up_and_latency():
    samples = health_to_samples("event_collector", ok=True, latency_ms=12.5,
                                payload={"status": "ok"})
    names = {(s.name, tuple(sorted(s.labels.items()))): s.value for s in samples}
    assert names[("cr_service_up", (("service", "event_collector"),))] == 1
    assert names[("cr_service_scrape_ms", (("service", "event_collector"),))] == 12.5


def test_health_down_is_zero_and_no_payload_metrics():
    samples = health_to_samples("noc", ok=False, latency_ms=0, payload=None)
    up = [s for s in samples if s.name == "cr_service_up"][0]
    assert up.value == 0
    # 다운이면 payload 파생 게이지 없음
    assert all(s.name in ("cr_service_up", "cr_service_scrape_ms") for s in samples)


def test_numeric_payload_fields_become_gauges():
    samples = health_to_samples("incident", ok=True, latency_ms=3,
                                payload={"service": "incident", "incidents": 7})
    g = [s for s in samples if s.name == "cr_service_incidents"]
    assert g and g[0].value == 7 and g[0].labels == {"service": "incident"}


def test_non_numeric_payload_ignored():
    samples = health_to_samples("x", ok=True, latency_ms=1,
                                payload={"service": "x", "note": "hello"})
    assert not any(s.name == "cr_service_note" for s in samples)
