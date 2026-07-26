"""
관측성 메트릭 순수 로직(P2-5)
==============================
Prometheus 노출 형식 렌더 + 서비스 health → 게이지 매핑. 상태 없는 순수함수(테스트 용이).

서비스마다 계측 라이브러리를 심는 대신, 각 서비스가 이미 제공하는 `/health`(도달성 + 숫자 카운터)
를 관측성 서비스가 스크레이프해 표준 형식으로 노출한다. 최소 침습으로 플랫폼 전역 지표를 얻는다.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Sample:
    name: str
    labels: dict[str, object]
    value: float
    help: str = ""
    type: str = "gauge"


def _escape_label(v: object) -> str:
    s = str(v)
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _fmt_value(v: float) -> str:
    # 정수는 정수로, 실수는 그대로(불필요한 .0 방지)
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, int) or (isinstance(v, float) and v.is_integer()):
        return str(int(v))
    return repr(v)


def render_prometheus(samples: list[Sample]) -> str:
    """Prometheus 텍스트 노출 형식. 메트릭당 HELP/TYPE 는 한 번만."""
    lines: list[str] = []
    seen: set[str] = set()
    for s in samples:
        if s.name not in seen:
            seen.add(s.name)
            if s.help:
                lines.append(f"# HELP {s.name} {s.help}")
            lines.append(f"# TYPE {s.name} {s.type}")
        if s.labels:
            lab = ",".join(f'{k}="{_escape_label(v)}"' for k, v in s.labels.items())
            lines.append(f"{s.name}{{{lab}}} {_fmt_value(s.value)}")
        else:
            lines.append(f"{s.name} {_fmt_value(s.value)}")
    return "\n".join(lines) + "\n"


def health_to_samples(service: str, ok: bool, latency_ms: float,
                      payload: dict | None) -> list[Sample]:
    """단일 서비스 health 결과 → 샘플들.
    - cr_service_up{service} : 1/0
    - cr_service_scrape_ms{service} : 스크레이프 지연
    - cr_service_<field>{service} : payload 의 숫자 필드(불리언/문자열 제외)
    """
    out = [
        Sample("cr_service_up", {"service": service}, 1 if ok else 0,
               "Service reachable (1=up,0=down)", "gauge"),
        Sample("cr_service_scrape_ms", {"service": service}, float(latency_ms),
               "Health scrape latency in milliseconds", "gauge"),
    ]
    if ok and isinstance(payload, dict):
        for k, v in payload.items():
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                continue   # 문자열/불리언 필드(status 등)는 게이지 아님
            out.append(Sample(f"cr_service_{k}", {"service": service}, float(v),
                              f"Reported '{k}' from {service}/health", "gauge"))
    return out
