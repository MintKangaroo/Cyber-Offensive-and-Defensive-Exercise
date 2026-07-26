"""
플랫폼 관측성 서비스(P2-5)
===========================
컨트롤플레인 전 서비스의 `/health` 를 스크레이프해 Prometheus 노출 형식(`/metrics`)과
JSON 요약(`/observability/summary`)으로 노출한다. 각 서비스에 계측 코드를 심지 않고도
플랫폼 전역 가동성·지연·핵심 카운터를 한곳에서 본다(최소 침습).

- GET /metrics            : Prometheus 텍스트(up/scrape_ms + health 숫자필드 게이지)
- GET /observability/summary : {up, down, total, services:[...]}
- 대상은 OBS_TARGETS(JSON) 로 재정의 가능. 미설정 시 docker 서비스명 기본값.

Prometheus/Grafana 를 붙이면 이 /metrics 를 스크레이프 타깃으로 등록하면 된다.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import metrics  # noqa: E402

# 대상 서비스: 이름 → base URL. docker 네트워크 기본값(OBS_TARGETS 로 재정의).
_DEFAULT_TARGETS = {
    "event_collector": "http://event_collector:8010",
    "scoring_engine": "http://scoring_engine:8020",
    "config_service": "http://config_service:8030",
    "siem_api": "http://siem_api:8040",
    "instructor_api": "http://instructor_api:8050",
    "auth": "http://auth:8051",
    "range_control": "http://range_control:8055",
    "challenge_portal": "http://challenge_portal:8060",
    "noc_monitor": "http://noc_monitor:8070",
    "edr_backend": "http://edr_backend:8080",
    "incident": "http://incident:8095",
    "injects": "http://injects:8096",
}


def _targets() -> dict[str, str]:
    raw = os.environ.get("OBS_TARGETS", "").strip()
    if raw:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
    return _DEFAULT_TARGETS


app = FastAPI(title="Platform Observability")


async def _scrape_one(client: httpx.AsyncClient, name: str, base: str) -> dict:
    t0 = time.perf_counter()
    try:
        r = await client.get(f"{base}/health", timeout=3.0)
        latency = (time.perf_counter() - t0) * 1000
        ok = r.status_code < 500
        payload = r.json() if ok else None
        return {"name": name, "ok": ok, "latency_ms": round(latency, 2), "payload": payload}
    except (httpx.HTTPError, ValueError):
        return {"name": name, "ok": False, "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
                "payload": None}


async def _scrape_all() -> list[dict]:
    targets = _targets()
    async with httpx.AsyncClient() as client:
        return await asyncio.gather(*[_scrape_one(client, n, b) for n, b in targets.items()])


@app.get("/health")
def health():
    return {"service": "observability", "targets": len(_targets())}


@app.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    results = await _scrape_all()
    samples: list[metrics.Sample] = []
    for r in results:
        samples.extend(metrics.health_to_samples(r["name"], r["ok"], r["latency_ms"], r["payload"]))
    up = sum(1 for r in results if r["ok"])
    samples.append(metrics.Sample("cr_platform_services_up", {}, up,
                                  "Number of reachable services", "gauge"))
    samples.append(metrics.Sample("cr_platform_services_total", {}, len(results),
                                  "Number of monitored services", "gauge"))
    return metrics.render_prometheus(samples)


@app.get("/observability/summary")
async def summary():
    results = await _scrape_all()
    up = sum(1 for r in results if r["ok"])
    return {
        "up": up, "down": len(results) - up, "total": len(results),
        "services": sorted(
            [{"name": r["name"], "up": r["ok"], "latency_ms": r["latency_ms"]} for r in results],
            key=lambda x: (x["up"], x["name"])),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8097)
