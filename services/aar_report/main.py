"""
AAR Report API (27번 문서 1.3절)
===================================
Event Collector/Scoring Engine/SIEM의 데이터를 모아 AAR 리포트를 조립한다.

실행: uvicorn services.aar_report.main:app --port 8090
"""
from __future__ import annotations
import os
import time
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from services.aar_report.metrics import (  # noqa: E402
    compute_mttd, compute_mttr, compute_detection_rate, compute_false_positive_rate, stealth_bonus_total,
)
from services.aar_report.attack_heatmap import build_heatmap, uncovered_techniques  # noqa: E402
from services.aar_report.recommendations import generate_recommendations  # noqa: E402
from services.aar_report.pdf.render import render_pdf  # noqa: E402
from services.aar_report.integrations import (  # noqa: E402
    summarize_incidents, summarize_injects, summarize_integrity, summarize_protocol_attacks,
)

EVENT_COLLECTOR_URL = os.environ.get("EVENT_COLLECTOR_URL", "http://event_collector:8010")
SCORING_ENGINE_URL = os.environ.get("SCORING_ENGINE_URL", "http://scoring_engine:8020")
SIEM_API_URL = os.environ.get("SIEM_API_URL", "http://siem_api:8040")
INCIDENT_URL = os.environ.get("INCIDENT_URL", "http://incident:8095")
INJECTS_URL = os.environ.get("INJECTS_URL", "http://injects:8096")
CHALLENGE_PORTAL_URL = os.environ.get("CHALLENGE_PORTAL_URL", "http://challenge_portal:8060")
PDF_OUTPUT_DIR = Path(os.environ.get("AAR_PDF_DIR", "/tmp/aar_reports"))
PDF_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="AAR Report API")


@app.get("/health")
def health():
    return {"status": "ok", "service": "aar_report"}


@app.get("/report/aar")
async def get_aar_report(scenario_id: str = "default"):
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            events_resp = await client.get(f"{EVENT_COLLECTOR_URL}/replay/events", params={"scenario_id": scenario_id})
            events_resp.raise_for_status()
            events = events_resp.json().get("events", [])
        except httpx.HTTPError as e:
            raise HTTPException(502, f"event_collector 조회 실패: {e}")

        try:
            scores_resp = await client.get(f"{SCORING_ENGINE_URL}/scores", params={"scenario_id": scenario_id})
            scores_resp.raise_for_status()
            scores = scores_resp.json()
        except httpx.HTTPError:
            scores = {"teams": {}}

        alerts: list[dict] = []
        try:
            alerts_resp = await client.get(f"{SIEM_API_URL}/alerts")
            alerts_resp.raise_for_status()
            alerts = alerts_resp.json().get("alerts", [])
        except httpx.HTTPError:
            pass  # SIEM이 없어도 리포트 자체는 이벤트/점수만으로 생성 가능

        # --- P2-4 확장: 인시던트·인젝트·무결성(각 best-effort, 없으면 빈 섹션) ---
        async def _get_json(url, key, default):
            try:
                r = await client.get(url); r.raise_for_status()
                return r.json().get(key, default)
            except (httpx.HTTPError, ValueError):
                return default
        incidents = await _get_json(f"{INCIDENT_URL}/incidents", "incidents", [])
        inject_board = await _get_json(f"{INJECTS_URL}/injects/scoreboard", "scoreboard", [])
        flagged = await _get_json(f"{CHALLENGE_PORTAL_URL}/portal/anticheat/flagged", "flagged", [])

    mttd = compute_mttd(events)
    mttr = compute_mttr(events)
    detection_rate = compute_detection_rate(events)
    noise_event_ids = {e["event_id"] for e in events if e.get("team_id") == "noise"}
    fp_rate = compute_false_positive_rate(alerts, noise_event_ids)
    stealth_total = stealth_bonus_total(events)

    heatmap = build_heatmap(events, alerts)
    gaps = uncovered_techniques(heatmap)
    recommendations = generate_recommendations(mttd, fp_rate, gaps)

    stage_events = [e for e in events if e.get("event_type") == "stage_completed"]
    flag_events = [e for e in events if e.get("event_type") == "flag_exfiltrated"]

    return {
        "summary": {
            "scenario_id": scenario_id,
            "teams": list(scores.get("teams", {}).keys()),
            "final_scores": scores.get("teams", {}),
            "generated_at": time.time(),
        },
        "red_performance": {
            "stages_completed": len(stage_events),
            "flags_obtained": len(flag_events),
            "stealth_bonus_total": stealth_total,
        },
        "blue_performance": {
            "mttd_sec": mttd,
            "mttr_sec": mttr,
            "detection_rate": detection_rate,
            "false_positive_rate": fp_rate,
        },
        "attack_heatmap": heatmap,
        "uncovered_techniques": gaps,
        "recommendations": recommendations,
        # P2-4 확장 섹션 — 이번 세션 하위시스템 종합
        "incident_management": summarize_incidents(incidents),
        "crisis_comms": summarize_injects(inject_board),
        "integrity": summarize_integrity(flagged),
        "ics_protocol_attacks": summarize_protocol_attacks(events),
    }


@app.get("/report/aar/pdf")
async def get_aar_report_pdf(scenario_id: str = "default"):
    """/report/aar과 동일한 데이터를 PDF로 렌더링해 파일 경로를 반환.
    reportlab 사용(WeasyPrint의 시스템 라이브러리 의존성 회피, 27번 문서 1.5절)."""
    from fastapi.responses import FileResponse

    report = await get_aar_report(scenario_id)
    output_path = PDF_OUTPUT_DIR / f"aar_{scenario_id}_{int(time.time())}.pdf"
    render_pdf(report, str(output_path))
    return FileResponse(str(output_path), media_type="application/pdf",
                        filename=f"aar_report_{scenario_id}.pdf")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8090)
