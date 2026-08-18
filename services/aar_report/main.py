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
from fastapi import FastAPI, HTTPException, Header

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.rbac import require_role, ROLES  # noqa: E402
from shared.rbac import require_read  # noqa: E402
from shared.timeline import build_timeline  # noqa: E402
from services.aar_report.metrics import (  # noqa: E402
    compute_mttd, compute_mttr, compute_detection_rate, compute_false_positive_rate, stealth_bonus_total,
)
from services.aar_report.attack_heatmap import build_heatmap, uncovered_techniques  # noqa: E402
from services.aar_report.recommendations import generate_recommendations  # noqa: E402
from services.aar_report.pdf.render import render_pdf  # noqa: E402
from services.aar_report.integrations import (  # noqa: E402
    summarize_incidents, summarize_injects, summarize_integrity, summarize_protocol_attacks,
    summarize_ics_lifecycle,
)

EVENT_COLLECTOR_URL = os.environ.get("EVENT_COLLECTOR_URL", "http://event_collector:8010")
SCORING_ENGINE_URL = os.environ.get("SCORING_ENGINE_URL", "http://scoring_engine:8020")
SIEM_API_URL = os.environ.get("SIEM_API_URL", "http://siem_api:8040")
INCIDENT_URL = os.environ.get("INCIDENT_URL", "http://incident:8095")
INJECTS_URL = os.environ.get("INJECTS_URL", "http://injects:8096")
CHALLENGE_PORTAL_URL = os.environ.get("CHALLENGE_PORTAL_URL", "http://challenge_portal:8060")
PDF_OUTPUT_DIR = Path(os.environ.get("AAR_PDF_DIR", "/tmp/aar_reports"))
PDF_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
# 감사 4.8: 보존 정책 — 오래됐거나(일수) 개수 상한을 넘는 PDF를 자동 정리(용량 무한 증가 방지).
AAR_RETENTION_DAYS = int(os.environ.get("AAR_RETENTION_DAYS", "14"))
AAR_MAX_REPORTS = int(os.environ.get("AAR_MAX_REPORTS", "500"))


def _prune_reports() -> dict:
    """AAR_RETENTION_DAYS 초과 파일 삭제 + 개수 상한(AAR_MAX_REPORTS) 초과분(오래된 것부터) 삭제."""
    pdfs = sorted(PDF_OUTPUT_DIR.glob("aar_*.pdf"), key=lambda p: p.stat().st_mtime)
    removed = 0
    if AAR_RETENTION_DAYS > 0:
        cutoff = time.time() - AAR_RETENTION_DAYS * 86400
        for p in list(pdfs):
            if p.stat().st_mtime < cutoff:
                try:
                    p.unlink(); removed += 1; pdfs.remove(p)
                except OSError:
                    pass
    if AAR_MAX_REPORTS > 0 and len(pdfs) > AAR_MAX_REPORTS:
        for p in pdfs[: len(pdfs) - AAR_MAX_REPORTS]:
            try:
                p.unlink(); removed += 1
            except OSError:
                pass
    return {"removed": removed, "remaining": len(list(PDF_OUTPUT_DIR.glob("aar_*.pdf")))}

app = FastAPI(title="AAR Report API")


def _require_viewer(authorization: str) -> None:
    """AAR 리포트는 매치 전체 데이터(점수·이벤트·히트맵)를 담으므로 무인증 노출 금지.
    인증된 아무 역할(instructor/observer/red/blue/...)이면 열람 허용, 무토큰은 401.
    (감사 1.8 DoD: aar_report 전 엔드포인트 require_role, 무토큰 401)"""
    require_role(authorization, set(ROLES))


@app.get("/health")
def health():
    return {"status": "ok", "service": "aar_report"}


@app.get("/report/aar")
async def get_aar_report(scenario_id: str = "default", authorization: str = Header(default="")):
    _require_viewer(authorization)
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
        "ics_lifecycle": summarize_ics_lifecycle(events),
    }


@app.get("/report/aar/pdf")
async def get_aar_report_pdf(scenario_id: str = "default", authorization: str = Header(default="")):
    """/report/aar과 동일한 데이터를 PDF로 렌더링해 파일 경로를 반환.
    reportlab 사용(WeasyPrint의 시스템 라이브러리 의존성 회피, 27번 문서 1.5절)."""
    from fastapi.responses import FileResponse

    _require_viewer(authorization)
    report = await get_aar_report(scenario_id, authorization)
    output_path = PDF_OUTPUT_DIR / f"aar_{scenario_id}_{int(time.time())}.pdf"
    render_pdf(report, str(output_path))
    _prune_reports()  # 감사 4.8: 생성 때마다 보존 정책 적용(용량 상한 유지)
    return FileResponse(str(output_path), media_type="application/pdf",
                        filename=f"aar_report_{scenario_id}.pdf")


@app.get("/report/timeline")
async def get_timeline(scenario_id: str = "default", authorization: str = Header(default="")):
    """통합 타임라인 — 이벤트·SIEM 알림·인시던트·인젝트를 하나의 시간순 뷰로 합쳐 반환.
    각 소스는 best-effort(없어도 됨)로 가져오고, 병합/정렬은 순수함수 build_timeline 에 위임."""
    _require_viewer(authorization)

    async def _get_json(url, key, default, params=None):
        try:
            r = await client.get(url, params=params); r.raise_for_status()
            return r.json().get(key, default)
        except (httpx.HTTPError, ValueError):
            return default

    async with httpx.AsyncClient(timeout=10.0) as client:
        events = await _get_json(f"{EVENT_COLLECTOR_URL}/replay/events", "events", [],
                                 params={"scenario_id": scenario_id})
        alerts = await _get_json(f"{SIEM_API_URL}/alerts", "alerts", [])
        incidents = await _get_json(f"{INCIDENT_URL}/incidents", "incidents", [])
        injects = await _get_json(f"{INJECTS_URL}/injects/scoreboard", "scoreboard", [])

    timeline = build_timeline({
        "events": events, "alerts": alerts, "incidents": incidents, "injects": injects,
    })
    return {"scenario_id": scenario_id, "count": len(timeline), "timeline": timeline}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8090)
