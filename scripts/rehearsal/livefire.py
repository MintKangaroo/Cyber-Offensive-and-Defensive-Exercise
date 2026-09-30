"""Live Fire 리허설 — 이벤트 파이프라인 E2E + 3대 검증.

레드 봇이 격리된 scenario 로 킬체인 5단계 공격 이벤트를 발행하고, 교관 관점에서:
  1) 점수 합계와 이벤트 원장 일치(유실 0) — reconcile all_match + scoreable_without_achievement 0
     + event_collector /metrics dlq_drop==0 + 발행 이벤트가 전부 원장(replay)에 존재.
  2) SIEM 경보의 팀 귀속 — 트윈 게이트웨이로 실 공격을 흘려 SIEM 경보가 src_ip 를 담는지.
  3) AAR PDF 생성(한글 폰트) — /report/aar/pdf 200 + %PDF + 한글 글리프.
를 검증한다. 격리 scenario_id 를 쓰므로 이전 매치/소크 잔여 데이터와 섞이지 않는다.
"""
from __future__ import annotations

import time
import uuid

import requests

from . import common as C

PHASES = ["initial_access", "privilege_escalation", "lateral_movement",
          "data_exfiltration", "objective"]


def _emit(scenario: str, idx: int, phase: str, team: str = "team-01") -> int:
    ev = {
        "event_id": f"{scenario}-{idx}",
        "event_type": "red_attack_started",
        "timestamp": time.time(),
        "actor": "red", "team_id": team, "scenario_id": scenario,
        "target_asset": "power_plant", "vuln_id": "PP-001", "phase": phase,
        "metadata": {"rehearsal": True},
    }
    r = requests.post(f"{C.EVENT_COLLECTOR}/events", json=ev,
                      headers=C.service_headers(), timeout=8)
    return r.status_code


def run(rep: C.Reporter) -> dict:
    scenario = f"reh-livefire-{uuid.uuid4().hex[:8]}"
    print(f"\n── Live Fire (scenario={scenario}) ─────────────────────")

    m0 = requests.get(f"{C.EVENT_COLLECTOR}/metrics", timeout=5).json()

    # 1) 킬체인 5단계 발행(각 phase 1회 = 팀당 5 achievement)
    codes = [_emit(scenario, i, ph) for i, ph in enumerate(PHASES, 1)]
    rep.check(all(c == 200 for c in codes), "킬체인 5단계 이벤트 발행 200",
              f"codes={codes}")
    time.sleep(5)  # 포워딩/스코어링 정착

    # 원장 완전성: 발행 5건이 전부 replay 에 존재
    replay = requests.get(f"{C.EVENT_COLLECTOR}/replay/events",
                          params={"scenario_id": scenario},
                          headers=C.service_headers(), timeout=10).json()
    rep.check(replay.get("count") == len(PHASES),
              "이벤트 원장 완전성(발행=원장)",
              f"emitted={len(PHASES)} ledger={replay.get('count')}")

    # 유실 0: dlq_drop==0, dlq_pending 정착 후 0
    m1 = requests.get(f"{C.EVENT_COLLECTOR}/metrics", timeout=5).json()
    drops = m1.get("dlq_drop", 0)
    rep.check(drops == 0, "이벤트 유실 0(dlq_drop==0)", f"dlq_drop={drops}")
    fwd_delta = m1.get("forwarded_ok", 0) - m0.get("forwarded_ok", 0)
    rep.note("forwarded_ok 증가", f"+{fwd_delta} (pending={m1.get('dlq_pending')})")
    rep.note("SSE 드롭 카운터(S-8 가시성)", f"sse_dropped={m1.get('sse_dropped')}")

    # 점수-원장 일치: reconcile(격리 scenario)
    rc = requests.get(f"{C.SCORING_ENGINE}/scores/reconcile",
                      params={"scenario_id": scenario},
                      headers=C.service_headers(), timeout=15).json()
    cc = rc.get("events_crosscheck", {})
    rep.check(rc.get("score_consistency") is True,
              "점수 합계 일치(stored==computed)",
              f"all_match={rc.get('all_match')}")
    rep.check(cc.get("checked") and cc.get("scoreable_without_achievement") == 0
              and not cc.get("missing_event_ids"),
              "이벤트-점수 원장 일치(유실 0)",
              f"total={cc.get('total_events')} missing={cc.get('scoreable_without_achievement')}")

    return {"scenario": scenario, "reconcile": rc, "metrics": m1}


def run_siem_attribution(rep: C.Reporter, twin_gateway_url: str) -> dict:
    """트윈 게이트웨이로 실 공격을 흘려 SIEM 경보의 src_ip 귀속을 검증."""
    print("\n── SIEM 팀 귀속 ─────────────────────")
    # /alerts 는 최근 N건 캡이라 카운트 증가로 판정하지 않고, 공격 시각 이후의 새 경보를 찾는다.
    attack_ts = time.time()
    # PP-001 미인가 PLC write 경로(라우트 매칭이 vuln 이벤트를 촉발; 스키마 400 이어도 발화)
    try:
        requests.post(f"{twin_gateway_url}/api/plc/write",
                      json={"register": "40001", "value": "1"}, timeout=8)
    except requests.RequestException:
        pass
    time.sleep(6)
    try:
        alerts = requests.get(f"{C.SIEM_API}/alerts", timeout=5).json().get("alerts", [])
    except requests.RequestException as e:
        rep.check(False, "SIEM /alerts 도달", str(e))
        return {}
    fresh = [a for a in alerts if a.get("timestamp", 0) >= attack_ts - 2]
    fresh.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
    rep.check(bool(fresh), "트윈 공격이 SIEM 경보를 발화(공격 시각 이후)",
              f"fresh={len(fresh)} " + (f"rule={fresh[0]['rule_id']}" if fresh else ""))
    src = None
    if fresh:
        src = (fresh[0].get("matched_event", {}).get("raw", {}) or {}).get("src_ip")
    rep.check(bool(src), "SIEM 경보에 공격 출발지 src_ip 귀속",
              f"src_ip={src} (트윈GW=$remote_addr; A/D 팀귀속은 ad_target_gateway XFF=S-9)")
    return {"fresh_alerts": len(fresh), "src_ip": src}


def run_aar_pdf(rep: C.Reporter) -> dict:
    """AAR PDF 생성 + 한글 폰트 렌더 검증."""
    print("\n── AAR PDF(한글) ─────────────────────")
    r = requests.get(f"{C.AAR_REPORT}/report/aar/pdf",
                     headers=C.instructor_headers(), timeout=25)
    ok_pdf = r.status_code == 200 and r.content[:5] == b"%PDF-"
    rep.check(ok_pdf, "AAR PDF 생성(200 · %PDF)",
              f"http={r.status_code} type={r.headers.get('content-type')} size={len(r.content)}")
    # 한글: PDF 안에 한글 텍스트/폰트가 임베드됐는지(ToUnicode/한글 글리프 흔적).
    korean = False
    marker = ""
    if ok_pdf:
        blob = r.content
        # aar_report 는 reportlab 내장 한글 CID 폰트(HYSMyeongJo-Medium, UniKS-UCS2-H 인코딩)로
        # 렌더한다(Helvetica 는 한글이 ■ 로 깨짐). 이 폰트/인코딩 마커가 있으면 한글이 렌더된 것.
        for m in (b"HYSMyeongJo", b"UniKS", b"CIDFontType2", b"Nanum", b"Noto"):
            if m in blob:
                korean = True
                marker = m.decode()
                break
    rep.check(korean, "AAR PDF 한글 폰트 렌더(HYSMyeongJo/CID)",
              f"marker={marker}" if korean else "한글 폰트 미검출")
    return {"http": r.status_code, "size": len(r.content), "korean": korean}
