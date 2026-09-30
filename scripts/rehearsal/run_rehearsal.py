"""무인 리허설 오케스트레이터.

Live Fire(이벤트 파이프라인) 1회 + Attack/Defense 2라운드를 완주시키고, 각 단계의 검증을
PASS/FAIL 로 집계한다. 서비스가 안 떠 있으면 해당 단계를 SKIP(UNVERIFIED)으로 남긴다.

사용:
  python3 -m scripts.rehearsal.run_rehearsal [--stage all|livefire|ad] [--json OUT]

메모리 제약상 전체 스택을 동시에 요구하지 않는다. `make rehearsal` 이 필요한 서브셋을 순차로
기동/해제하고 이 오케스트레이터를 호출한다.
"""
from __future__ import annotations

import argparse
import json
import os
import time

import requests

from . import common as C
from . import livefire, red_bot, instructor


def _up(url: str) -> bool:
    try:
        return requests.get(url, timeout=3).status_code == 200
    except requests.RequestException:
        return False


def stage_livefire(rep: C.Reporter, twin_gateway: str) -> dict:
    if not _up(f"{C.EVENT_COLLECTOR}/health") or not _up(f"{C.SCORING_ENGINE}/health"):
        rep.note("Live Fire SKIP", "이벤트 파이프라인 미기동 → UNVERIFIED")
        return {"skipped": True}
    out = livefire.run(rep)
    if _up(f"{C.SIEM_API}/health") and twin_gateway:
        out["siem"] = livefire.run_siem_attribution(rep, twin_gateway)
    else:
        rep.note("SIEM 귀속 SKIP", "siem_api/트윈 게이트웨이 미기동")
    if _up(f"{C.AAR_REPORT}/health"):
        out["aar"] = livefire.run_aar_pdf(rep)
    else:
        rep.note("AAR PDF SKIP", "aar_report 미기동")
    return out


def stage_ad(rep: C.Reporter, match_id: str = "ad-demo") -> dict:
    if not _up(f"{C.AD_API}/ready"):
        rep.note("A/D SKIP", "attack_defense 미기동 → UNVERIFIED")
        return {"skipped": True}
    secret = os.environ.get("AUTH_JWT_SECRET", "")
    if not secret:
        rep.check(False, "AUTH_JWT_SECRET 필요(competitor 토큰)", "미설정")
        return {"skipped": True}

    print("\n── A/D: 교관 매치 시작 ─────────────────────")
    boot = instructor.start(match_id)
    rep.check(boot.get("match", {}).get("status") in {"running", "active"},
              "교관: 매치 시작(running)", f"status={boot.get('match',{}).get('status')}")

    # 공격 대상: team-1(공격) → team-2 notes(host:9102)
    attacker, target = "team-1", "http://localhost:9102"
    rounds = []
    for rnd in range(1, 3):  # 2 라운드
        time.sleep(6)  # 라운드 플래그 주입 대기
        st = instructor.round_state(match_id)
        print(f"\n── A/D 라운드 {rnd} (seq={st.get('sequence')}, {st.get('status')}) ──")
        res = red_bot.attack_and_submit(attacker, target, match_id, secret)
        rep.check(res["accepted"] >= 1,
                  f"라운드{rnd}: 레드가 현재 플래그 탈취·제출 accepted",
                  f"stolen={res['stolen']} accepted={res['accepted']} +{res['score_delta']}")
        rounds.append({"round": rnd, "seq": st.get("sequence"), **res})
        if rnd == 1:
            fin = instructor.finalize_round(match_id)  # 교관: 라운드 넘기기
            rep.check(fin["http"] in (200, 202, 409),
                      "교관: 라운드1 확정→라운드2 진행", f"http={fin['http']}")

    # 점수 원장: 스코어보드에 공격 점수 반영
    state = instructor.match_state(match_id)
    rep.note("A/D 매치 상태", f"status={state.get('status')}")
    return {"rounds": rounds, "state_status": state.get("status")}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["all", "livefire", "ad"], default="all")
    ap.add_argument("--twin-gateway", default="http://localhost:8002")
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    print("=" * 66)
    print(" 무인 리허설 (Phase 3) — Live Fire + Attack/Defense 2라운드")
    print("=" * 66)
    rep = C.Reporter("rehearsal")
    result: dict = {"started_at": time.time(), "stages": {}}

    if args.stage in ("all", "livefire"):
        result["stages"]["livefire"] = stage_livefire(rep, args.twin_gateway)
    if args.stage in ("all", "ad"):
        result["stages"]["ad"] = stage_ad(rep)

    result["finished_at"] = time.time()
    result["passed"] = rep.passed
    result["failed"] = rep.failed
    result["checks"] = rep.checks

    print("\n" + "=" * 66)
    print(f" {rep.summary_line()}  →  {'✅ 완주(무결함)' if rep.ok else '❌ 실패 있음'}")
    print("=" * 66)

    if args.json:
        os.makedirs(os.path.dirname(args.json) or ".", exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2, default=str)
        print(f"결과 → {args.json}")
    return 0 if rep.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
