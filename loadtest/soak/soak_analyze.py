#!/usr/bin/env python3
"""U-6 소크 분석기 — mem_samples.csv 를 읽어 컨테이너별 RSS 추세를 판정한다.

누수 판정 기준:
  * 선형회귀 기울기(MiB/hour)를 구한다.
  * 마지막 25% 구간 평균이 첫 25% 평균 대비 증가율(%)을 본다.
  * 재시작(RestartCount 증가 = OOM/crash 의심)이 있었는지.

판정:
  PASS  — 기울기 < SLOPE_WARN(기본 5 MiB/h) 이고 재시작 없음
  WARN  — 기울기 SLOPE_WARN~SLOPE_FAIL 사이(관찰 필요)
  FAIL  — 기울기 >= SLOPE_FAIL(기본 20 MiB/h) 또는 재시작 발생
"""
from __future__ import annotations

import csv
import json
import os
import sys
from collections import defaultdict

CSV = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), "results", "mem_samples.csv"
)
SLOPE_WARN = float(os.environ.get("SOAK_SLOPE_WARN_MIB_H", "5"))
SLOPE_FAIL = float(os.environ.get("SOAK_SLOPE_FAIL_MIB_H", "20"))
# 초반 warmup(SQLite 페이지·연결·브로드캐스트 버퍼 워밍업) 램프는 누수가 아니므로
# 회귀에서 컨테이너별로 앞 N 샘플을 버린다. steady-state 기울기만 판정에 쓴다.
WARMUP_SKIP = int(os.environ.get("SOAK_WARMUP_SKIP", "5"))
MIB = 1024 * 1024


def _slope(xs: list[float], ys: list[float]) -> float:
    """최소제곱 기울기 (ys 단위/xs 단위)."""
    n = len(xs)
    if n < 2:
        return 0.0
    mx = sum(xs) / n
    my = sum(ys) / n
    num = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = sum((x - mx) ** 2 for x in xs)
    return num / den if den else 0.0


def main() -> int:
    if not os.path.exists(CSV):
        print(f"[soak-analyze] no CSV: {CSV}", file=sys.stderr)
        return 2

    series: dict[str, list[tuple[float, float]]] = defaultdict(list)
    restarts: dict[str, list[int]] = defaultdict(list)
    with open(CSV) as f:
        for row in csv.DictReader(f):
            try:
                epoch = float(row["epoch"])
                mem = float(row["mem_bytes"])
            except (ValueError, KeyError):
                continue
            c = row["container"]
            series[c].append((epoch, mem))
            try:
                restarts[c].append(int(row["restarts"]))
            except (ValueError, KeyError):
                pass

    report: dict[str, dict] = {}
    verdicts: list[str] = []
    for c, pts in sorted(series.items()):
        pts.sort()
        # warmup 램프 제거(단, 최소 3점은 남긴다)
        if len(pts) > WARMUP_SKIP + 3:
            pts = pts[WARMUP_SKIP:]
        if len(pts) < 3:
            continue
        t0 = pts[0][0]
        xs_h = [(t - t0) / 3600.0 for t, _ in pts]      # 시간(hour)
        ys_mib = [m / MIB for _, m in pts]
        slope = _slope(xs_h, ys_mib)                    # MiB/hour

        q = max(1, len(pts) // 4)
        first_avg = sum(ys_mib[:q]) / q
        last_avg = sum(ys_mib[-q:]) / q
        growth_pct = ((last_avg - first_avg) / first_avg * 100) if first_avg else 0.0

        rs = restarts.get(c, [])
        restart_delta = (max(rs) - min(rs)) if rs else 0

        if restart_delta > 0 or slope >= SLOPE_FAIL:
            verdict = "FAIL"
        elif slope >= SLOPE_WARN:
            verdict = "WARN"
        else:
            verdict = "PASS"
        verdicts.append(verdict)

        report[c] = {
            "samples": len(pts),
            "first_mib": round(first_avg, 1),
            "last_mib": round(last_avg, 1),
            "peak_mib": round(max(ys_mib), 1),
            "growth_pct": round(growth_pct, 1),
            "slope_mib_per_h": round(slope, 2),
            "restart_delta": restart_delta,
            "verdict": verdict,
        }

    overall = "FAIL" if "FAIL" in verdicts else ("WARN" if "WARN" in verdicts else "PASS")
    out = {
        "overall": overall,
        "slope_warn_mib_h": SLOPE_WARN,
        "slope_fail_mib_h": SLOPE_FAIL,
        "containers": report,
    }

    print(json.dumps(out, indent=2, ensure_ascii=False))
    print()
    print(f"{'container':<22} {'first':>8} {'last':>8} {'peak':>8} "
          f"{'growth%':>8} {'MiB/h':>8} {'restart':>7}  verdict")
    print("-" * 88)
    for c, r in report.items():
        print(f"{c:<22} {r['first_mib']:>8.1f} {r['last_mib']:>8.1f} "
              f"{r['peak_mib']:>8.1f} {r['growth_pct']:>8.1f} "
              f"{r['slope_mib_per_h']:>8.2f} {r['restart_delta']:>7}  {r['verdict']}")
    print("-" * 88)
    print(f"OVERALL: {overall}")

    summary_path = os.path.join(os.path.dirname(CSV), "soak_report.json")
    with open(summary_path, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"[soak-analyze] wrote {summary_path}")

    return 1 if overall == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
