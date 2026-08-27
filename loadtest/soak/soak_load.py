#!/usr/bin/env python3
"""U-6 소크 부하 생성기 — 장시간 지속부하로 코어 서비스 메모리 누수를 유도한다.

기존 k6 스크립트(loadtest/k6/*)는 90초~5분 버스트라 시간-비례 누수(타이머/백그라운드
루프/브로드캐스트 팬아웃 누적)를 못 잡는다. 이 스크립트는 낮은~중간 지속 rate 로 몇 시간
동안 event_collector 수집 경로(→ scoring S2S 팬아웃 + WS 브로드캐스트)와 siem_api 조회
경로(→ file tailer/detection 백그라운드 루프)를 계속 두드린다.

호스트에서 실행. 트윈은 호스트 포트가 없으므로(격리) 대상에서 제외하고, 호스트 포트가
열린 코어 서비스만 타깃한다.

환경변수:
  SOAK_DURATION_SEC   총 지속시간(기본 7200 = 2h)
  SOAK_RATE           초당 총 요청수(기본 40)
  SOAK_EC_URL         event_collector (기본 http://localhost:8010)
  SOAK_SIEM_URL       siem_api        (기본 http://localhost:8040)
  SOAK_SUMMARY        종료 요약 JSON 경로(기본 loadtest/soak/results/load_summary.json)
"""
from __future__ import annotations

import json
import os
import random
import threading
import time
from collections import defaultdict

import requests

DURATION = int(os.environ.get("SOAK_DURATION_SEC", "7200"))
RATE = float(os.environ.get("SOAK_RATE", "40"))
EC_URL = os.environ.get("SOAK_EC_URL", "http://localhost:8010").rstrip("/")
SIEM_URL = os.environ.get("SOAK_SIEM_URL", "http://localhost:8040").rstrip("/")
SUMMARY = os.environ.get(
    "SOAK_SUMMARY",
    os.path.join(os.path.dirname(__file__), "results", "load_summary.json"),
)

# 요청 믹스: 대부분 event_collector 수집(가장 풍부한 누수 표면), 일부 siem 조회.
_stop = threading.Event()
_lock = threading.Lock()
_stats = {
    "sent": 0,
    "ok": 0,
    "fail": 0,
    "status": defaultdict(int),   # status_code -> count
    "latency_sum": 0.0,
    "latency_max": 0.0,
}

_SIEM_GETS = ["/alerts", "/stats", "/search?q=protocol&limit=25", "/sources/health"]
# RedPhase enum(shared/event_schema.py) 유효값만 — 그 외는 422 로 튕겨 팬아웃 경로를 못 탄다.
_PHASES = ["initial_access", "privilege_escalation", "lateral_movement",
           "data_exfiltration", "objective"]


def _record(ok: bool, code: int, latency: float) -> None:
    with _lock:
        _stats["sent"] += 1
        _stats["status"][code] += 1
        _stats["latency_sum"] += latency
        _stats["latency_max"] = max(_stats["latency_max"], latency)
        if ok:
            _stats["ok"] += 1
        else:
            _stats["fail"] += 1


def _one_request(sess: requests.Session, vu: int, it: int) -> None:
    t0 = time.perf_counter()
    ok = False
    code = 0
    try:
        if random.random() < 0.8:
            payload = {
                "event_id": f"soak-{vu}-{it}-{time.time_ns()}",
                "event_type": "red_attack_started",
                "actor": "red",
                "target_asset": "ground_station",
                "vuln_id": "GS-001",
                "phase": random.choice(_PHASES),
                "team_id": f"team_{vu % 16}",
            }
            r = sess.post(f"{EC_URL}/events", json=payload, timeout=10)
        else:
            r = sess.get(f"{SIEM_URL}{random.choice(_SIEM_GETS)}", timeout=10)
        code = r.status_code
        ok = 200 <= code < 300
    except Exception:  # noqa: BLE001 — 연결거부/타임아웃도 실패로 집계
        code = -1
    _record(ok, code, time.perf_counter() - t0)


def _worker(vu: int, per_worker_interval: float) -> None:
    sess = requests.Session()
    it = 0
    # 워커별 시작 지터로 톱니 방지
    time.sleep(random.random() * per_worker_interval)
    while not _stop.is_set():
        _one_request(sess, vu, it)
        it += 1
        # 목표 rate 유지를 위한 슬립(간단한 open-loop 페이싱)
        time.sleep(per_worker_interval)


def _snapshot() -> dict:
    with _lock:
        sent = _stats["sent"]
        return {
            "sent": sent,
            "ok": _stats["ok"],
            "fail": _stats["fail"],
            "fail_rate": (_stats["fail"] / sent) if sent else 0.0,
            "latency_avg_ms": (_stats["latency_sum"] / sent * 1000) if sent else 0.0,
            "latency_max_ms": _stats["latency_max"] * 1000,
            "status": dict(_stats["status"]),
        }


def main() -> None:
    # 워커 수: rate 를 워커당 ~4 req/s 로 나눔(최소 4, 최대 64)
    workers = max(4, min(64, int(RATE / 4) or 1))
    per_worker_rate = RATE / workers
    per_worker_interval = 1.0 / per_worker_rate

    print(
        f"[soak-load] duration={DURATION}s rate={RATE}/s workers={workers} "
        f"ec={EC_URL} siem={SIEM_URL}",
        flush=True,
    )
    threads = [
        threading.Thread(target=_worker, args=(i, per_worker_interval), daemon=True)
        for i in range(workers)
    ]
    for t in threads:
        t.start()

    start = time.time()
    end = start + DURATION
    try:
        while time.time() < end:
            time.sleep(60)
            snap = _snapshot()
            elapsed = int(time.time() - start)
            print(
                f"[soak-load] t={elapsed}s sent={snap['sent']} "
                f"fail={snap['fail']} fail_rate={snap['fail_rate']:.4f} "
                f"avg={snap['latency_avg_ms']:.1f}ms max={snap['latency_max_ms']:.0f}ms "
                f"status={snap['status']}",
                flush=True,
            )
    except KeyboardInterrupt:
        print("[soak-load] interrupted", flush=True)
    finally:
        _stop.set()
        for t in threads:
            t.join(timeout=5)

    snap = _snapshot()
    snap["duration_sec"] = int(time.time() - start)
    snap["rate_target"] = RATE
    snap["rate_actual"] = snap["sent"] / snap["duration_sec"] if snap["duration_sec"] else 0
    os.makedirs(os.path.dirname(SUMMARY), exist_ok=True)
    with open(SUMMARY, "w") as f:
        json.dump(snap, f, indent=2)
    print(f"[soak-load] DONE {json.dumps(snap)}", flush=True)


if __name__ == "__main__":
    main()
