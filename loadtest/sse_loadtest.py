#!/usr/bin/env python3
"""
SSE 상황판 부하 테스트(P0-4) — 스레드 기반
==========================================
관전자 N + 팀 M 이 동시에 /stream 을 구독한 상태에서 이벤트를 rate/s 로 주입하고,
"상황판 반영 지연"(주입 timestamp → 구독자 수신) p50/p95/p99 를 측정한다. 목표: p95 < 1s.

왜 스레드인가:
  다수의 SSE 스트림을 단일 asyncio 이벤트루프에서 aiter_lines 로 읽으면 리더끼리 굶어
  측정이 왜곡된다(실제 브라우저는 각자 독립 루프). 블로킹 소켓 read 는 GIL 을 놓으므로
  스레드 N개가 실브라우저 N개에 더 가깝다.

지연 측정은 팀/교관 구독자(실시간)에서만. 관전자는 설계상 30초 지연 큐이므로 연결 부하로만.

사용:
  python3 loadtest/sse_loadtest.py --url http://127.0.0.1:8010 \
      --observers 100 --teams 8 --rate 1000 --duration 5
의존성: requests (표준적으로 설치됨). 없으면 urllib fallback.
"""
import argparse
import json
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor


def sse_subscribe(url, topics, latencies, stop, t_connect, measure):
    """블로킹 SSE 구독. measure=True 면 fresh 이벤트의 (수신-주입) 지연을 기록."""
    req = urllib.request.Request(f"{url}/stream?topics={topics}",
                                 headers={"Accept": "text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            for raw in resp:
                if stop.is_set():
                    break
                line = raw.decode("utf-8", "replace")
                if line.startswith("data:"):
                    if not measure:
                        continue
                    try:
                        d = json.loads(line[5:].strip())
                        ts = d.get("timestamp")
                        if ts and float(ts) >= t_connect:
                            latencies.append(time.time() - float(ts))
                    except (ValueError, KeyError):
                        pass
    except Exception:
        pass


def post_event(url, i, sent):
    body = json.dumps({
        "event_id": f"lt-{time.time_ns()}-{i}",
        "event_type": "red_attack_started",
        "timestamp": time.time(),
        "actor": "red", "team_id": f"t{i % 8}", "scenario_id": "loadtest",
        "target_asset": "power_plant", "phase": "initial_access",
        "metadata": {"match_id": "m1"},
    }).encode()
    req = urllib.request.Request(f"{url}/events", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10).read()
        sent[0] += 1
    except Exception:
        pass


def inject(url, rate, duration, sent, pool):
    """rate/s 로 절대 시각 페이싱 주입. 각 POST 는 스레드풀에서 병렬 실행."""
    total = int(rate * duration)
    start = time.time()
    for i in range(total):
        target = start + i / rate
        now = time.time()
        if target > now:
            time.sleep(target - now)
        pool.submit(post_event, url, i, sent)


def pct(xs, p):
    if not xs:
        return float("nan")
    s = sorted(xs)
    return s[min(len(s) - 1, int(len(s) * p))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8010")
    ap.add_argument("--observers", type=int, default=100)
    ap.add_argument("--teams", type=int, default=8)
    ap.add_argument("--rate", type=int, default=1000)
    ap.add_argument("--duration", type=float, default=5.0)
    a = ap.parse_args()

    latencies: list = []
    sent = [0]
    stop = threading.Event()
    t_connect = time.time()
    threads = []
    for _ in range(a.teams):
        t = threading.Thread(target=sse_subscribe,
                             args=(a.url, "events", latencies, stop, t_connect, True),
                             daemon=True)
        t.start(); threads.append(t)
    for _ in range(a.observers):
        t = threading.Thread(target=sse_subscribe,
                             args=(a.url, "events", latencies, stop, t_connect, False),
                             daemon=True)
        t.start(); threads.append(t)
    time.sleep(1.5)   # 전 구독자 연결 안정화

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=64) as pool:
        inject(a.url, a.rate, a.duration, sent, pool)
    time.sleep(1.5)   # 잔여 수신 대기
    elapsed = time.time() - t0
    stop.set()

    total_conn = a.teams + a.observers
    print(f"구독자        : 팀 {a.teams} + 관전자 {a.observers} = {total_conn} 동시연결")
    print(f"주입 이벤트   : {sent[0]}  ({sent[0] / elapsed:.0f}/s, 목표 {a.rate}/s)")
    print(f"수신 샘플(팀) : {len(latencies)}")
    print(f"반영 지연 p50 : {pct(latencies, 0.50) * 1000:.1f} ms")
    print(f"반영 지연 p95 : {pct(latencies, 0.95) * 1000:.1f} ms   (목표 < 1000 ms)")
    print(f"반영 지연 p99 : {pct(latencies, 0.99) * 1000:.1f} ms")
    p95 = pct(latencies, 0.95)
    ok = p95 == p95 and p95 < 1.0 and len(latencies) > 0
    print(f"판정          : {'PASS ✅' if ok else 'FAIL ❌'}")


if __name__ == "__main__":
    main()
