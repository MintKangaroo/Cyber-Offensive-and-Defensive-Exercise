"""
SIEM syslog ingestion 부하테스트 (28번 문서 2.3절)
======================================================
k6가 UDP를 잘 못 다루므로 별도 파이썬 스크립트로 플러딩.
측정 대상: SIEM의 /sources/health 드롭 카운터, 저장 지연.
"""
import argparse
import socket
import time


def flood(host: str, port: int, eps: float, duration_sec: int) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interval = 1.0 / eps
    end = time.time() + duration_sec
    msg = b"<134>1 2026-07-11T00:00:00Z host filterlog: 100,,,1,igb0,match,block,in,4,,,64,,,,6,tcp,60,10.13.37.66,10.0.0.10,40001,8001"
    sent = 0
    while time.time() < end:
        sock.sendto(msg, (host, port))
        sent += 1
        time.sleep(interval)
    return sent


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="localhost")
    ap.add_argument("--port", type=int, default=1514)
    ap.add_argument("--eps", type=float, default=500)
    ap.add_argument("--duration", type=int, default=60)
    args = ap.parse_args()

    sent = flood(args.host, args.port, args.eps, args.duration)
    print(f"sent={sent} (target eps={args.eps}, duration={args.duration}s)")
    print("이제 SIEM의 GET /sources/health 로 드롭카운트/최종수신시각을 확인하세요.")
