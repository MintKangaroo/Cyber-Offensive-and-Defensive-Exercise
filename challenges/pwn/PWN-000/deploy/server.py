"""PWN-000 TCP 래퍼 — 연결마다 lng 바이너리의 stdin/stdout 을 소켓에 직결(ForkingTCPServer).
컨테이너 시작 시 CHALLENGE_SECRET 기반 정적 플래그를 /flag 에 기록한다."""
import hashlib
import os
import socketserver
import subprocess

SECRET = os.environ.get("CHALLENGE_SECRET")
if not SECRET:
    raise RuntimeError("CHALLENGE_SECRET 미설정 — 기본값 없이 fail-fast.")
PORT = int(os.environ.get("PORT", "9010"))


def static_flag() -> str:
    sig = hashlib.sha256(f"PWN-000:{SECRET}".encode()).hexdigest()[:16]
    return f"flag{{lng_alarm_{sig}}}"


with open("/flag", "w", encoding="utf-8") as fh:
    fh.write(static_flag() + "\n")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        fd = self.request.fileno()
        try:
            subprocess.run(["/app/lng"], stdin=fd, stdout=fd, stderr=fd, timeout=60)
        except Exception:
            pass


class Server(socketserver.ForkingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", PORT), Handler) as s:
        print(f"[pwn] LNG 경보센터 serving on :{PORT}", flush=True)
        s.serve_forever()
