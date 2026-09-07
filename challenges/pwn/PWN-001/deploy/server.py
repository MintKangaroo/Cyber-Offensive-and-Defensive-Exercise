"""PWN-001 TCP 래퍼 — 연결마다 ptp 바이너리의 stdin/stdout 을 소켓에 직결(ForkingTCPServer).
기동 시 CHALLENGE_SECRET 기반 정적 플래그를 /flag 에 기록."""
import hashlib
import os
import socketserver
import subprocess

SECRET = os.environ.get("CHALLENGE_SECRET")
if not SECRET:
    raise RuntimeError("CHALLENGE_SECRET 미설정 — 기본값 없이 fail-fast.")
PORT = int(os.environ.get("PORT", "9011"))


def static_flag() -> str:
    sig = hashlib.sha256(f"PWN-001:{SECRET}".encode()).hexdigest()[:16]
    return f"flag{{ptp_fmtstr_{sig}}}"


with open("/flag", "w", encoding="utf-8") as fh:
    fh.write(static_flag() + "\n")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        fd = self.request.fileno()
        try:
            subprocess.run(["/app/ptp"], stdin=fd, stdout=fd, stderr=fd, timeout=30)
        except Exception:
            pass


class Server(socketserver.ForkingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    with Server(("0.0.0.0", PORT), Handler) as s:
        print(f"[pwn] 정수처리장 로그 콘솔 serving on :{PORT}", flush=True)
        s.serve_forever()
