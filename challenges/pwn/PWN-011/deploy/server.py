"""PWN-011 TCP 래퍼 — 연결마다 relayctl 바이너리 stdin/stdout 소켓 직결. 기동 시 /flag 기록."""
import hashlib, os, socketserver, subprocess
SECRET = os.environ.get("CHALLENGE_SECRET")
if not SECRET: raise RuntimeError("CHALLENGE_SECRET 미설정 — fail-fast.")
PORT = int(os.environ.get("PORT","9021"))
def static_flag():
    sig = hashlib.sha256(f"PWN-011:{SECRET}".encode()).hexdigest()[:16]
    return f"flag{{substation_rop_execve_shell_{sig}}}"
with open("/flag","w",encoding="utf-8") as fh: fh.write(static_flag()+"\n")
class H(socketserver.BaseRequestHandler):
    def handle(self):
        fd=self.request.fileno()
        try: subprocess.run(["/app/relayctl"], stdin=fd, stdout=fd, stderr=fd, timeout=30)
        except Exception: pass
class S(socketserver.ForkingTCPServer):
    allow_reuse_address=True; daemon_threads=True
if __name__=="__main__":
    with S(("0.0.0.0",PORT),H) as s:
        print(f"[pwn] 변전소 제어 릴레이 콘솔 :{PORT}", flush=True); s.serve_forever()
