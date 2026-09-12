"""PWN-012 TCP 래퍼 — 연결마다 plcsafe 바이너리 stdin/stdout 소켓 직결. 기동 시 /flag 기록."""
import hashlib, os, socketserver, subprocess
SECRET = os.environ.get("CHALLENGE_SECRET")
if not SECRET: raise RuntimeError("CHALLENGE_SECRET 미설정 — fail-fast.")
PORT = int(os.environ.get("PORT","9022"))
def static_flag():
    sig = hashlib.sha256(f"PWN-012:{SECRET}".encode()).hexdigest()[:16]
    return f"flag{{turbine_srop_execve_{sig}}}"
with open("/flag","w",encoding="utf-8") as fh: fh.write(static_flag()+"\n")
class H(socketserver.BaseRequestHandler):
    def handle(self):
        fd=self.request.fileno()
        try: subprocess.run(["/app/plcsafe"], stdin=fd, stdout=fd, stderr=fd, timeout=30)
        except Exception: pass
class S(socketserver.ForkingTCPServer):
    allow_reuse_address=True; daemon_threads=True
if __name__=="__main__":
    with S(("0.0.0.0",PORT),H) as s:
        print(f"[pwn] 터빈 세이프티 PLC 콘솔 :{PORT}", flush=True); s.serve_forever()
