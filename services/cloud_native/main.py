"""
Cloud-Native Attack Surface Twin (클라우드 네이티브 공격면 트윈)
=================================================================
ICS 일변도였던 트윈 셋에 현대 클라우드/컨테이너 공격면을 추가. 실제 클라우드 침해에서 흔한
5가지 취약점을 모사한다(훈련용 시뮬 — 실제 클라우드와 무관).

취약점:
  CLD-001 IMDS SSRF            (POST /api/proxy/fetch)   — 클라우드 메타데이터(169.254.169.254) 자격증명 탈취
  CLD-002 Exposed Docker API   (POST /api/docker/exec)   — 무인증 Docker 소켓/2375 컨테이너 명령
  CLD-003 Kubelet Anon Exec    (POST /api/kubelet/exec)  — kubelet 익명 인증(10250) 파드 exec
  CLD-004 Secrets Exposure     (GET  /api/config/env)    — env/ConfigMap 평문 시크릿 노출
  CLD-005 SSTI → RCE           (POST /api/render)        — 서버측 템플릿 인젝션 원격 코드 실행
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from shared.ics_twin import make_ics_twin, Vuln, deny  # noqa: E402

_META_HOSTS = ("169.254.169.254", "metadata.google", "metadata.internal")


def imds_ssrf(patched, p, emit):
    url = p.get("url", "")
    if patched and not url.startswith(("https://api.internal/", "http://svc.")):
        deny(400, "URL blocked by egress allowlist")
    if any(h in url for h in _META_HOSTS) or "/latest/meta-data" in url:
        if not patched:
            emit({"url": url, "note": "SSRF to cloud metadata (IMDS) — 자격증명 탈취"})
        return {"fetched": url, "imds_credentials": {
            "AccessKeyId": "AKIA-TRAINING-ONLY", "SecretAccessKey": "REDACTED-TRAINING",
            "Token": "training-session-token", "Expiration": "2099-01-01T00:00:00Z"}}
    return {"fetched": url, "body": "ok"}


def docker_exec(patched, p, emit):
    if patched and p.get("authorization") != "Bearer docker-mtls-client":
        deny(401, "Docker API requires mTLS client cert")
    cmd = p.get("cmd", "id")
    if not patched:
        emit({"cmd": cmd, "note": "unauthenticated Docker API exec (exposed 2375)"})
    return {"container": "web-1", "exec": cmd, "output": "uid=0(root) gid=0(root)"}


def kubelet_exec(patched, p, emit):
    if patched:
        deny(401, "kubelet anonymous-auth disabled")
    pod = p.get("pod", "default/web")
    emit({"pod": pod, "note": "kubelet anonymous exec (10250)"})
    return {"pod": pod, "exec": p.get("cmd", "id"), "output": "uid=0(root) gid=0(root)"}


def secrets_env(patched, p, emit):
    if patched:
        return {"env": {"APP_ENV": "prod", "LOG_LEVEL": "info"}}   # 시크릿은 Secret manager 로 이관됨
    emit({"note": "secrets exposed via env/ConfigMap 평문"})
    return {"env": {"APP_ENV": "prod", "DB_PASSWORD": "TRAINING-s3cr3t!",
                    "AWS_SECRET_ACCESS_KEY": "TRAINING-REDACTED", "JWT_SIGNING_KEY": "TRAINING-key"}}


def ssti_render(patched, p, emit):
    tpl = p.get("template", "")
    injected = ("{{" in tpl or "${" in tpl or "#{" in tpl)
    if patched and injected:
        deny(400, "template expression blocked (autoescape/sandbox)")
    if not patched and injected:
        emit({"template": tpl, "note": "server-side template injection → RCE"})
        return {"rendered": "uid=0(root) gid=0(root)", "rce": True}
    return {"rendered": tpl, "rce": False}


VULNS = [
    Vuln("CLD-001", "/api/proxy/fetch", "POST", "IMDS SSRF credential theft",
         "red_attack_started", "data_exfiltration", imds_ssrf),
    Vuln("CLD-002", "/api/docker/exec", "POST", "Exposed Docker API exec",
         "red_attack_started", "lateral_movement", docker_exec),
    Vuln("CLD-003", "/api/kubelet/exec", "POST", "Kubelet anonymous exec",
         "red_attack_started", "lateral_movement", kubelet_exec),
    Vuln("CLD-004", "/api/config/env", "GET", "Secrets exposure via env/ConfigMap",
         "flag_exfiltrated", "data_exfiltration", secrets_env),
    Vuln("CLD-005", "/api/render", "POST", "SSTI remote code execution",
         "red_objective_success", "objective", ssti_render),
]

app = make_ics_twin("cloud_native", "Cloud-Native Attack Surface Twin", VULNS)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8209)
