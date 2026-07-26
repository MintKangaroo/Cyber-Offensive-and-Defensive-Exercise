"""
Defense Network Digital Twin (사내망 디지털 트윈)
--------------------------------------------------
Live Fire Cyber Range 훈련용 모의 서비스. 실제 AD/파일서버/메일서버가 아니며
SMB/Kerberos/SMTP 프로토콜을 흉내낸 REST API 시뮬레이션입니다. 모든 계정/
자격증명/문서는 더미 데이터입니다.

취약점 목록(shared/vuln_catalog.json 의 defense_network 항목과 대응):
  DN-001 SMB Anonymous Share Access          (/api/smb/shares)
  DN-002 Kerberoastable Service Account       (/api/ad/service-accounts)
  DN-003 Exposed Backup Config w/ Plaintext   (/api/fileserver/backup-config)
  DN-004 Open Mail Relay                      (/api/mail/relay)
  DN-005 LDAP Injection                       (/api/directory/search) — 직원 디렉터리 검색
  DN-006 SSRF (URL 미리보기)                  (/api/webhook/preview)  — 파일서버 링크 미리보기
"""

import os
import time
from pathlib import Path
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))  # repo root (shared/ 위치)
from shared.event_client import emit_event  # noqa: E402
from shared.event_schema import Event, EventType, RedPhase  # noqa: E402
from shared.config_client import ConfigClient  # noqa: E402
from shared.edr_agent import start_edr_agent  # noqa: E402
from shared.siem_access_log import make_siem_access_middleware  # noqa: E402

DN_ROUTE_VULN_MAP = {
    "/api/smb/shares": "DN-001",
    "/api/ad/service-accounts": "DN-002",
    "/api/fileserver/backup-config": "DN-003",
    "/api/mail/relay": "DN-004",
    "/api/directory/search": "DN-005",
    "/api/webhook/preview": "DN-006",
}

ASSET_NAME = "defense_network"

_config = ConfigClient(asset=ASSET_NAME)


def _flag_key_to_vuln_id(flag_key: str) -> str:
    """'PATCH_DN_001' -> 'DN-001' (Config Service의 vuln_id 표기와 맞춤)."""
    rest = flag_key.removeprefix("PATCH_")
    return rest.replace("_", "-", 1)


app = FastAPI(title="Defense Network Digital Twin (TRAINING ONLY)")


@app.on_event("startup")
async def _start_edr_agent():
    start_edr_agent(asset_name=ASSET_NAME)


@app.middleware("http")
async def quarantine_and_killswitch_guard(request: Request, call_next):
    """EDR 콘솔의 '호스트 격리' 또는 교관의 킬스위치가 활성화되면 /health를 제외한
    모든 요청을 503으로 차단한다(호스트 격리/훈련 강제정지 시뮬레이션)."""
    if request.url.path != "/health":
        if _config.is_killswitch_active():
            return JSONResponse(status_code=503, content={"detail": "training halted by instructor killswitch"})
        if _config.is_quarantined():
            return JSONResponse(status_code=503, content={"detail": f"{ASSET_NAME} is quarantined by EDR console"})
    return await call_next(request)


app.middleware("http")(make_siem_access_middleware(ASSET_NAME, DN_ROUTE_VULN_MAP))


def patched(flag_key: str) -> bool:
    vuln_id = _flag_key_to_vuln_id(flag_key)
    return _config.is_patched(vuln_id, env_fallback_key=flag_key)


# ---------------------------------------------------------------------------
# 실제 SMTP 서버(P1-2 슬라이스) — 진짜 SMTP + 오픈 릴레이(DN-004).
# 인증 없이 외부 도메인 릴레이 수락 시 취약(스팸/피싱 발판). smtplib/swaks 로 실공격 가능.
# ---------------------------------------------------------------------------
import json as _json  # noqa: E402
import asyncio as _asyncio  # noqa: E402
from shared.net.smtp_server import SmtpSession as _SmtpSession, serve as _smtp_serve  # noqa: E402
from shared.siem_access_log import get_siem_logger as _get_siem_logger  # noqa: E402

_LOCAL_DOMAINS = {"corp.local", "defense.local"}
_smtp_siem = _get_siem_logger(ASSET_NAME)
_smtp_server = None


def _on_mail(msg: dict) -> None:
    """메일 접수 콜백 — 외부 릴레이면 DN-004 이벤트 + SIEM 로그(Blue 탐지 가능)."""
    if not msg.get("relay"):
        return
    if patched("PATCH_DN_004"):
        return
    try:
        emit_event(
            event_id=Event.make_id("smtp", ASSET_NAME, "DN-004", str(time.time())),
            event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
            vuln_id="DN-004", phase=RedPhase.lateral_movement, team_id="default",
            trace_id=Event.session_trace_id("smtp", ASSET_NAME),
            metadata={"protocol": "smtp", "sender": msg.get("sender"),
                      "recipients": msg.get("recipients"), "vector": "open_relay"})
    except Exception:
        pass
    try:
        _smtp_siem.info(_json.dumps({
            "ts": time.time(), "asset": ASSET_NAME, "method": "SMTP",
            "endpoint": "/smtp/relay", "status": 250, "vuln_id": "DN-004",
            "team_id": "default", "trace_id": Event.session_trace_id("smtp", ASSET_NAME),
            "sender": msg.get("sender"), "recipients": msg.get("recipients")}))
    except Exception:
        pass


def _smtp_factory() -> "_SmtpSession":
    # allow_relay 는 커넥션마다 patched 상태를 반영(패치되면 외부 릴레이 거부).
    return _SmtpSession("mail.corp.local", allow_relay=not patched("PATCH_DN_004"),
                        local_domains=_LOCAL_DOMAINS, on_message=_on_mail)


@app.on_event("startup")
async def _start_smtp():
    global _smtp_server
    if os.environ.get("SMTP_ENABLED", "1") != "1":
        return
    try:
        _smtp_server = await _smtp_serve(_smtp_factory, "0.0.0.0", int(os.environ.get("SMTP_PORT", "25")))
    except OSError:
        pass  # 25 바인딩 실패해도 HTTP 트윈은 계속


SHARES = {
    "PublicShare": ["readme.txt", "briefing_schedule.txt"],
    "AdminShare$": ["classified_dummy_report.pdf", "plant_safety_config.flag"],
}

SERVICE_ACCOUNTS = [
    {"name": "svc_backup", "spn": "MSSQLSvc/db01.internal.dummy:1433", "password_strength": "weak(8char)"},
    {"name": "svc_web", "spn": "HTTP/web01.internal.dummy", "password_strength": "weak(default)"},
]

BACKUP_CONFIG = {
    "backup_server": "backup01.internal.dummy",
    "service_account": "DUMMY\\svc_backup",
    "password": "B@ckup2019!",  # 더미 평문 자격증명 (DN-003)
    "path": "\\\\backup01\\shares\\daily",
}


class MailRelayRequest(BaseModel):
    mail_from: str
    mail_to: str
    subject: str
    body: str
    authenticated: bool = False


@app.get("/health")
def health():
    return {"status": "ok", "service": "defense_network"}


# ---------------------------------------------------------------------------
# DN-001: SMB Anonymous Share Access
# ---------------------------------------------------------------------------
@app.get("/api/smb/shares")
def smb_shares(authorization: str = Header(default=""), x_team_id: str = Header(default="default")):
    if patched("PATCH_DN_001"):
        if authorization != "Bearer valid-domain-user-token":
            raise HTTPException(401, "authentication required (Guest account disabled)")
    else:
        emit_event(
            event_id=Event.make_id(x_team_id, ASSET_NAME, "DN-001", str(time.time())),
            event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
            vuln_id="DN-001", phase=RedPhase.initial_access, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
            metadata={},
        )
    return {"patched": patched("PATCH_DN_001"), "shares": SHARES}


# ---------------------------------------------------------------------------
# DN-002: Kerberoastable Service Account
# ---------------------------------------------------------------------------
@app.get("/api/ad/service-accounts")
def service_accounts(authorization: str = Header(default=""), x_team_id: str = Header(default="default")):
    if patched("PATCH_DN_002"):
        # 패치 후: gMSA 전환 가정 -> 평문 강도 정보 노출하지 않고 인증 필요
        if authorization != "Bearer valid-domain-user-token":
            raise HTTPException(401, "authentication required")
        return {"patched": True, "accounts": [{"name": a["name"], "spn": a["spn"], "password_strength": "gMSA(240-char random)"} for a in SERVICE_ACCOUNTS]}
    emit_event(
        event_id=Event.make_id(x_team_id, ASSET_NAME, "DN-002", str(time.time())),
        event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
        vuln_id="DN-002", phase=RedPhase.privilege_escalation, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
        metadata={"accounts": [a["name"] for a in SERVICE_ACCOUNTS]},
    )
    return {"patched": False, "accounts": SERVICE_ACCOUNTS, "note": "TGS 요청만으로 오프라인 크래킹 대상 해시 획득 가능(시뮬레이션)"}


# ---------------------------------------------------------------------------
# DN-003: Exposed Backup Config with Plaintext Credentials
# ---------------------------------------------------------------------------
@app.get("/api/fileserver/backup-config")
def backup_config(authorization: str = Header(default=""), x_team_id: str = Header(default="default")):
    if patched("PATCH_DN_003"):
        raise HTTPException(404, "not found")  # 패치 후: Vault로 이관, 엔드포인트 제거된 것으로 처리
    emit_event(
        event_id=Event.make_id(x_team_id, ASSET_NAME, "DN-003", str(time.time())),
        event_type=EventType.flag_exfiltrated, actor="red", target_asset=ASSET_NAME,
        vuln_id="DN-003", phase=RedPhase.data_exfiltration, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
        metadata={"leaked_account": BACKUP_CONFIG["service_account"]},
    )
    return {"patched": False, "config": BACKUP_CONFIG}


# ---------------------------------------------------------------------------
# DN-004: Open Mail Relay
# ---------------------------------------------------------------------------
@app.post("/api/mail/relay")
def mail_relay(req: MailRelayRequest, x_team_id: str = Header(default="default")):
    if patched("PATCH_DN_004"):
        if not req.authenticated:
            raise HTTPException(401, "SMTP AUTH required")
        if not req.mail_from.endswith("@internal.dummy"):
            raise HTTPException(403, "sender domain not permitted (SPF/DKIM mismatch)")
    elif not req.authenticated:
        emit_event(
            event_id=Event.make_id(x_team_id, ASSET_NAME, "DN-004", str(time.time())),
            event_type=EventType.red_objective_success, actor="red", target_asset=ASSET_NAME,
            vuln_id="DN-004", phase=RedPhase.objective, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
            metadata={"mail_from": req.mail_from, "mail_to": req.mail_to},
        )
    return {
        "patched": patched("PATCH_DN_004"),
        "status": "relayed",
        "from": req.mail_from,
        "to": req.mail_to,
        "subject": req.subject,
    }


# ---------------------------------------------------------------------------
# DN-005: LDAP Injection (직원 디렉터리 검색)
# ---------------------------------------------------------------------------
DIRECTORY = [
    {"uid": "jkim", "name": "Kim Jiwoo", "dept": "Ops", "title": "Operator"},
    {"uid": "shan", "name": "Han Seo", "dept": "IT", "title": "Sysadmin"},
    {"uid": "admin", "name": "Domain Admin", "dept": "IT", "title": "Administrator",
     "secret_note": "temp_pw=Winter2026! (교체 예정)"},  # 인젝션으로 유출되면 안 되는 더미 민감정보
]
_LDAP_META = ["*", "(", ")", "|", "&", "\\", "\x00"]


@app.get("/api/directory/search")
def directory_search(q: str, x_team_id: str = Header(default="default")):
    injection = any(m in q for m in _LDAP_META)
    if patched("PATCH_DN_005"):
        # 패치 후: LDAP 메타문자 이스케이프/거부 -> 인젝션 불가
        if injection:
            raise HTTPException(400, "invalid characters in search query")
        results = [{k: v for k, v in e.items() if k != "secret_note"}
                   for e in DIRECTORY if q.lower() in e["name"].lower() or q.lower() == e["uid"]]
        return {"patched": True, "results": results}
    # 취약 지점: q를 LDAP 필터 문자열에 그대로 결합 -> '*' / ')(' 로 전체·관리자 레코드 덤프
    if injection:
        emit_event(
            event_id=Event.make_id(x_team_id, ASSET_NAME, "DN-005", q, str(time.time())),
            event_type=EventType.flag_exfiltrated, actor="red", target_asset=ASSET_NAME,
            vuln_id="DN-005", phase=RedPhase.data_exfiltration, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
            metadata={"query": q, "note": "LDAP filter injection dumped full directory"},
        )
        return {"patched": False, "filter": f"(|(uid={q})(cn={q}))", "results": DIRECTORY}
    results = [e for e in DIRECTORY if q.lower() in e["name"].lower() or q.lower() == e["uid"]]
    return {"patched": False, "filter": f"(|(uid={q})(cn={q}))", "results": results}


# ---------------------------------------------------------------------------
# DN-006: SSRF (파일서버 URL 미리보기)
# ---------------------------------------------------------------------------
class PreviewRequest(BaseModel):
    url: str


def _is_internal_target(url: str) -> bool:
    u = url.lower()
    if u.startswith("file://") or u.startswith("gopher://") or u.startswith("dict://"):
        return True
    for needle in ("169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0",
                   "10.", "192.168.", "internal", "metadata"):
        if needle in u:
            return True
    return False


@app.post("/api/webhook/preview")
def webhook_preview(req: PreviewRequest, x_team_id: str = Header(default="default")):
    internal = _is_internal_target(req.url)
    if patched("PATCH_DN_006"):
        # 패치 후: 내부/사설/파일 스킴 차단(SSRF 방지), 외부 http(s)만 미리보기
        if internal or not (req.url.startswith("http://") or req.url.startswith("https://")):
            raise HTTPException(400, "target not allowed")
        return {"patched": True, "url": req.url, "title": "External document preview"}
    # 취약 지점: 사용자 URL을 서버가 그대로 요청 -> 내부 자원/메타데이터 미리보기(SSRF)
    if internal:
        emit_event(
            event_id=Event.make_id(x_team_id, ASSET_NAME, "DN-006", req.url, str(time.time())),
            event_type=EventType.red_attack_started, actor="red", target_asset=ASSET_NAME,
            vuln_id="DN-006", phase=RedPhase.lateral_movement, team_id=x_team_id,
            trace_id=Event.session_trace_id(x_team_id, ASSET_NAME),
            metadata={"requested_url": req.url},
        )
        return {"patched": False, "url": req.url,
                "internal_response": {"service_account": "DUMMY\\svc_backup", "note": "SSRF reached internal resource"}}
    return {"patched": False, "url": req.url, "title": "External document preview"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
