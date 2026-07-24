"""
Defense Network Digital Twin (국방망 디지털 트윈)
--------------------------------------------------
Live Fire Cyber Range 훈련용 모의 서비스. 실제 AD/파일서버/메일서버가 아니며
SMB/Kerberos/SMTP 프로토콜을 흉내낸 REST API 시뮬레이션입니다. 모든 계정/
자격증명/문서는 더미 데이터입니다.

취약점 목록(shared/vuln_catalog.json 의 defense_network 항목과 대응):
  DN-001 SMB Anonymous Share Access          (/api/smb/shares)
  DN-002 Kerberoastable Service Account       (/api/ad/service-accounts)
  DN-003 Exposed Backup Config w/ Plaintext   (/api/fileserver/backup-config)
  DN-004 Open Mail Relay                      (/api/mail/relay)
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
