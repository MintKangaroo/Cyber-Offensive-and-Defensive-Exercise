"""
PCAP 프라이버시 — 익명화·플래그 스크러빙·지연 배포·워터마크 (roadmap #1)
=========================================================================
A/D 대회에서 캡처한 네트워크 트래픽(플로우 레코드)을 팀에 공개하기 전에 반드시 정제한다:

  1. 플래그 스크러빙   — 라이브 플래그·민감 토큰을 페이로드에서 제거(현재 라운드 플래그 하베스팅 방지)
  2. 식별자 익명화     — 팀 IP 를 salt 기반 불투명 별칭(TEAM-xxxx)으로 치환(귀속 은닉)
  3. 지연 게이팅       — 라운드 종료 후 delay_sec 이 지나야 공개(라이브 익스플로잇 방지)
  4. 워터마크          — 수신자별 결정론적 마커 삽입(유출 추적)

순수 함수라 소켓/파일 없이 단위 테스트 가능. 실제 PCAP 파싱(scapy)은 캡처 파이프라인의 별도
어댑터가 담당하고, 이 모듈은 구조화된 플로우 레코드({ts,src_ip,dst_ip,payload})에 적용한다.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from .utils import stable_id

# 일반적인 CTF 플래그 패턴(PREFIX{...}). active 목록에 없어도 보수적으로 스크럽.
_FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}\r\n]{3,}\}")
# authorization/token/password/secret 뒤의 값 스크럽.
_SENSITIVE_RE = re.compile(
    r"(?i)\b(authorization|token|password|secret|api[_-]?key)\b(\s*[:=]\s*(?:Bearer\s+)?)([^\s\"',;}]+)")
_REDACTED = "[FLAG-REDACTED]"


def scrub_flags(payload: str, active_flags: set) -> str:
    """페이로드에서 라이브 플래그·일반 플래그 패턴·민감 토큰 값을 제거."""
    if not payload:
        return payload
    out = payload
    for f in sorted((f for f in active_flags if f), key=len, reverse=True):
        out = out.replace(f, _REDACTED)
    out = _FLAG_RE.sub(_REDACTED, out)
    out = _SENSITIVE_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", out)
    return out


def build_alias_map(team_ips: dict, salt: str) -> dict:
    """team_id->ip 매핑 → ip->불투명 별칭(TEAM-xxxx). salt 없이는 실팀 역추적 불가."""
    out = {}
    for team_id, ip in team_ips.items():
        if not ip:
            continue
        h = hashlib.sha256(f"{salt}:{team_id}".encode()).hexdigest()[:6]
        out[ip] = f"TEAM-{h}"
    return out


def rewrite_text(text: str, alias_map: dict) -> str:
    """텍스트 내 알려진 팀 IP 를 별칭으로 치환(긴 IP 우선)."""
    if not text:
        return text
    out = text
    for ip in sorted(alias_map, key=len, reverse=True):
        out = out.replace(ip, alias_map[ip])
    return out


def is_released(capture_ts: float, now: float, delay_sec: float) -> bool:
    """캡처 후 delay_sec 이 지나 공개 가능한가."""
    return (now - capture_ts) > delay_sec


def watermark(content: str, recipient_id: str) -> str:
    """수신자별 결정론적 워터마크 삽입(유출 추적용)."""
    tag = stable_id("pcap-wm", recipient_id, content)[:12]
    return f"{content}\n# watermark:{tag}"


def sanitize_capture(flows: list, active_flags: set, team_ips: dict, recipient_id: str,
                     capture_ts: float, now: float, delay_sec: float, salt: str) -> dict:
    """캡처 플로우를 수신자에게 배포 가능한 정제본으로 변환.
    지연 전이면 flows 를 비우고 released=False. 지연 후엔 스크럽+익명화+워터마크."""
    released = is_released(capture_ts, now, delay_sec)
    if not released:
        return {"released": False, "flows": [], "recipient": recipient_id,
                "available_after_sec": max(0, int(capture_ts + delay_sec - now))}
    alias = build_alias_map(team_ips, salt)
    clean_flows: list[dict[str, Any]] = []
    for fl in flows:
        payload = scrub_flags(str(fl.get("payload", "")), active_flags)
        payload = rewrite_text(payload, alias)
        clean_flows.append({
            "ts": fl.get("ts"),
            "src": alias.get(fl.get("src_ip"), fl.get("src_ip")),
            "dst": alias.get(fl.get("dst_ip"), fl.get("dst_ip")),
            "payload": payload,
        })
    from .utils import canonical_json
    wm = watermark(canonical_json(clean_flows), recipient_id).rsplit("watermark:", 1)[-1]
    return {"released": True, "recipient": recipient_id, "flows": clean_flows, "watermark": wm}
