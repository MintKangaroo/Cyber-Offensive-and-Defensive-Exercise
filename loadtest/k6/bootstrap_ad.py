#!/usr/bin/env python3
"""Attack/Defense 부하 프로파일 부트스트랩.

k6 `attack_defense.js` 는 매치·팀·경쟁자 토큰이 이미 존재한다고 가정한다. 이 스크립트는
k6 실행 전에 그 전제를 실제로 만들어 준다:

  1. operator JWT 로 매치(id=MATCH_ID)를 생성
  2. 팀 N개(team-01..team-NN) + 서비스 2개(notes/vault)를 등록
  3. 매치를 시작(팀 ≥2·서비스 ≥1 요건 충족 → 라운드 활성)
  4. 팀별 competitor JWT(team_id·match_id 클레임 포함)를 민팅해 파일로 내보냄

의존성 0 — HS256 서명을 표준 라이브러리(hmac/hashlib/base64)로 직접 만든다. CI 러너에
PyJWT 를 설치할 필요가 없다. 서비스는 AUTH_JWT_SECRET 로 이 토큰을 검증한다(shared/rbac.py).

모든 생성 단계는 멱등이다(이미 있으면 409 → 성공으로 취급). 이미 시작된 매치를 다시
시작하면 409 이므로 마찬가지로 무시한다.

환경변수:
  AD_API             attack_defense 베이스 URL (기본 http://localhost:8100)
  MATCH_ID           매치 ID (기본 ad-load) — k6 의 MATCH_ID 와 일치해야 함
  AD_TEAMS           팀 수 (기본 12)
  AUTH_JWT_SECRET    JWT 서명 시크릿 (필수)
  JWT_TTL_SECONDS    토큰 만료(초, 기본 7200)
  TOKENS_OUT         competitor 토큰을 콤마로 이어 쓸 파일 경로
                     (기본 loadtest/results/ad_competitor_tokens.txt)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request

AD_API = os.environ.get("AD_API", "http://localhost:8100").rstrip("/")
MATCH_ID = os.environ.get("MATCH_ID", "ad-load")
TEAMS = int(os.environ.get("AD_TEAMS", "12"))
SECRET = os.environ.get("AUTH_JWT_SECRET", "").strip()
TTL = int(os.environ.get("JWT_TTL_SECONDS", "7200"))
TOKENS_OUT = os.environ.get(
    "TOKENS_OUT", "loadtest/results/ad_competitor_tokens.txt"
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint_jwt(claims: dict) -> str:
    """HS256 JWT 를 표준 라이브러리만으로 서명한다."""
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {"iat": now, "exp": now + TTL, "type": "access", **claims}
    segments = [
        _b64(json.dumps(header, separators=(",", ":")).encode()),
        _b64(json.dumps(payload, separators=(",", ":")).encode()),
    ]
    signing_input = ".".join(segments).encode("ascii")
    signature = hmac.new(SECRET.encode(), signing_input, hashlib.sha256).digest()
    segments.append(_b64(signature))
    return ".".join(segments)


def _request(method: str, path: str, token: str, body: dict | None = None):
    url = f"{AD_API}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode() or "{}"
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            parsed = json.loads(raw)
        except ValueError:
            parsed = {"detail": raw}
        return exc.code, parsed


def _ok(status: int, *, idempotent_conflict: bool = True) -> bool:
    if 200 <= status < 300:
        return True
    return idempotent_conflict and status == 409


def main() -> int:
    if not SECRET:
        print("AUTH_JWT_SECRET 미설정 — 부트스트랩은 실제 JWT 를 요구한다.", file=sys.stderr)
        return 2

    operator = mint_jwt({"sub": "loadtest-operator", "role": "operator"})

    # 1) 매치 생성 --------------------------------------------------------
    status, resp = _request(
        "POST", "/api/attack-defense/matches", operator,
        {"id": MATCH_ID, "name": "Load Profile", "mode": "attack_defense",
         "round_duration_seconds": 30},
    )
    if not _ok(status):
        print(f"매치 생성 실패 status={status} resp={resp}", file=sys.stderr)
        return 1
    print(f"매치 준비 완료: {MATCH_ID} (status={status})")

    # 2) 팀 생성(멱등) ---------------------------------------------------
    team_ids: list[str] = []
    for i in range(1, TEAMS + 1):
        tid = f"team-{i:02d}"
        status, resp = _request(
            "POST", f"/api/attack-defense/matches/{MATCH_ID}/teams", operator,
            {"id": tid, "slug": f"load-{i:02d}", "name": f"Load Team {i:02d}"},
        )
        if not _ok(status):
            print(f"팀 {tid} 생성 실패 status={status} resp={resp}", file=sys.stderr)
            return 1
        team_ids.append(tid)
    print(f"팀 {len(team_ids)}개 준비 완료")

    # 3) 서비스 2개 생성(매치 시작 요건: 서비스 ≥1) ----------------------
    services = [
        {"id": "svc-notes", "slug": "notes", "name": "Notes",
         "base_image": "attack-defense/notes:load", "internal_port": 9000,
         "checker_type": "vulnerable_notes"},
        {"id": "svc-vault", "slug": "vault", "name": "Vault",
         "base_image": "attack-defense/vault:load", "internal_port": 9000,
         "checker_type": "file_vault"},
    ]
    for svc in services:
        status, resp = _request(
            "POST", f"/api/attack-defense/matches/{MATCH_ID}/services", operator, svc,
        )
        if not _ok(status):
            print(f"서비스 {svc['id']} 생성 실패 status={status} resp={resp}",
                  file=sys.stderr)
            return 1
    print(f"서비스 {len(services)}개 준비 완료")

    # 4) 매치 시작(멱등: 이미 running 이면 409) ---------------------------
    status, resp = _request(
        "POST", f"/api/attack-defense/matches/{MATCH_ID}/start", operator,
        {"reason": "load profile bootstrap"},
    )
    if _ok(status):
        print(f"매치 시작(status={status})")
    else:
        # 이미 실행 중이 아닌 다른 실패는 치명적이지 않다 — scoreboard 는 매치만 있으면
        # 200 이고, flag submit 은 라운드가 없어도 rejected(200) 을 돌려준다.
        print(f"매치 시작 경고 status={status} resp={resp} — 계속 진행", file=sys.stderr)

    # 5) competitor 토큰 민팅 --------------------------------------------
    tokens = [
        mint_jwt({
            "sub": f"loadtest-{tid}", "role": "competitor",
            "team_id": tid, "match_id": MATCH_ID,
        })
        for tid in team_ids
    ]
    os.makedirs(os.path.dirname(TOKENS_OUT) or ".", exist_ok=True)
    with open(TOKENS_OUT, "w", encoding="utf-8") as fh:
        fh.write(",".join(tokens))
    print(f"competitor 토큰 {len(tokens)}개 → {TOKENS_OUT}")

    # 6) 스모크: 첫 팀 토큰으로 무효 플래그 제출 → 200(rejected) 확인 ------
    smoke_status, smoke_resp = _request(
        "POST", f"/api/attack-defense/matches/{MATCH_ID}/flags/submit", tokens[0],
        {"flag": "FLAG{loadprofilesmoke0000000000000000}"},
    )
    if smoke_status != 200:
        print(f"스모크 제출 실패 status={smoke_status} resp={smoke_resp} — "
              "토큰/멤버십 문제일 수 있음", file=sys.stderr)
        return 1
    print(f"스모크 제출 확인: status=200 accepted={smoke_resp.get('accepted')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
