"""리허설 하네스(scripts/rehearsal) 순수 로직 회귀 — 도커 불필요.

봇의 핵심 로직(competitor JWT 발급 형식, 플래그 추출, 리포터 집계)이 계약대로 동작함을
고정한다. 실제 E2E 완주(make rehearsal)는 도커 기동이 필요하므로 별도.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

from scripts.rehearsal import common, red_bot


def _decode_seg(seg: str) -> dict:
    pad = "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg + pad))


def test_mint_competitor_jwt_is_valid_hs256_with_claims():
    secret = "test-secret-key-for-rehearsal-only"  # training-only
    tok = red_bot.mint_competitor("team-1", "ad-demo", secret)
    header_b64, payload_b64, sig_b64 = tok.split(".")
    header = _decode_seg(header_b64)
    payload = _decode_seg(payload_b64)
    assert header == {"alg": "HS256", "typ": "JWT"}
    assert payload["role"] == "competitor"
    assert payload["team_id"] == "team-1"
    assert payload["match_id"] == "ad-demo"
    assert payload["type"] == "access"
    # 서명이 시크릿으로 검증되는지(위조 불가)
    expected = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f"{header_b64}.{payload_b64}".encode(),
                 hashlib.sha256).digest()).rstrip(b"=").decode()
    assert sig_b64 == expected


def test_flag_regex_extracts_flags():
    body = 'note content FLAG{abc-DEF_123} trailing and FLAG{second_one}'
    found = red_bot.FLAG_RE.findall(body)
    assert found == ["FLAG{abc-DEF_123}", "FLAG{second_one}"]
    assert red_bot.FLAG_RE.findall("no flag here") == []


def test_reporter_aggregates_pass_fail():
    rep = common.Reporter("t")
    rep.check(True, "a")
    rep.check(False, "b")
    rep.check(True, "c")
    rep.note("info")  # ok=None, 집계 제외
    assert rep.passed == 2
    assert rep.failed == 1
    assert rep.ok is False
    rep2 = common.Reporter("t2")
    rep2.check(True, "x")
    assert rep2.ok is True
