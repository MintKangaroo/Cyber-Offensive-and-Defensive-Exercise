"""
PCAP 프라이버시(roadmap #1) 계약 고정 — 플래그 스크러빙·식별자 익명화·지연 게이팅·워터마크.
A/D 에서 캡처 트래픽을 팀에 공개하기 전, 라이브 플래그/토큰을 제거하고 팀 귀속을 익명화하며
지연 후에만, 수신자별 워터마크와 함께 배포한다.
"""
from services.attack_defense.pcap_privacy import (
    scrub_flags, build_alias_map, rewrite_text, is_released, watermark, sanitize_capture,
)


def test_scrub_exact_active_flag():
    p = "GET /note?x=CR{live-flag-abc123} HTTP/1.1"
    out = scrub_flags(p, {"CR{live-flag-abc123}"})
    assert "live-flag-abc123" not in out and "[FLAG-REDACTED]" in out


def test_scrub_generic_flag_pattern():
    # active 목록에 없어도 일반 플래그 패턴은 스크럽(보수적)
    out = scrub_flags("token FLAG{unknown_but_looks_like_flag}", set())
    assert "unknown_but_looks_like_flag" not in out


def test_scrub_sensitive_kv():
    out = scrub_flags("Authorization: Bearer sk-secret-xyz\npassword=hunter2", set())
    assert "sk-secret-xyz" not in out and "hunter2" not in out


def test_alias_map_opaque_and_stable():
    m1 = build_alias_map({"team-red": "10.0.0.1", "team-blue": "10.0.0.2"}, salt="s")
    m2 = build_alias_map({"team-red": "10.0.0.1", "team-blue": "10.0.0.2"}, salt="s")
    assert m1 == m2                              # 결정론적
    assert set(m1.keys()) == {"10.0.0.1", "10.0.0.2"}
    # 실팀 id 가 별칭에 노출되지 않음
    assert all("team-red" not in a and "team-blue" not in a for a in m1.values())
    assert all(a.startswith("TEAM-") for a in m1.values())


def test_alias_salt_changes_mapping():
    a = build_alias_map({"t": "10.0.0.1"}, salt="s1")["10.0.0.1"]
    b = build_alias_map({"t": "10.0.0.1"}, salt="s2")["10.0.0.1"]
    assert a != b


def test_rewrite_text_replaces_ips_with_alias():
    m = {"10.0.0.1": "TEAM-ab", "10.0.0.2": "TEAM-cd"}
    out = rewrite_text("from 10.0.0.1 to 10.0.0.2", m)
    assert "10.0.0.1" not in out and "TEAM-ab" in out and "TEAM-cd" in out


def test_release_delay_gate():
    assert is_released(capture_ts=100, now=100 + 300, delay_sec=600) is False
    assert is_released(capture_ts=100, now=100 + 601, delay_sec=600) is True


def test_watermark_deterministic_per_recipient():
    w1 = watermark("content", "team-red")
    w2 = watermark("content", "team-red")
    w3 = watermark("content", "team-blue")
    assert w1 == w2 and w1 != w3 and "content" in w1


def test_sanitize_capture_end_to_end():
    flows = [
        {"ts": 100, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
         "payload": "POST /login token=CR{secret} 10.0.0.1"},
    ]
    res = sanitize_capture(
        flows, active_flags={"CR{secret}"},
        team_ips={"team-red": "10.0.0.1", "team-blue": "10.0.0.2"},
        recipient_id="team-blue", capture_ts=100, now=100 + 700, delay_sec=600, salt="s")
    assert res["released"] is True
    f = res["flows"][0]
    assert "CR{secret}" not in f["payload"] and "10.0.0.1" not in f["payload"]
    assert f["src"].startswith("TEAM-") and f["dst"].startswith("TEAM-")
    assert "watermark" in res


def test_sanitize_capture_withheld_before_delay():
    res = sanitize_capture([], set(), {}, "t", capture_ts=100, now=200, delay_sec=600, salt="s")
    assert res["released"] is False and res["flows"] == []


# ── API 레벨: operator 게이팅 + 정제 배포 ──────────────────────────────────
import time
import jwt
from fastapi.testclient import TestClient
from services.attack_defense.api import create_app

_SECRET = "unit-test-jwt-secret-with-enough-entropy"


def _tok(role, team="", match=""):
    return jwt.encode({"sub": f"{role}-{team or 'u'}", "role": role, "team_id": team,
                       "match_id": match, "type": "access", "exp": int(time.time()) + 300},
                      _SECRET, algorithm="HS256")


def test_api_sanitize_requires_operator(ad, monkeypatch):
    monkeypatch.setenv("AUTH_JWT_SECRET", _SECRET)
    client = TestClient(create_app(ad))
    body = {"recipient_team_id": "team-1", "capture_ts": time.time(), "flows": [], "team_ips": {}, "reason": "post-round analysis"}
    r = client.post("/api/attack-defense/captures/sanitize", json=body,
                    headers={"Authorization": f"Bearer {_tok('competitor', 'team-1', 'm')}"})
    assert r.status_code == 403


def test_api_sanitize_released_and_scrubbed(ad, monkeypatch):
    monkeypatch.setenv("AUTH_JWT_SECRET", _SECRET)
    client = TestClient(create_app(ad))
    body = {
        "recipient_team_id": "team-blue", "capture_ts": time.time() - 100000,  # 지연 지남
        "flows": [{"ts": 1, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                   "payload": "token=CR{live} from 10.0.0.1"}],
        "active_flags": ["CR{live}"],
        "team_ips": {"team-red": "10.0.0.1", "team-blue": "10.0.0.2"},
        "reason": "post-round analysis release",
    }
    r = client.post("/api/attack-defense/captures/sanitize", json=body,
                    headers={"Authorization": f"Bearer {_tok('operator')}"})
    assert r.status_code == 200
    d = r.json()
    assert d["released"] is True
    fl = d["flows"][0]
    assert "CR{live}" not in fl["payload"] and "10.0.0.1" not in fl["payload"]
    assert fl["src"].startswith("TEAM-") and "watermark" in d
