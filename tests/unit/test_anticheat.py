"""
공정성/안티치트(P1-5) 계약 고정.
- 플래그 rate-limit(슬라이딩 윈도) + 연속 실패 lockout(백오프)
- 제출 감사(모든 시도 기록) + 플래그 공유(팀 간 동일 플래그) 탐지
대회 무결성: 무차별 대입·정답 공유를 막고 모든 제출을 감사 가능하게.
"""
import sqlite3

import pytest

from services.challenge_portal.anticheat import (
    AntiCheatState, Config, flag_hash, precheck, record, detect_sharing, init_audit,
)


@pytest.fixture
def cfg():
    return Config(max_attempts=5, window_sec=60, lock_fails=3, lock_sec=100)


@pytest.fixture
def st():
    return AntiCheatState()


@pytest.fixture
def audit():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    init_audit(c)
    return c


def test_flag_hash_stable_and_opaque():
    h = flag_hash("CTF{secret}")
    assert h == flag_hash("CTF{secret}")
    assert "secret" not in h and len(h) == 64


def test_under_limit_allowed(st, cfg):
    # rate-limit(윈도) 격리 검증 — lockout 을 건드리지 않도록 정답 제출로 진행(연속실패 0 유지).
    for i in range(cfg.max_attempts):
        allowed, retry = precheck(st, "team_a", "web-01", now=1000 + i, cfg=cfg)
        assert allowed, f"attempt {i} should be allowed"
        record(st, None, "team_a", "", "web-01", "red", flag_hash(f"x{i}"), passed=True, now=1000 + i, cfg=cfg)


def test_rate_limit_blocks_over_window(st, cfg):
    # window 안에서 max_attempts 초과 → 차단(retry_after > 0)
    for i in range(cfg.max_attempts):
        precheck(st, "t", "c", now=1000, cfg=cfg)
        record(st, None, "t", "", "c", "red", flag_hash(str(i)), passed=False, now=1000, cfg=cfg)
    allowed, retry = precheck(st, "t", "c", now=1000, cfg=cfg)
    assert not allowed and retry > 0


def test_window_slides_and_recovers(st, cfg):
    # 윈도 회복 격리 — lockout 개입 없도록 정답 제출로 윈도만 채운다.
    for i in range(cfg.max_attempts):
        record(st, None, "t", "", "c", "red", flag_hash(str(i)), passed=True, now=1000, cfg=cfg)
    allowed_now, _ = precheck(st, "t", "c", now=1000, cfg=cfg)
    assert not allowed_now                      # 윈도 가득 → 차단
    allowed, _ = precheck(st, "t", "c", now=1000 + cfg.window_sec + 1, cfg=cfg)
    assert allowed                              # 윈도(60s) 이후 회복


def test_lockout_after_consecutive_fails(st, cfg):
    # 연속 lock_fails 회 오답 → lock_sec 동안 잠금(윈도와 별개)
    for i in range(cfg.lock_fails):
        record(st, None, "t", "", "c", "red", flag_hash(str(i)), passed=False, now=2000 + i, cfg=cfg)
    allowed, retry = precheck(st, "t", "c", now=2000 + cfg.lock_fails, cfg=cfg)
    assert not allowed and retry > 0


def test_correct_answer_resets_consecutive_fails(st, cfg):
    for i in range(cfg.lock_fails - 1):
        record(st, None, "t", "", "c", "red", flag_hash(str(i)), passed=False, now=3000 + i, cfg=cfg)
    record(st, None, "t", "", "c", "red", flag_hash("correct"), passed=True, now=3000 + cfg.lock_fails, cfg=cfg)
    # 정답으로 연속 실패 카운터 리셋 → 다음 시도 허용
    allowed, _ = precheck(st, "t", "c", now=3000 + cfg.lock_fails + 1, cfg=cfg)
    assert allowed


def test_audit_records_every_attempt(st, cfg, audit):
    record(st, audit, "team_a", "m1", "web-01", "red", flag_hash("a"), passed=False, now=1, cfg=cfg)
    record(st, audit, "team_a", "m1", "web-01", "red", flag_hash("b"), passed=True, now=2, cfg=cfg)
    rows = audit.execute("SELECT * FROM submissions ORDER BY ts").fetchall()
    assert len(rows) == 2 and rows[1]["passed"] == 1 and rows[0]["team_id"] == "team_a"


def test_detect_flag_sharing_across_teams(st, cfg, audit):
    shared = flag_hash("CTF{shared_between_teams}")
    record(st, audit, "team_a", "m1", "web-01", "red", shared, passed=True, now=1, cfg=cfg)
    record(st, audit, "team_b", "m1", "web-01", "red", shared, passed=True, now=2, cfg=cfg)
    others = detect_sharing(audit, "web-01", shared, "team_b")
    assert others == ["team_a"]   # 같은 플래그를 먼저 낸 다른 팀


def test_no_false_sharing_for_unique_flags(st, cfg, audit):
    record(st, audit, "team_a", "m1", "web-01", "red", flag_hash("uniqueA"), passed=True, now=1, cfg=cfg)
    others = detect_sharing(audit, "web-01", flag_hash("uniqueB"), "team_b")
    assert others == []
