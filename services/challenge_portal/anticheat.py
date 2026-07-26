"""
공정성/안티치트(P1-5) — 플래그 제출 무결성
=============================================
challenge_portal 제출 경로에 얹는 대회 무결성 통제. 상태 로직은 순수함수(테스트 용이),
감사는 sqlite 영속.

통제:
  1) rate-limit: (팀,챌린지) 슬라이딩 윈도 내 제출 횟수 상한 → 무차별 플래그 대입 차단.
  2) lockout: 연속 오답 lock_fails 회 → lock_sec 잠금(정답 시 카운터 리셋).
  3) 감사(audit): 모든 제출 시도를 기록(팀·매치·챌린지·정답여부·플래그해시·시각) → 사후 검증.
  4) 플래그 공유 탐지: 같은 챌린지에 동일 플래그 해시를 낸 다른 팀 발견 → 담합 신호.

플래그 원문은 저장하지 않는다(sha256 해시만). 매치별 플래그 회전과 결합하면 같은 매치에서
팀 간 동일 해시 = 강한 공유 신호.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Config:
    max_attempts: int = 10     # 윈도 내 최대 제출
    window_sec: int = 60       # 슬라이딩 윈도 길이
    lock_fails: int = 6        # 연속 오답 임계
    lock_sec: int = 120        # 잠금 시간

    @staticmethod
    def from_env() -> "Config":
        g = lambda k, d: int(os.environ.get(k, d))  # noqa: E731
        return Config(g("PORTAL_MAX_ATTEMPTS", 10), g("PORTAL_WINDOW_SEC", 60),
                      g("PORTAL_LOCK_FAILS", 6), g("PORTAL_LOCK_SEC", 120))


@dataclass
class AntiCheatState:
    # key=(team,cid) → 최근 제출 시각 리스트
    attempts: dict[tuple[str, str], list[float]] = field(default_factory=lambda: defaultdict(list))
    consecutive_fails: dict[tuple[str, str], int] = field(default_factory=lambda: defaultdict(int))
    locked_until: dict[tuple[str, str], float] = field(default_factory=dict)


def flag_hash(value: str) -> str:
    return hashlib.sha256((value or "").strip().encode()).hexdigest()


def precheck(st: AntiCheatState, team: str, cid: str, now: float, cfg: Config):
    """제출 허용 여부. 반환 (allowed: bool, retry_after: int(초))."""
    key = (team, cid)
    lu = st.locked_until.get(key, 0)
    if now < lu:
        return False, int(lu - now) + 1
    # 슬라이딩 윈도 정리
    recent = [t for t in st.attempts[key] if now - t < cfg.window_sec]
    st.attempts[key] = recent
    if len(recent) >= cfg.max_attempts:
        retry = int(cfg.window_sec - (now - min(recent))) + 1
        return False, max(retry, 1)
    return True, 0


def record(st: AntiCheatState, audit: sqlite3.Connection | None, team: str, match: str,
           cid: str, side: str, value_hash: str, passed: bool, now: float, cfg: Config) -> None:
    """제출 1건 반영 — 윈도·연속실패·잠금 갱신 + 감사 기록."""
    key = (team, cid)
    st.attempts[key].append(now)
    if passed:
        st.consecutive_fails[key] = 0
        st.locked_until.pop(key, None)
    else:
        st.consecutive_fails[key] += 1
        if st.consecutive_fails[key] >= cfg.lock_fails:
            st.locked_until[key] = now + cfg.lock_sec
            st.consecutive_fails[key] = 0   # 잠금 후 카운터 리셋(잠금 만료 뒤 재시도 여지)
    if audit is not None:
        audit.execute(
            "INSERT INTO submissions(ts,team_id,match_id,cid,side,passed,value_hash) VALUES(?,?,?,?,?,?,?)",
            (now, team, match, cid, side, 1 if passed else 0, value_hash))
        audit.commit()


def detect_sharing(audit: sqlite3.Connection, cid: str, value_hash: str, team: str) -> list[str]:
    """같은 챌린지에 동일 플래그 해시를 낸 '다른' 팀 목록(먼저 제출한 순). 비면 공유 없음."""
    rows = audit.execute(
        "SELECT DISTINCT team_id FROM submissions WHERE cid=? AND value_hash=? AND team_id!=? ORDER BY ts",
        (cid, value_hash, team)).fetchall()
    return [r["team_id"] if isinstance(r, sqlite3.Row) else r[0] for r in rows]


def init_audit(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS submissions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL, team_id TEXT, match_id TEXT, cid TEXT, side TEXT,
        passed INTEGER, value_hash TEXT)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sub_cid_hash ON submissions(cid, value_hash)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sub_team ON submissions(team_id)")
    conn.commit()
