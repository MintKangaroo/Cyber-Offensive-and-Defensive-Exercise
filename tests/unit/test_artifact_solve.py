"""
artifact_solve 하버스 유닛 테스트 (P2b)
==========================================
exploit 계약 통일의 두 핵심 헬퍼를 검증:
 - _call_solve: 시그니처(경로형/team_id형/HTTP형)에 맞춰 올바른 인자로 호출
 - _normalize_submission: dict는 그대로, str은 {"flag": ...}로 정규화
"""
import importlib.util
from pathlib import Path

REPO = Path(__file__).parent.parent.parent
_spec = importlib.util.spec_from_file_location(
    "artifact_solve", REPO / "infra" / "challenge_qa" / "artifact_solve.py"
)
asolve = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(asolve)


# --- _normalize_submission --------------------------------------------------

def test_normalize_dict_passthrough():
    assert asolve._normalize_submission({"username": "a", "password": "b"}) == {"username": "a", "password": "b"}


def test_normalize_str_wraps_as_flag():
    assert asolve._normalize_submission("flag{x}") == {"flag": "flag{x}"}


# --- _call_solve 시그니처 분기 ----------------------------------------------

def test_call_solve_path_form():
    solve = lambda path: f"path:{path}"
    got = asolve._call_solve(solve, base_url="http://x", team_id="t1", artifact_path=Path("/tmp/a.bin"))
    assert got == "path:/tmp/a.bin"


def test_call_solve_team_form():
    solve = lambda team_id: f"team:{team_id}"
    got = asolve._call_solve(solve, base_url="http://x", team_id="t1", artifact_path=None)
    assert got == "team:t1"


def test_call_solve_http_form():
    solve = lambda base_url, team_id: f"{base_url}|{team_id}"
    got = asolve._call_solve(solve, base_url="http://x", team_id="t1", artifact_path=None)
    assert got == "http://x|t1"


def test_call_solve_path_missing_raises():
    solve = lambda capture_path: capture_path
    import pytest
    with pytest.raises(RuntimeError):
        asolve._call_solve(solve, base_url="http://x", team_id="t1", artifact_path=None)
