"""S-1(경미) 회귀: safe_probe CLI 가 측정 불가(도달 불가)/오류 시 fail-closed 로 비-0 종료한다.

원 지적(audit/101_reaudit.md S-1 잔여): run() 요약은 unreachable 을 집계하지만 __main__ 은
종료코드를 항상 0 으로 둬, CLI 를 자동화에서 소비하는 스크립트가 "측정 실패"를 통과로 오인할
여지가 있었다. 이 테스트는 서비스가 하나도 안 뜬 상태(전부 UNREACHABLE)에서 CLI 가 exit 1
을 내는지 고정한다.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_cli_exits_nonzero_when_unreachable():
    # 서비스 미기동 → 프로브가 전부 도달 불가 → fail-closed exit 1.
    proc = subprocess.run(
        [sys.executable, "-m", "shared.safe_probe", "--asset", "ground_station",
         "--no-emit", "--summary"],
        cwd=str(ROOT), capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 1, f"unreachable 인데 exit {proc.returncode} (0 이면 조용한 통과)"
    assert "unreachable" in proc.stdout.lower() or "UNREACHABLE" in proc.stdout
