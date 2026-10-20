"""회귀: 소크 부하(soak_load.py)와 종료 R-1 게이트(run_soak.sh)가 같은 scenario_id 를 쓴다.

과거 결함: 부하는 scenario_id='soak-exercise' 로 이벤트를 발행했는데 게이트는 'soak' 로
reconcile/AAR 를 조회 → 빈 시나리오라 reconcile checked=false·AAR PDF HTTPError →
R-1 게이트가 거짓 FAIL(실제 event_collector 는 무거운 replay 후에도 health 200).
부하와 게이트의 scenario_id 기본값이 어긋나거나 run_soak.sh 가 단일 소스로 export 하지
않으면 이 테스트가 깨진다.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUN_SOAK = ROOT / "loadtest" / "soak" / "run_soak.sh"
SOAK_LOAD = ROOT / "loadtest" / "soak" / "soak_load.py"


def _load_default() -> str:
    """soak_load.py 의 SCENARIO_ID = os.environ.get("SOAK_SCENARIO_ID", "<기본>") 기본값."""
    txt = SOAK_LOAD.read_text(encoding="utf-8")
    m = re.search(r'os\.environ\.get\(\s*"SOAK_SCENARIO_ID"\s*,\s*"([^"]+)"\s*\)', txt)
    assert m, "soak_load.py 에서 SOAK_SCENARIO_ID 기본값을 찾지 못함"
    return m.group(1)


def _gate_defaults() -> list[str]:
    """run_soak.sh 의 게이트가 쓰는 SOAK_SCENARIO_ID 기본값(쉘 `:-` + 파이썬 fallback) 전부."""
    txt = RUN_SOAK.read_text(encoding="utf-8")
    shell = re.findall(r'\$\{SOAK_SCENARIO_ID:-([^}]+)\}', txt)
    py = re.findall(r'os\.environ\.get\(\s*"SOAK_SCENARIO_ID"\s*,\s*"([^"]+)"\s*\)', txt)
    return shell + py


def test_load_and_gate_scenario_id_defaults_match():
    load_default = _load_default()
    gate_defaults = _gate_defaults()
    assert gate_defaults, "run_soak.sh 에서 SOAK_SCENARIO_ID 기본값을 찾지 못함"
    # 모든 게이트 기본값이 부하 기본값과 동일해야 한다(어긋나면 빈 시나리오 조회 → 거짓 FAIL).
    for d in gate_defaults:
        assert d == load_default, f"게이트 기본값 {d!r} 이 부하 기본값 {load_default!r} 과 다름"


def test_run_soak_exports_scenario_id_as_single_source():
    """run_soak.sh 가 부하 실행 전에 SOAK_SCENARIO_ID 를 export → 부하·게이트가 같은 값 상속."""
    txt = RUN_SOAK.read_text(encoding="utf-8")
    assert re.search(r'^export SOAK_SCENARIO_ID=', txt, re.MULTILINE), \
        "run_soak.sh 가 SOAK_SCENARIO_ID 를 export 하지 않음(단일 소스 부재 → 분기 위험)"
    export_pos = txt.index("export SOAK_SCENARIO_ID=")
    m = re.search(r'python3\s+"?\$?\{?HERE\}?[^"\n]*soak_load\.py', txt)
    assert m, "run_soak.sh 에서 soak_load.py 실행부를 찾지 못함"
    assert export_pos < m.start(), "export 가 soak_load.py 실행보다 뒤 → 부하가 상속 못 함"


def test_soak_load_module_honors_env_scenario_id():
    """런타임 확인: 환경변수 설정 시 soak_load.SCENARIO_ID 가 그 값을 따른다."""
    import importlib
    import sys

    prev = os.environ.get("SOAK_SCENARIO_ID")
    os.environ["SOAK_SCENARIO_ID"] = "soak-regtest-xyz"
    try:
        sys.modules.pop("soak_load", None)
        spec = importlib.util.spec_from_file_location("soak_load", SOAK_LOAD)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.SCENARIO_ID == "soak-regtest-xyz"
    finally:
        sys.modules.pop("soak_load", None)
        if prev is None:
            os.environ.pop("SOAK_SCENARIO_ID", None)
        else:
            os.environ["SOAK_SCENARIO_ID"] = prev
