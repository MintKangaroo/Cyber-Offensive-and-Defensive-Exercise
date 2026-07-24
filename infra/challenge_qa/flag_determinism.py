#!/usr/bin/env python3
"""
C-QA Step 7: Flag Determinism (25번 문서 1절)
=================================================
deploy_up -> intended_solve -> teardown -> deploy_up(재배포) -> intended_solve 재실행.
동적 플래그의 팀별 결과가 재배포 후에도 일관되는지 확인(같은 team_id는 같은 플래그).
"""
import argparse
import importlib.util
import subprocess
import sys
import time
from pathlib import Path

import requests


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _wait_health(base_url: str, timeout_sec: int = 30) -> None:
    """재배포 직후 uvicorn 준비 전에 exploit를 쏘면 connection reset이 나므로,
    deploy_up.py와 동일하게 /health가 200이 될 때까지 대기한다."""
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            if requests.get(f"{base_url}/health", timeout=2).ok:
                return
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)
    raise TimeoutError(f"flag_determinism: {timeout_sec}초 내 {base_url}/health 준비 안 됨")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge-dir", required=True)
    ap.add_argument("--base-url", default="http://localhost:8100")
    ap.add_argument("--team-id", default="qa_team")
    args = ap.parse_args()

    challenge_dir = Path(args.challenge_dir)
    deploy_dir = challenge_dir / "deploy"
    exploit_path = challenge_dir / "solution" / "exploit.py"

    def _redeploy():
        subprocess.run(["docker", "compose", "down", "-v"], cwd=deploy_dir)
        subprocess.run(["docker", "compose", "up", "-d", "--build"], cwd=deploy_dir)

    _redeploy()
    _wait_health(args.base_url)
    exploit_mod1 = _load_module(exploit_path, "exploit_run1")
    flag1 = exploit_mod1.solve(args.base_url, args.team_id)

    _redeploy()
    _wait_health(args.base_url)
    exploit_mod2 = _load_module(exploit_path, "exploit_run2")
    flag2 = exploit_mod2.solve(args.base_url, args.team_id)

    if flag1 != flag2:
        print(f"❌ flag_determinism: 재배포 후 같은 team_id의 플래그가 달라짐 "
             f"(run1={flag1}, run2={flag2}) - CHALLENGE_SECRET이 배포마다 랜덤 생성되고 있는지 확인")
        return 1

    print(f"✅ flag_determinism: 재배포 후에도 팀별 플래그 일관성 확인 ({flag1})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
