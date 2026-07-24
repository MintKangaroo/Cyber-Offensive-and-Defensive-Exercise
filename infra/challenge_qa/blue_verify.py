#!/usr/bin/env python3
"""
C-QA Step 5: Blue Verify (25번 문서 1절)
============================================
solution/defense.md의 절차(주로 환경변수 패치 토글)를 적용 -> blue_grader PASS 확인
-> intended_solve를 재실행해 이번엔 red_grader가 FAIL해야 함(방어가 실제로 공격을 막는지).

이 스크립트는 표준 절차상 "패치 환경변수 이름"을 challenge.yaml에서 유추하기 어려우므로
--patch-env 인자로 명시적으로 받는다(예: PATCH_WEB_002=true).
"""
import argparse
import importlib.util
import os
import subprocess
import sys
from pathlib import Path


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge-dir", required=True)
    ap.add_argument("--base-url", default="http://localhost:8100")
    ap.add_argument("--team-id", default="qa_team")
    ap.add_argument("--patch-env", required=True, help="예: PATCH_WEB_002=true")
    args = ap.parse_args()

    challenge_dir = Path(args.challenge_dir)
    deploy_dir = challenge_dir / "deploy"

    # 1) 패치 환경변수를 반영해 재기동
    key, _, value = args.patch_env.partition("=")
    env = os.environ.copy()
    env[key] = value
    rc = subprocess.run(["docker", "compose", "up", "-d", "--build"], cwd=deploy_dir, env=env).returncode
    if rc != 0:
        print("❌ blue_verify: 패치 적용 재기동 실패")
        return 1

    # 2) blue_grader 확인
    blue_grader_path = challenge_dir / "grader" / "blue_grader.py"
    blue_mod = _load_module(blue_grader_path, "blue_grader_under_test")
    blue_result = blue_mod.grade_blue({"base_url": args.base_url, "team_id": args.team_id})
    if not blue_result.passed:
        print(f"❌ blue_verify: 패치 후에도 blue_grader 미통과 - {blue_result.detail}")
        return 1
    print(f"  blue_grader 통과: {blue_result.detail}")

    # 3) 패치 후 Red 재시도가 막히는지(red_grader가 FAIL해야 함)
    exploit_path = challenge_dir / "solution" / "exploit.py"
    red_grader_path = challenge_dir / "grader" / "red_grader.py"
    exploit_mod = _load_module(exploit_path, "exploit_post_patch")
    red_mod = _load_module(red_grader_path, "red_grader_post_patch")

    try:
        flag = exploit_mod.solve(args.base_url, args.team_id)
        red_result = red_mod.grade_red({"team_id": args.team_id, "flag": flag}, {})
        if red_result.passed:
            print("❌ blue_verify: 패치 후에도 기존 익스플로잇이 여전히 통함(방어 실패)")
            return 1
    except Exception:
        pass  # 익스플로잇 자체가 실패하는 것도 정상(방어 성공의 증거)

    print("✅ blue_verify: 패치 후 blue_grader 통과 + 기존 공격 차단 확인")
    return 0


if __name__ == "__main__":
    sys.exit(main())
