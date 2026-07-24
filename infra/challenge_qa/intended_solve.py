#!/usr/bin/env python3
"""
C-QA Step 3: Intended Solve (25번 문서 1절)
==============================================
solution/exploit.py를 실행해 red_grader가 PASS 하는지 확인.
"""
import argparse
import importlib.util
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
    args = ap.parse_args()

    challenge_dir = Path(args.challenge_dir)
    exploit_path = challenge_dir / "solution" / "exploit.py"
    grader_path = challenge_dir / "grader" / "red_grader.py"

    if not exploit_path.exists() or not grader_path.exists():
        print(f"❌ intended_solve: exploit.py 또는 red_grader.py 없음")
        return 1

    exploit_mod = _load_module(exploit_path, "exploit_under_test")
    grader_mod = _load_module(grader_path, "red_grader_under_test")

    try:
        flag = exploit_mod.solve(args.base_url, args.team_id)
    except Exception as e:
        print(f"❌ intended_solve: exploit 실행 실패 - {e}")
        return 1

    result = grader_mod.grade_red({"team_id": args.team_id, "flag": flag}, {})
    if not result.passed:
        print(f"❌ intended_solve: 의도된 해법이 채점 통과하지 못함 - {result.detail}")
        return 1

    print(f"✅ intended_solve: 통과 (points={result.points}, detail={result.detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
