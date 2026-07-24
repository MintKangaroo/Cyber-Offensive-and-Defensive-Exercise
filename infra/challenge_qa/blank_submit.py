#!/usr/bin/env python3
"""
C-QA Step 4: Blank Submit (25번 문서 1절)
============================================
아무것도 안 하고 빈 flag를 제출해도 red_grader가 FAIL 해야 통과.
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
    ap.add_argument("--team-id", default="qa_team")
    args = ap.parse_args()

    grader_path = Path(args.challenge_dir) / "grader" / "red_grader.py"
    grader_mod = _load_module(grader_path, "red_grader_blank_test")

    result = grader_mod.grade_red({"team_id": args.team_id, "flag": ""}, {})
    if result.passed:
        print("❌ blank_submit: 빈 제출인데 채점이 통과됨(결함 문제 — 아무것도 안 해도 점수 획득 가능)")
        return 1

    print(f"✅ blank_submit: 빈 제출 정상적으로 미통과 처리 확인 (detail={result.detail})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
