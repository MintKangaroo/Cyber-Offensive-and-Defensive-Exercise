#!/usr/bin/env python3
"""
C-QA: Detection Intended-Solve (탐지형 DET 통합)
==================================================
탐지형 챌린지(DET)는 "익스플로잇"이 아니라 **탐지 규칙(answer_rule.yaml)**을 제출하고, 우리
진짜 SIEM DetectionEngine이 그 규칙을 합성 데이터셋에 태워 채점한다(25번 문서). 인터페이스가
red/artifact형과 달라(`grade_blue(context)`, submission=규칙 파일) 별도 게이트로 검증한다.

절차:
  1) deploy/generate_datasets.py 실행 → 공격/정상 로그 생성(grader가 파일명을 안다).
  2) 정답 규칙(solution/answer_rule.yaml)으로 grade_blue → PASS(공격 탐지 + 정상 오탐 없음) 확인.
  3) 아무것도 안 잡는 no-op 규칙으로 grade_blue → **FAIL** 확인(채점기가 실제로 판별함을 보증).
  4) 생성한 데이터셋 중 사전에 없던 파일은 정리.

사용: python detection_solve.py --challenge-dir challenges/detection/DET-000
"""
from __future__ import annotations
import argparse
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


NOOP_RULE = (
    "id: QA-NOOP\n"
    "title: never matches\n"
    "severity: 1\n"
    "kind: match\n"
    "match:\n"
    "  __qa_nonexistent_field__: __qa_never_value__\n"
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge-dir", required=True)
    args = ap.parse_args()

    # 그레이더/생성기는 CHALLENGE_SECRET 을 모듈 로드 시 요구(기본값 제거됨). QA 더미 주입.
    os.environ.setdefault("CHALLENGE_SECRET", "qa-challenge-secret")

    challenge_dir = Path(args.challenge_dir)
    deploy_dir = challenge_dir / "deploy"
    grader_path = challenge_dir / "grader" / "blue_grader.py"
    generator = deploy_dir / "generate_datasets.py"
    if not grader_path.exists() or not generator.exists():
        print("❌ detection_solve: blue_grader.py 또는 generate_datasets.py 없음")
        return 1

    # 1) 데이터셋 생성(사전 존재 .jsonl은 보존, 새로 만든 것만 정리)
    pre_existing = {p.name for p in deploy_dir.glob("*.jsonl")}
    rc = subprocess.run([sys.executable, str(generator.resolve())], cwd=str(deploy_dir)).returncode
    if rc != 0:
        print("❌ detection_solve: 데이터셋 생성기 실패")
        return 1
    created = [p for p in deploy_dir.glob("*.jsonl") if p.name not in pre_existing]

    try:
        grader = _load_module(grader_path, "detection_grader")
        ctx = {"challenge_dir": str(challenge_dir)}

        # 2) 정답 규칙 PASS
        good = grader.grade_blue(ctx)
        if not good.passed:
            print(f"❌ detection_solve: 정답 규칙이 채점 통과 못함 - {good.detail}")
            return 1

        # 3) no-op 규칙 FAIL(채점기 판별력 보증)
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(NOOP_RULE)
            noop_path = tf.name
        try:
            bad = grader.grade_blue({**ctx, "submitted_rule_path": noop_path})
        finally:
            Path(noop_path).unlink(missing_ok=True)
        if bad.passed:
            print("❌ detection_solve: 아무것도 안 잡는 규칙이 통과됨(채점기 결함)")
            return 1

        print(f"✅ detection_solve: 통과 (points={good.points}, detail={good.detail}) / no-op 규칙 정상 거부")
        return 0
    finally:
        for f in created:
            try:
                f.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
