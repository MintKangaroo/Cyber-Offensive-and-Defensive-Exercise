#!/usr/bin/env python3
"""
C-QA: Artifact Intended-Solve (P2b — exploit 계약 통일)
========================================================
아티팩트형 챌린지(배포 서비스 없이 파일 산출물만; DET 제외 NET/FOR/REV)의 의도된 해법을
실제로 실행해 red_grader가 PASS 하는지 검증한다.

배경: HTTP형 exploit은 `solve(base_url, team_id) -> flag(str)` 규약이지만, 아티팩트형은
규약이 제각각이었다 — `solve(path) -> dict`(NET-000/FOR-000/FOR-002), `solve(path) -> str`
(REV-000), `solve(team_id) -> str`(REV-001) 등. 그래서 HTTP 전용인 intended_solve.py가
아티팩트형을 검증하지 못했다(P2에서 남긴 갭).

여기서 **하버스 계약 계층에서 통일**한다:
  1) 생성기(deploy/generate_artifact.py 등)를 실행해 아티팩트를 deploy/ 아래 만든다.
  2) exploit.solve를 시그니처로 분기 호출(경로형 vs team_id형).
  3) 반환값을 submission dict로 정규화(dict → 그대로, str → {"flag": str}).
  4) grade_red({"team_id", **submission}, {"challenge_dir": ...}) 로 채점 → PASS 확인.
  5) 빈 제출({team_id}만)이 FAIL 하는지도 함께 확인(blank 보증).
생성기가 만든 아티팩트 중 사전에 없던 파일은 끝나고 정리한다(리포 오염 방지).

사용: python artifact_solve.py --challenge-dir challenges/network/NET-000
"""
from __future__ import annotations
import argparse
import importlib.util
import inspect
import os
import subprocess
import sys
from pathlib import Path

import yaml


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _artifact_names(challenge_dir: Path) -> list[str]:
    data = yaml.safe_load((challenge_dir / "challenge.yaml").read_text())
    arts = (data.get("challenge", {}) or {}).get("artifacts", []) or []
    # 파일처럼 보이는 항목만(확장자 有). "standard" 같은 비파일 토큰 배제.
    return [a for a in arts if isinstance(a, str) and "." in a]


def _find_generator(deploy_dir: Path) -> Path | None:
    for name in ("generate_artifact.py", "generate_datasets.py"):
        if (deploy_dir / name).exists():
            return deploy_dir / name
    return None


def _normalize_submission(result) -> dict:
    """exploit.solve 반환을 grade_red가 받는 submission dict로 정규화.
    dict면 그대로(각 grader가 기대하는 필드 집합), str이면 {"flag": ...}."""
    if isinstance(result, dict):
        return result
    return {"flag": result}


def _call_solve(solve, *, base_url: str, team_id: str, artifact_path: Path | None):
    """solve 시그니처에 따라 알맞은 인자로 호출(계약 통일 지점)."""
    params = list(inspect.signature(solve).parameters)
    if len(params) >= 2:
        return solve(base_url, team_id)                 # HTTP형(예외적 경로)
    if len(params) == 1:
        if "team" in params[0].lower():
            return solve(team_id)                        # team_id형(REV-001)
        if artifact_path is None:
            raise RuntimeError("경로형 solve인데 생성된 아티팩트를 찾지 못함")
        return solve(str(artifact_path))                 # 경로형(대다수)
    return solve()                                       # 무인자(드묾)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge-dir", required=True)
    ap.add_argument("--team-id", default="qa_team")
    ap.add_argument("--base-url", default="http://localhost:8100")
    args = ap.parse_args()

    # 그레이더/생성기/익스플로잇은 CHALLENGE_SECRET 을 모듈 로드 시 요구(기본값 제거됨).
    # QA 하버스는 결정적 더미 secret 을 주입(외부에서 이미 설정했으면 존중).
    os.environ.setdefault("CHALLENGE_SECRET", "qa-challenge-secret")

    challenge_dir = Path(args.challenge_dir)
    deploy_dir = challenge_dir / "deploy"
    exploit_path = challenge_dir / "solution" / "exploit.py"
    grader_path = challenge_dir / "grader" / "red_grader.py"
    if not exploit_path.exists() or not grader_path.exists():
        print("❌ artifact_solve: exploit.py 또는 red_grader.py 없음")
        return 1

    # 1) 아티팩트 생성(사전 존재 파일은 보존, 새로 만든 것만 나중에 정리)
    art_names = _artifact_names(challenge_dir)
    pre_existing = {n for n in art_names if (deploy_dir / n).exists()}
    generator = _find_generator(deploy_dir)
    if generator is not None:
        # 생성기는 cwd=deploy_dir에서 실행(상대 출력 파일명이 여기 떨어짐)하되 경로는 절대경로로.
        rc = subprocess.run([sys.executable, str(generator.resolve()), args.team_id],
                            cwd=str(deploy_dir)).returncode
        if rc != 0:
            print(f"❌ artifact_solve: 생성기 실패 ({generator.name})")
            return 1

    artifact_path = None
    for n in art_names:
        cand = deploy_dir / n
        if cand.exists():
            artifact_path = cand
            break

    created = [deploy_dir / n for n in art_names if n not in pre_existing and (deploy_dir / n).exists()]
    try:
        exploit_mod = _load_module(exploit_path, "artifact_exploit")
        grader_mod = _load_module(grader_path, "artifact_grader")

        # 2~3) solve 호출 + submission 정규화
        try:
            result = _call_solve(exploit_mod.solve, base_url=args.base_url,
                                  team_id=args.team_id, artifact_path=artifact_path)
        except Exception as e:
            print(f"❌ artifact_solve: exploit 실행 실패 - {e}")
            return 1
        submission = {"team_id": args.team_id, **_normalize_submission(result)}
        ctx = {"challenge_dir": str(challenge_dir)}

        # 4) 정답 제출 PASS 확인
        good = grader_mod.grade_red(submission, ctx)
        if not good.passed:
            print(f"❌ artifact_solve: 의도된 해법이 채점 통과 못함 - {good.detail}")
            return 1

        # 5) 빈 제출 FAIL 확인(아무것도 안 해도 통과되는 결함 차단)
        blank = grader_mod.grade_red({"team_id": args.team_id}, ctx)
        if blank.passed:
            print("❌ artifact_solve: 빈 제출이 통과됨(결함 챌린지)")
            return 1

        print(f"✅ artifact_solve: 통과 (points={good.points}, detail={good.detail}) / 빈제출 정상 거부")
        return 0
    finally:
        for f in created:
            try:
                f.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
