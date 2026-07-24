#!/usr/bin/env python3
"""
C-QA run_all (25번 문서 1절)
================================
schema_validate -> deploy_up -> intended_solve -> blank_submit -> blue_verify ->
safety_scan -> flag_determinism -> teardown 순서로 전부 실행. 하나라도 실패하면 중단.
통과 시 challenges/<id>/QA_PASSED 마커 생성.
"""
import argparse
import subprocess
import sys
from pathlib import Path


def _find_challenge_dir(challenge_id: str, challenges_root: Path) -> Path:
    import yaml
    for path in challenges_root.rglob("challenge.yaml"):
        with open(path) as f:
            data = yaml.safe_load(f)
        if data.get("challenge", {}).get("id") == challenge_id:
            return path.parent
    raise FileNotFoundError(f"challenge '{challenge_id}' not found")


def _derive_base_url(challenge_dir: Path) -> str | None:
    """챌린지 deploy/docker-compose.yaml의 published 호스트 포트에서 base URL을 유도.

    챌린지마다 배포 포트가 다르다(WEB-000=8101, AI-000=8102, WEB-003=8100 ...).
    과거엔 run_all이 8100 고정이라 8100을 쓰는 챌린지만 우연히 docker QA를 통과하고
    나머지는 health check가 엉뚱한 포트를 찔러 실패했다. 여기서 compose를 읽어 실제
    포트를 뽑아 모든 서비스형 챌린지가 자동으로 검증되게 한다.

    반환: "http://localhost:<port>" 또는 (compose/포트 없으면) None.
    ports 항목 포맷: "8101:8101", "127.0.0.1:8101:8101", 8101:8101(int) 모두 흡수.
    """
    import yaml
    compose = challenge_dir / "deploy" / "docker-compose.yaml"
    if not compose.exists():
        return None
    try:
        data = yaml.safe_load(compose.read_text())
    except yaml.YAMLError:
        return None
    for svc in (data.get("services") or {}).values():
        for entry in (svc.get("ports") or []):
            token = str(entry).split("/")[0]          # "8101:8101/tcp" -> "8101:8101"
            parts = token.split(":")
            host_port = parts[-2] if len(parts) >= 2 else parts[0]
            if host_port.isdigit():
                return f"http://localhost:{host_port}"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--challenge", required=True)
    ap.add_argument("--challenges-root", default="challenges")
    ap.add_argument("--base-url", default="http://localhost:8100")
    ap.add_argument("--patch-env", default=None, help="예: PATCH_WEB_002=true (blue_verify용)")
    ap.add_argument("--skip-docker", action="store_true", help="Docker 없는 환경에서 스키마/시크릿 검사만")
    args = ap.parse_args()

    here = Path(__file__).parent
    challenge_dir = _find_challenge_dir(args.challenge, Path(args.challenges_root))

    # 사용자가 --base-url을 명시하지 않았으면 챌린지 compose 포트에서 자동 유도.
    # (명시했으면 그대로 존중 — 원격/특수 배포 대응.)
    DEFAULT_BASE_URL = "http://localhost:8100"
    derived = _derive_base_url(challenge_dir)
    base_url_overridden = args.base_url != DEFAULT_BASE_URL
    if not base_url_overridden and derived:
        args.base_url = derived

    print("=" * 70)
    print(f"C-QA 검수: {args.challenge}")
    print(f"base_url: {args.base_url}")
    print("=" * 70)

    steps: list[tuple[str, list[str]]] = [
        ("schema_validate", [sys.executable, str(here / "schema_validate.py"),
                             "--challenge", args.challenge, "--challenges-root", args.challenges_root]),
        ("safety_scan", [sys.executable, str(here / "safety_scan.py"), "--challenge-dir", str(challenge_dir)]),
    ]

    # HTTP 배포 서비스가 있는 챌린지만 docker 배포 게이트(deploy_up/intended_solve/flag_determinism)를
    # 적용한다. "배포 서비스 있음"의 판정 = compose에 published 호스트 포트가 있어 base URL을 유도할 수
    # 있는가(=derived). 아티팩트형(DET/FOR/NET/REV; compose 없음)과 무포트형(AI-001; compose는 있으나
    # 포트 미노출, 오프라인 산출물)은 모두 여기서 제외되어 스키마/안전성 검사만 받는다.
    # 과거엔 docker 모드에서 8100 고정이라 8100 챌린지만 우연히 통과하고 나머지는 엉뚱한 포트/compose
    # 없음으로 혼란스럽게 실패했다.
    # 아티팩트형 solve/grader 검증은 P2b에서 하버스 계약을 통일해 artifact_solve.py로 통합됐다
    # (생성 → 시그니처 분기 solve → submission 정규화 → grade_red). DET처럼 exploit.solve가 없는
    # 탐지형은 answer_rule.yaml을 SIEM 엔진으로 채점하는 별도 모델이라 여기서는 스키마/안전성만 받는다.
    is_deployable_service = base_url_overridden or (derived is not None)
    run_docker_gates = (not args.skip_docker) and is_deployable_service
    exploit_py = challenge_dir / "solution" / "exploit.py"
    blue_grader = challenge_dir / "grader" / "blue_grader.py"
    dataset_gen = challenge_dir / "deploy" / "generate_datasets.py"
    non_service_verify = (not args.skip_docker) and (not is_deployable_service)
    has_artifact_solve = (
        non_service_verify and exploit_py.exists() and "def solve" in exploit_py.read_text()
    )
    # 탐지형(DET): exploit.solve가 없고 blue_grader + 데이터셋 생성기가 있으면 SIEM 엔진 채점 게이트.
    has_detection_solve = (
        non_service_verify and (not has_artifact_solve)
        and blue_grader.exists() and dataset_gen.exists()
    )
    if non_service_verify:
        if has_artifact_solve:
            print("ℹ️  아티팩트형 챌린지 감지 → docker 배포 게이트 대신 artifact_solve(생성→solve→채점) 수행.")
        elif has_detection_solve:
            print("ℹ️  탐지형 챌린지 감지 → detection_solve(데이터셋 생성→SIEM 엔진 규칙 채점) 수행.")
        else:
            print("ℹ️  배포 서비스/solve/규칙 채점기 없는 챌린지 감지 → 스키마/안전성 검사만 수행.")

    if has_artifact_solve:
        steps.append(("artifact_solve", [sys.executable, str(here / "artifact_solve.py"),
                                         "--challenge-dir", str(challenge_dir)]))
    if has_detection_solve:
        steps.append(("detection_solve", [sys.executable, str(here / "detection_solve.py"),
                                          "--challenge-dir", str(challenge_dir)]))

    if run_docker_gates:
        steps += [
            ("deploy_up", [sys.executable, str(here / "deploy_up.py"), "--challenge-dir", str(challenge_dir),
                          "--health-url", f"{args.base_url}/health"]),
            ("intended_solve", [sys.executable, str(here / "intended_solve.py"),
                                "--challenge-dir", str(challenge_dir), "--base-url", args.base_url]),
            ("blank_submit", [sys.executable, str(here / "blank_submit.py"), "--challenge-dir", str(challenge_dir)]),
        ]
        if args.patch_env:
            steps.append(("blue_verify", [sys.executable, str(here / "blue_verify.py"),
                                         "--challenge-dir", str(challenge_dir), "--base-url", args.base_url,
                                         "--patch-env", args.patch_env]))
        steps += [
            ("flag_determinism", [sys.executable, str(here / "flag_determinism.py"),
                                  "--challenge-dir", str(challenge_dir), "--base-url", args.base_url]),
            ("teardown", [sys.executable, str(here / "teardown.py"), "--challenge-dir", str(challenge_dir)]),
        ]
    elif args.skip_docker:
        print("⚠️  --skip-docker: 스키마/시크릿 검사만 수행(배포 기반 검증은 실제 Docker 환경에서 실행할 것)")

    for name, cmd in steps:
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"\n🚨 {name} 실패. C-QA 중단.")
            return 1

    marker = challenge_dir / "QA_PASSED"
    marker.write_text("all C-QA steps passed\n")
    print(f"\n✅ 전체 C-QA 통과. 마커 생성: {marker}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
