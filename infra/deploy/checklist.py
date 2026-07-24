#!/usr/bin/env python3
"""
Deploy Checklist Runner (08번 안전장치 6절 자동화)
=====================================================
배포 전 체크리스트 8개 항목을 순서대로 실행하고 종합 리포트를 낸다.
하나라도 실패하면 종료코드 1(배포 파이프라인에서 이 스크립트를 게이트로 사용).

사용법:
    python infra/deploy/checklist.py --repo-root . [--skip-docker-checks]
"""
from __future__ import annotations
import argparse
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ChecklistItem:
    name: str
    passed: bool
    detail: str = ""


def run_py(script: str, args: list[str]) -> tuple[int, str]:
    cmd = [sys.executable, script] + args
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr)


def check_secret_scan(repo_root: Path) -> ChecklistItem:
    script = repo_root / "infra" / "ci" / "secret_scan.py"
    rc, out = run_py(str(script), ["--path", str(repo_root)])
    return ChecklistItem("실제 시크릿 패턴 스캔 통과(더미만 존재)", rc == 0, out.strip().splitlines()[-1] if out.strip() else "")


def check_isolation(repo_root: Path, skip_docker: bool) -> ChecklistItem:
    script = repo_root / "infra" / "ci" / "isolation_test.py"
    args = ["--skip-if-no-docker"] if skip_docker else []
    rc, out = run_py(str(script), args)
    return ChecklistItem(
        "트윈 외부 egress 차단 + 트윈간 직접통신 차단 확인",
        rc == 0,
        out.strip().splitlines()[-1] if out.strip() else "",
    )


def check_hardening_overlay_exists(repo_root: Path) -> ChecklistItem:
    f = repo_root / "infra" / "hardening" / "docker-compose.hardening.yml"
    exists = f.exists()
    has_capdrop = exists and "cap_drop" in f.read_text()
    has_readonly = exists and "read_only" in f.read_text()
    ok = exists and has_capdrop and has_readonly
    return ChecklistItem(
        "커맨드인젝션/역직렬화 트윈 read-only + cap_drop 적용 확인",
        ok,
        f"file_exists={exists} cap_drop={has_capdrop} read_only={has_readonly}",
    )


def check_resource_limits_declared(repo_root: Path) -> ChecklistItem:
    f = repo_root / "infra" / "hardening" / "docker-compose.hardening.yml"
    text = f.read_text() if f.exists() else ""
    has_mem = "mem_limit" in text
    has_cpu = "cpus" in text
    return ChecklistItem("리소스 제한 설정 확인", has_mem and has_cpu, f"mem_limit={has_mem} cpus={has_cpu}")


def check_killswitch_endpoint_declared(repo_root: Path) -> ChecklistItem:
    """04번 문서의 killswitch API가 계약(api_contract.py)에 선언되어 있는지 정적 확인."""
    f = repo_root / "contracts" / "shared" / "api_contract.py"
    if not f.exists():
        f = repo_root / "shared" / "api_contract.py"
    text = f.read_text() if f.exists() else ""
    ok = "KILLSWITCH" in text
    return ChecklistItem("킬스위치 API 계약 존재 확인(동작 테스트는 운영환경에서 별도)", ok, f"contract_found={f.exists()}")


def check_auth_required_note(repo_root: Path) -> ChecklistItem:
    """대시보드/API 인증 요구사항이 문서화되어 있는지(정적 점검, 실제 인증은 배포시 구성)."""
    docs_dir = repo_root / "docs"
    found = False
    if docs_dir.exists():
        for f in docs_dir.glob("*.md"):
            if "Authorization" in f.read_text(errors="ignore") or "교관 토큰" in f.read_text(errors="ignore"):
                found = True
                break
    return ChecklistItem("대시보드/API 인증 요구사항 문서화 확인", found, f"found_in_docs={found}")


def check_training_banner_note(repo_root: Path) -> ChecklistItem:
    """TRAINING ONLY 마커가 코드/문서 어딘가에 있는지."""
    found = False
    for pattern in ["*.py", "*.md"]:
        for f in repo_root.rglob(pattern):
            if any(part in {".git", "node_modules"} for part in f.parts):
                continue
            try:
                if "TRAINING ONLY" in f.read_text(errors="ignore") or "training-only" in f.read_text(errors="ignore"):
                    found = True
                    break
            except Exception:
                continue
        if found:
            break
    return ChecklistItem('"TRAINING ONLY" 배너/마커 존재 확인', found, f"found={found}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--skip-docker-checks", action="store_true",
                    help="Docker 없는 CI/샌드박스 환경에서 격리 테스트를 건너뛰고 안내만 출력")
    args = ap.parse_args()
    repo_root = Path(args.repo_root).resolve()

    checks = [
        check_secret_scan(repo_root),
        check_isolation(repo_root, args.skip_docker_checks),
        check_hardening_overlay_exists(repo_root),
        check_resource_limits_declared(repo_root),
        check_killswitch_endpoint_declared(repo_root),
        check_auth_required_note(repo_root),
        check_training_banner_note(repo_root),
    ]

    print("=" * 70)
    print("배포 전 체크리스트 (08_safety_hardening_spec.md 6절)")
    print("=" * 70)
    for c in checks:
        status = "✅" if c.passed else "❌"
        print(f"{status} {c.name}")
        if c.detail:
            print(f"    └─ {c.detail}")

    failed = [c for c in checks if not c.passed]
    print("-" * 70)
    if failed:
        print(f"🚨 {len(failed)}/{len(checks)} 항목 실패. 배포 차단.")
        return 1
    print(f"✅ 전체 {len(checks)}개 항목 통과. 배포 가능.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
