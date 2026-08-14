"""One-command beginner Blue Team defense.

New trainees should be able to *defend* a service without first learning Docker
build/push, the patch registry namespace, or the runtime worker. This script
drives the exact same production patch pipeline an advanced user would run by
hand, but as a single automated, narrated flow:

    build patched image  ->  push to the match registry  ->  submit patch
      ->  drive the runtime worker (sandbox validate -> deploy)
      ->  poll until deployed  ->  verify the vulnerability is actually blocked

Advanced users keep the manual workflow (docker build/push + Patches UI +
`make attack-defense-runtime-work`); this only adds a guided shortcut.

Usage:
    python3 -m scripts.beginner_defense                 # patch Team 01 Notes
    python3 -m scripts.beginner_defense --service both   # Notes + Vault
    python3 -m scripts.beginner_defense --service vault
    python3 -m scripts.beginner_defense --dry-run        # show the plan only
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]

AD_API = os.environ.get("ATTACK_DEFENSE_API_URL", "http://localhost:8100").rstrip("/")
AUTH_API = os.environ.get("AUTH_API_URL", "http://localhost:8051").rstrip("/")
MATCH_ID = os.environ.get("ATTACK_DEFENSE_DEMO_MATCH_ID", "ad-demo")
# Reference registry the game engine trusts (resolved inside the AD network);
# the host pushes to the same registry published on localhost.
ALLOWED_REGISTRY = os.environ.get("PATCH_ALLOWED_REGISTRY", "registry.local:5000")
PUSH_REGISTRY = os.environ.get("PATCH_PUSH_REGISTRY", "localhost:5000")

TERMINAL_STATUSES = {"deployed", "rejected", "failed"}


@dataclass(frozen=True)
class ServiceSpec:
    key: str
    service_id: str
    slug: str
    base_image: str
    dockerfile: str
    patch_build_arg: str          # env flag that switches the fix on
    public_port_by_team: dict[str, int]
    vuln: str                     # human label for the vulnerability


NOTES = ServiceSpec(
    key="notes",
    service_id="service-vulnerable-notes",
    slug="vulnerable-notes",
    base_image="cyber-range/ad-vulnerable-notes:base",
    dockerfile="services/attack_defense/demo_services/vulnerable_notes/Dockerfile",
    patch_build_arg="PATCH_IDOR",
    public_port_by_team={"team-01": 9101, "team-02": 9102, "team-03": 9103},
    vuln="IDOR (남의 노트를 번호만 바꿔 조회)",
)
VAULT = ServiceSpec(
    key="vault",
    service_id="service-file-vault",
    slug="file-vault",
    base_image="cyber-range/ad-file-vault:base",
    dockerfile="services/attack_defense/demo_services/file_vault/Dockerfile",
    patch_build_arg="PATCH_TRAVERSAL",
    public_port_by_team={"team-01": 9201, "team-02": 9202, "team-03": 9203},
    vuln="Path Traversal (상위 경로로 시스템 파일 열람)",
)
SPECS = {NOTES.key: NOTES, VAULT.key: VAULT}

# team-id -> (login username, default demo password)
TEAM_LOGINS = {
    "team-01": ("team01", "demo-team-01-change-me"),
    "team-02": ("team02", "demo-team-02-change-me"),
    "team-03": ("team03", "demo-team-03-change-me"),
}


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested in tests/scripts/test_beginner_defense.py)
# --------------------------------------------------------------------------- #
def patch_reference(registry: str, team_slug: str, service_slug: str, tag: str) -> str:
    """Immutable, team-namespaced image reference the game engine accepts."""
    return f"{registry}/{team_slug}/{service_slug}:{tag}"


def is_terminal(status: str) -> bool:
    return status in TERMINAL_STATUSES


def build_command(
    spec: ServiceSpec, image_tag: str, base_digest: str,
) -> list[str]:
    return [
        "docker", "build",
        "-f", spec.dockerfile,
        "--build-arg", f"{spec.patch_build_arg}=true",
        "--build-arg", f"CYBER_RANGE_BASE_DIGEST={base_digest}",
        "-t", image_tag,
        ".",
    ]


# --------------------------------------------------------------------------- #
# Narration
# --------------------------------------------------------------------------- #
def step(msg: str) -> None:
    print(f"\n\033[1;36m▶ {msg}\033[0m", flush=True)


def ok(msg: str) -> None:
    print(f"  \033[1;32m✓\033[0m {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"  \033[1;33m!\033[0m {msg}", flush=True)


def fail(msg: str) -> None:
    print(f"  \033[1;31m✗\033[0m {msg}", flush=True)


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, text=True, **kwargs)


# --------------------------------------------------------------------------- #
# Pipeline stages
# --------------------------------------------------------------------------- #
def preflight() -> None:
    step("환경 점검 (Preflight)")
    try:
        r = requests.get(f"{AD_API}/ready", timeout=3)
        if r.status_code != 200:
            raise RuntimeError(f"Attack/Defense API not ready (HTTP {r.status_code})")
        ok(f"Attack/Defense API 연결됨 · {AD_API}")
    except requests.RequestException as exc:
        raise SystemExit(
            f"Attack/Defense API에 연결할 수 없습니다 ({AD_API}). 먼저 'make training-up'을 실행하세요.\n  ({exc})"
        )
    if run(["docker", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        raise SystemExit("docker 명령을 사용할 수 없습니다. Docker Desktop/데몬이 실행 중인지 확인하세요.")
    ok("docker 사용 가능")


def local_image_digest(image: str) -> str:
    result = run(
        ["docker", "image", "inspect", "--format={{.Id}}", image],
        capture_output=True,
    )
    digest = result.stdout.strip()
    if not (digest.startswith("sha256:") and len(digest) == 71):
        raise SystemExit(
            f"기준 이미지 '{image}'를 찾을 수 없습니다. 'make training-up'으로 A/D 이미지를 먼저 빌드하세요."
        )
    return digest


def competitor_token(team_id: str) -> str:
    username, default_password = TEAM_LOGINS[team_id]
    password = os.environ.get(f"{username.upper()}_PASSWORD", default_password)
    r = requests.post(
        f"{AUTH_API}/auth/login",
        json={"username": username, "password": password}, timeout=10,
    )
    if r.status_code != 200:
        raise SystemExit(
            f"{username} 로그인 실패 (HTTP {r.status_code}). 비밀번호가 바뀌었다면 {username.upper()}_PASSWORD 환경변수로 지정하세요."
        )
    return r.json()["access_token"]


def build_and_push(spec: ServiceSpec, team_slug: str, tag: str) -> str:
    base_digest = local_image_digest(spec.base_image)
    push_tag = patch_reference(PUSH_REGISTRY, team_slug, spec.slug, tag)
    step(f"패치 이미지 빌드 ({spec.slug})")
    print(f"  {spec.vuln} 취약점을 {spec.patch_build_arg}=true 로 차단한 이미지를 만듭니다.")
    if run(build_command(spec, push_tag, base_digest)).returncode != 0:
        raise SystemExit("이미지 빌드에 실패했습니다.")
    ok(f"빌드 완료 · {push_tag}")
    step("레지스트리에 업로드 (Push)")
    if run(["docker", "push", push_tag]).returncode != 0:
        raise SystemExit(
            "이미지 push에 실패했습니다. 로컬 레지스트리(localhost:5000)가 실행 중인지 확인하세요."
        )
    ok("업로드 완료")
    # The engine trusts references under registry.local:5000 (same registry).
    return patch_reference(ALLOWED_REGISTRY, team_slug, spec.slug, tag)


def submit_patch(spec: ServiceSpec, token: str, reference: str) -> str:
    step("패치 제출 (Submit)")
    r = requests.post(
        f"{AD_API}/api/attack-defense/matches/{MATCH_ID}/services/{spec.service_id}/patches",
        headers={"Authorization": f"Bearer {token}"},
        json={"image_reference": reference}, timeout=30,
    )
    if r.status_code >= 400:
        raise SystemExit(f"패치 제출 실패 (HTTP {r.status_code}): {r.text}")
    patch_id = r.json()["id"]
    ok(f"제출 접수 · patch_id={patch_id}")
    return patch_id


def patch_status(spec: ServiceSpec, token: str, patch_id: str) -> dict:
    r = requests.get(
        f"{AD_API}/api/attack-defense/matches/{MATCH_ID}/patches/{patch_id}",
        headers={"Authorization": f"Bearer {token}"}, timeout=15,
    )
    r.raise_for_status()
    return r.json()


def drive_runtime_worker() -> bool:
    """Run one runtime-work claim. Returns True if a job was processed."""
    result = run(
        [sys.executable, "-m", "services.attack_defense.cli", "ad", "runtime-work"],
        capture_output=True,
    )
    if result.returncode != 0:
        warn(f"runtime worker 오류: {result.stderr.strip()[:200]}")
        return False
    try:
        payload = json.loads(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return False
    if payload.get("reason") == "no_pending_job":
        return False
    return True


def deploy_patch(spec: ServiceSpec, token: str, patch_id: str, max_iterations: int) -> str:
    step("패치 배포 및 검증 파이프라인 (자동)")
    print("  runtime worker가 sandbox 검증 → 배포 → 재검증을 순서대로 처리합니다.")
    last_status = "uploaded"
    for _ in range(max_iterations):
        current = patch_status(spec, token, patch_id)
        last_status = current.get("status", last_status)
        print(f"    · patch status: {last_status}")
        if is_terminal(last_status):
            break
        worked = drive_runtime_worker()
        if not worked:
            # No job ready yet; the background inspection may still be queuing.
            time.sleep(2)
    else:
        warn("최대 반복 횟수에 도달했습니다.")
    if last_status == "deployed":
        ok("패치 배포 완료 · 서비스가 새 이미지로 교체되고 checker 검증을 통과했습니다.")
    elif last_status in TERMINAL_STATUSES:
        fail(f"패치가 배포되지 못했습니다 (status={last_status}).")
    return last_status


# --------------------------------------------------------------------------- #
# Verification (attack your own now-patched service)
# --------------------------------------------------------------------------- #
def _svc_base(spec: ServiceSpec, team_id: str) -> str:
    host = os.environ.get("AD_SERVICE_HOST", "localhost")
    return f"http://{host}:{spec.public_port_by_team[team_id]}"


def _register_login(base: str, user: str) -> str | None:
    creds = {"username": user, "password": f"{user}-pass-2026-defense"}
    requests.post(f"{base}/api/register", json=creds, timeout=10)
    r = requests.post(f"{base}/api/login", json=creds, timeout=10)
    if r.status_code != 200:
        return None
    return r.json().get("access_token")


def verify_notes_blocked(team_id: str) -> bool:
    base = _svc_base(NOTES, team_id)
    suffix = str(int(time.time()))[-6:]
    owner_token = _register_login(base, f"defowner{suffix}")
    if not owner_token:
        warn("검증용 계정 준비 실패 — 서비스 상태를 확인하세요.")
        return False
    created = requests.post(
        f"{base}/api/notes", headers={"Authorization": f"Bearer {owner_token}"},
        json={"content": f"defense-probe-{suffix}"}, timeout=10,
    )
    note_id = created.json().get("id") if created.status_code < 400 else None
    attacker_token = _register_login(base, f"defatt{suffix}")
    if note_id is None or not attacker_token:
        warn("검증 요청을 완료하지 못했습니다.")
        return False
    stolen = requests.get(
        f"{base}/api/notes/{note_id}",
        headers={"Authorization": f"Bearer {attacker_token}"}, timeout=10,
    )
    # Patched: another user's note must be indistinguishable from a missing one.
    return stolen.status_code == 404


def verify_vault_blocked(team_id: str) -> bool:
    base = _svc_base(VAULT, team_id)
    suffix = str(int(time.time()))[-6:]
    token = _register_login(base, f"defvault{suffix}")
    if not token:
        warn("검증용 계정 준비 실패 — 서비스 상태를 확인하세요.")
        return False
    probe = requests.get(
        f"{base}/api/files?path=../../system",
        headers={"Authorization": f"Bearer {token}"}, timeout=10,
    )
    if probe.status_code == 404:
        return True
    try:
        return not probe.json().get("entries")
    except ValueError:
        return True


def verify(spec: ServiceSpec, team_id: str) -> bool:
    step("취약점 차단 확인 (Verify)")
    print(f"  이제 방어자가 되어 자신의 서비스를 다시 공격해 봅니다: {spec.vuln}")
    blocked = verify_notes_blocked(team_id) if spec.key == "notes" else verify_vault_blocked(team_id)
    if blocked:
        ok("공격이 차단되었습니다 — 취약점이 성공적으로 방어되었습니다. 🛡️")
    else:
        fail("아직 취약점이 열려 있습니다. 서비스가 아직 재기동 중이거나 패치가 반영되지 않았을 수 있습니다.")
    return blocked


# --------------------------------------------------------------------------- #
def defend_one(spec: ServiceSpec, team_id: str, token: str, args) -> dict:
    print("\n" + "═" * 62)
    print(f"  Defense Mission · {spec.slug}  ({team_id})")
    print("═" * 62)
    tag = f"beginner-{int(time.time())}"
    team_slug = team_id  # slugs match the team id (team-01) in the demo
    if args.dry_run:
        push_tag = patch_reference(PUSH_REGISTRY, team_slug, spec.slug, tag)
        reference = patch_reference(ALLOWED_REGISTRY, team_slug, spec.slug, tag)
        step("계획 (dry-run)")
        print("  " + " ".join(build_command(spec, push_tag, "<base-digest>")))
        print(f"  docker push {push_tag}")
        print(f"  submit -> {reference}")
        return {"service": spec.key, "dry_run": True}
    reference = build_and_push(spec, team_slug, tag)
    patch_id = submit_patch(spec, token, reference)
    status = deploy_patch(spec, token, patch_id, args.max_iterations)
    built = True
    deployed = status == "deployed"
    blocked = verify(spec, team_id) if deployed else False
    return {
        "service": spec.key, "patch_id": patch_id, "status": status,
        "built": built, "deployed": deployed, "vulnerability_blocked": blocked,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Beginner Blue Team one-command defense")
    parser.add_argument(
        "--service", choices=["notes", "vault", "both"], default="notes",
        help="어떤 서비스를 방어할지 (기본: notes)",
    )
    parser.add_argument("--team", default="team-01", choices=list(TEAM_LOGINS))
    parser.add_argument("--max-iterations", type=int, default=12)
    parser.add_argument("--dry-run", action="store_true", help="실제 실행 없이 계획만 표시")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    services = [NOTES, VAULT] if args.service == "both" else [SPECS[args.service]]
    print("\n\033[1;35mCYBER RANGE · Beginner Blue Team Defense\033[0m")
    print(f"Team {args.team} 의 서비스를 자동으로 패치·배포·검증합니다.")
    if not args.dry_run:
        preflight()
        token = competitor_token(args.team)
        ok(f"{args.team} 참가자 인증 완료")
    else:
        token = ""
    results = [defend_one(spec, args.team, token, args) for spec in services]

    print("\n" + "═" * 62)
    print("  결과 요약 (Summary)")
    print("═" * 62)
    all_ok = True
    for r in results:
        if r.get("dry_run"):
            print(f"  {r['service']:<7} · dry-run")
            continue
        line = (
            f"  {r['service']:<7} · 빌드 {'✓' if r['built'] else '✗'}"
            f"  배포 {'✓' if r['deployed'] else '✗'}"
            f"  취약점차단 {'✓' if r['vulnerability_blocked'] else '✗'}"
        )
        print(line)
        all_ok = all_ok and r["vulnerability_blocked"]
    if not args.dry_run:
        print("\n" + ("  🎉 방어 완료! START HERE 화면에서 Defense 단계가 완료로 표시됩니다."
                       if all_ok else
                       "  일부 단계가 완료되지 않았습니다. 위 로그를 확인하세요."))
    return 0 if (all_ok or args.dry_run) else 1


if __name__ == "__main__":
    raise SystemExit(main())
