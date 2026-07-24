"""
Functional (exploit-level) verifier for standalone WEB challenges — no docker.

`run_all.py --skip-docker` 는 스키마+안전성 검사만 하고 익스플로잇을 실제로 돌리지 않는다.
이 스크립트는 docker 없이도 deploy/main.py 를 uvicorn(subprocess)으로 띄워 실제 공격을
수행하고 채점 계약까지 검증한다:
  VULNERABLE 모드: 익스플로잇 -> 플래그, grade_red 통과, 빈 제출 거부, 플래그 결정성
  PATCHED 모드   : grade_blue 통과, 재익스플로잇 차단

리포 경로에 독립적(스크립트 위치 기준 상대경로). challenges/web/<ID>/ 구조를 가정.

사용법:
  python3 infra/challenge_qa/functional_verify.py WEB-003 PATCH_WEB_003
  python3 infra/challenge_qa/functional_verify.py --all      # 등록된 3종 전부
"""
import importlib.util
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

# 스크립트 위치 기준으로 리포 루트/챌린지 루트 해석 (절대경로 하드코딩 없음)
REPO_ROOT = Path(__file__).resolve().parent.parent.parent      # infra/challenge_qa/ -> repo root
CH_ROOT = REPO_ROOT / "challenges" / "web"
TEAM = "qa_team"

# (challenge_id, patch_env_var, challenge_secret)
REGISTRY = {
    "WEB-003": ("PATCH_WEB_003", "web003-dev-secret"),
    "WEB-005": ("PATCH_WEB_005", "web005-dev-secret"),
    "WEB-007": ("PATCH_WEB_007", "web007-dev-secret"),
}


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def wait_port(port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def start_app(cid, patch_var, secret, patched, port):
    env = dict(os.environ)
    env[patch_var] = "true" if patched else "false"
    env["CHALLENGE_SECRET"] = secret
    main_py = CH_ROOT / cid / "deploy" / "main.py"
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(main_py.parent), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if not wait_port(port):
        proc.terminate()
        raise RuntimeError(f"{cid} (patched={patched}) app did not start on {port}")
    return proc


def verify(cid, patch_var, secret):
    print(f"\n{'='*60}\n{cid}  (patch var: {patch_var})\n{'='*60}")
    # 중요: grader/exploit 모듈은 CHALLENGE_SECRET 을 모듈 로드 시점(top-level)에 읽는다.
    # 반드시 load() 이전에 env 를 세팅해야 이전 챌린지의 secret 오염을 막는다.
    os.environ["CHALLENGE_SECRET"] = secret
    exploit = load(CH_ROOT / cid / "solution" / "exploit.py", f"{cid}_exploit")
    red = load(CH_ROOT / cid / "grader" / "red_grader.py", f"{cid}_red")
    blue = load(CH_ROOT / cid / "grader" / "blue_grader.py", f"{cid}_blue")

    port_v, port_p = 8100, 8101
    ok = True

    # ---- VULNERABLE 모드 ----
    proc = start_app(cid, patch_var, secret, patched=False, port=port_v)
    base = f"http://127.0.0.1:{port_v}"
    try:
        flag = exploit.solve(base, TEAM)
        print(f"[1] exploit obtained flag: {flag}")
        r = red.grade_red({"team_id": TEAM, "flag": flag}, {"base_url": base})
        print(f"[2] grade_red(correct flag): passed={r.passed} points={r.points} :: {r.detail}")
        ok &= r.passed
        rb = red.grade_red({"team_id": TEAM, "flag": ""}, {"base_url": base})
        print(f"[3] grade_red(blank):         passed={rb.passed} (must be False)")
        ok &= (not rb.passed)
        flag2 = exploit.solve(base, TEAM)
        det = (flag == flag2)
        print(f"[4] determinism: re-exploit flag == first? {det}")
        ok &= det
    finally:
        proc.terminate(); proc.wait()

    # ---- PATCHED 모드 ----
    proc = start_app(cid, patch_var, secret, patched=True, port=port_p)
    base = f"http://127.0.0.1:{port_p}"
    try:
        gb = blue.grade_blue({"base_url": base, "team_id": TEAM})
        print(f"[5] grade_blue(patched):      passed={gb.passed} points={gb.points} :: {gb.detail}")
        ok &= gb.passed
        try:
            leaked = exploit.solve(base, TEAM)
            print(f"[6] re-exploit on patched: LEAKED {leaked}  (BAD, must fail)")
            ok = False
        except Exception as e:
            print(f"[6] re-exploit on patched: blocked as expected ({type(e).__name__})")
    finally:
        proc.terminate(); proc.wait()

    print(f"RESULT {cid}: {'PASS' if ok else 'FAIL'}")
    return ok


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    if argv[0] == "--all":
        results = {cid: verify(cid, pv, sec) for cid, (pv, sec) in REGISTRY.items()}
        print("\n" + "=" * 60)
        for cid, r in results.items():
            print(f"  {cid}: {'PASS' if r else 'FAIL'}")
        return 0 if all(results.values()) else 1
    cid = argv[0]
    if cid in REGISTRY:
        pv, sec = REGISTRY[cid]
    else:
        # 미등록 챌린지: patch var / secret 를 인자로 받음
        pv = argv[1] if len(argv) > 1 else f"PATCH_{cid.replace('-', '_')}"
        sec = argv[2] if len(argv) > 2 else f"{cid.lower().replace('-', '')}-dev-secret"
    return 0 if verify(cid, pv, sec) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
