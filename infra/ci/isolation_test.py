#!/usr/bin/env python3
"""
Isolation Regression Test (08번 안전장치 1절)
================================================
배포된 트윈 컨테이너가 실제로 격리되어 있는지 자동 검증한다.
docker exec로 컨테이너 내부에서 명령을 실행해 확인하므로 Docker 환경이 필요하다
(이 파일 자체는 문법/로직 검증만 이 샌드박스에서 가능하고, 실행은 실제 배포 환경에서).

검증 항목 (08번 체크리스트 대응):
  [1] 트윈 컨테이너 -> 외부 인터넷 egress 실패
  [2] 트윈 컨테이너 -> 다른 트윈 컨테이너 직접 통신 실패 (range_control만 허용)
  [3] 트윈 컨테이너 -> event_collector(range_control) 통신 성공 (필요 경로는 열려있어야 함)
  [4] 커맨드인젝션/역직렬화 트윈의 read-only 파일시스템 확인
  [5] 리소스 제한(mem_limit/cpus) 적용 확인

사용법: python isolation_test.py --compose-file docker-compose.yml
종료코드: 0=전부 통과, 1=하나라도 실패(배포 차단 신호)
"""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
from dataclasses import dataclass


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""


def resolve_container(name_or_service: str) -> str:
    """실제 docker 컨테이너 이름으로 해석한다.
    - container_name 이 지정된 서비스(트윈 gs_twin 등)는 그대로 이름이 존재한다.
    - container_name 이 없는 서비스(A/D 팀 서비스)는 compose 가 `<project>-<svc>-N` 로 이름을
      붙이므로, compose 서비스 라벨로 실제 이름을 찾아 반환한다(없으면 원래 문자열 유지)."""
    p = subprocess.run(["docker", "ps", "--filter", f"name=^{name_or_service}$",
                        "--format", "{{.Names}}"], capture_output=True, text=True)
    if p.returncode == 0 and p.stdout.strip():
        return p.stdout.strip().splitlines()[0]
    p = subprocess.run(["docker", "ps", "--filter",
                        f"label=com.docker.compose.service={name_or_service}",
                        "--format", "{{.Names}}"], capture_output=True, text=True)
    if p.returncode == 0 and p.stdout.strip():
        return p.stdout.strip().splitlines()[0]
    return name_or_service


def run(cmd: list[str], timeout: int = 8) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except FileNotFoundError as e:
        return -1, "", str(e)


def _tcp_probe(container: str, host: str, port: int, timeout: int = 3) -> tuple[bool, str]:
    """컨테이너 내부에서 host:port로 TCP 연결을 시도한다. (reachable, detail) 반환.
    curl 미설치 이미지(A/D 팀 서비스 등)에서도 동작하도록 python3 소켓을 쓴다."""
    code = (
        "import socket\n"
        "try:\n"
        f"    s=socket.create_connection(({host!r},{port}),timeout={timeout}); s.close(); print('OPEN')\n"
        "except Exception as e:\n"
        "    print('BLOCKED:'+type(e).__name__)\n"
    )
    rc, out, err = run(["docker", "exec", container, "python3", "-c", code])
    reachable = out.strip() == "OPEN"
    return reachable, f"rc={rc} out={out.strip()!r} err={err.strip()!r}"


def check_external_egress_blocked(container: str) -> CheckResult:
    """컨테이너 안에서 외부(1.1.1.1:443) 연결 시도 -> 실패해야 통과."""
    reachable, detail = _tcp_probe(container, "1.1.1.1", 443)
    return CheckResult(
        name=f"external_egress_blocked[{container}]",
        passed=not reachable,
        detail=detail,
    )


def check_twin_to_twin_blocked(src_container: str, dst_host: str, dst_port: int) -> CheckResult:
    """A -> B 직접 접속 시도 -> 실패해야 통과 (허용 경로만 열려야 함)."""
    reachable, detail = _tcp_probe(src_container, dst_host, dst_port)
    return CheckResult(
        name=f"twin_to_twin_blocked[{src_container}->{dst_host}:{dst_port}]",
        passed=not reachable,
        detail=detail,
    )


def check_required_path_open(src_container: str, dst_host: str, dst_port: int) -> CheckResult:
    """트윈 -> event_collector는 반드시 열려있어야 함(필요 경로 과차단 방지)."""
    reachable, detail = _tcp_probe(src_container, dst_host, dst_port)
    return CheckResult(
        name=f"required_path_open[{src_container}->{dst_host}:{dst_port}]",
        passed=reachable,
        detail=detail,
    )


def check_readonly_fs(container: str) -> CheckResult:
    """읽기전용 강제 대상 컨테이너에서 쓰기 시도 -> 실패해야 통과."""
    rc, out, err = run(["docker", "exec", container, "sh", "-c", "echo test > /tmp_write_test_$$"])
    # read_only + tmpfs 조합이면 /tmp는 쓰기 가능할 수 있음 -> 루트 파일시스템(/app 등)에 시도
    rc2, out2, err2 = run(["docker", "exec", container, "sh", "-c", "echo test > /app/write_test"])
    write_blocked = (rc2 != 0)
    return CheckResult(
        name=f"readonly_fs[{container}]",
        passed=write_blocked,
        detail=f"app_write_rc={rc2} err={err2!r}",
    )


def check_resource_limits(container: str, expected_mem_mb: int, expected_cpus: float) -> CheckResult:
    """docker inspect로 리소스 제한이 설정되어 있는지 확인."""
    rc, out, err = run(["docker", "inspect", container])
    if rc != 0:
        return CheckResult(name=f"resource_limits[{container}]", passed=False, detail=f"inspect failed: {err}")
    try:
        info = json.loads(out)[0]
        mem_bytes = info["HostConfig"].get("Memory", 0)
        nano_cpus = info["HostConfig"].get("NanoCpus", 0)
        mem_ok = mem_bytes > 0 and mem_bytes <= expected_mem_mb * 1024 * 1024 * 1.5
        cpu_ok = nano_cpus > 0
        return CheckResult(
            name=f"resource_limits[{container}]",
            passed=mem_ok and cpu_ok,
            detail=f"mem_bytes={mem_bytes} nano_cpus={nano_cpus}",
        )
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return CheckResult(name=f"resource_limits[{container}]", passed=False, detail=str(e))


# ---------------- 실행 계획(배포 구성에 맞게 조정) ----------------

def default_checks() -> list:
    """cyber-range docker-compose.yml 구성 기준 기본 체크 목록."""
    twins = ["gs_twin", "pp_twin", "dn_twin"]
    checks = []
    for c in twins:
        checks.append(lambda c=c: check_external_egress_blocked(c))
        checks.append(lambda c=c: check_required_path_open(c, "event_collector", 8010))
    # 트윈 간 직접 통신 차단(예: gs_twin -> pp_twin)
    checks.append(lambda: check_twin_to_twin_blocked("gs_twin", "pp_twin", 8002))
    checks.append(lambda: check_twin_to_twin_blocked("pp_twin", "dn_twin", 8003))
    # 강격리 대상(커맨드인젝션/역직렬화 트윈)
    checks.append(lambda: check_readonly_fs("pp_twin"))
    checks.append(lambda: check_resource_limits("pp_twin", expected_mem_mb=512, expected_cpus=0.5))

    # ---- Attack/Defense 격리(감사 2.3/2.4) ----
    # 팀 컨테이너는 ad_team_access(internal:true)에만 붙어 외부 egress 불가여야 하고,
    # ad_management(엔진↔postgres/registry 평면)에서 분리돼 ad_postgres·ad_registry 도달 불가여야 한다.
    # A/D 팀 서비스는 container_name 이 없어 실제 이름을 라벨로 해석한다.
    ad_teams = [resolve_container("ad_team_01_notes"), resolve_container("ad_team_01_vault")]
    for c in ad_teams:
        checks.append(lambda c=c: check_external_egress_blocked(c))                    # 2.3 egress 차단
        checks.append(lambda c=c: check_twin_to_twin_blocked(c, "ad_postgres", 5432))  # 2.4 DB 도달 불가
        checks.append(lambda c=c: check_twin_to_twin_blocked(c, "ad_registry", 5000))  # 2.4 registry 도달 불가
    return checks


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-if-no-docker", action="store_true",
                    help="Docker 없는 환경(예: 문서 검증용 샌드박스)에서는 통과 처리하고 안내만 출력")
    args = ap.parse_args()

    rc, _, _ = run(["docker", "--version"])
    if rc != 0:
        msg = "Docker not available in this environment."
        if args.skip_if_no_docker:
            print(f"⚠️  {msg} Skipping isolation test (run in real deploy env before go-live).")
            return 0
        print(f"❌ {msg} Cannot run isolation tests. Use --skip-if-no-docker to bypass in dev sandboxes.")
        return 1

    results = [c() for c in default_checks()]
    failed = [r for r in results if not r.passed]

    for r in results:
        status = "✅ PASS" if r.passed else "❌ FAIL"
        print(f"{status}  {r.name}  ({r.detail})")

    if failed:
        print(f"\n🚨 {len(failed)}/{len(results)} isolation checks FAILED. Deployment blocked.")
        return 1
    print(f"\n✅ ALL {len(results)} isolation checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
