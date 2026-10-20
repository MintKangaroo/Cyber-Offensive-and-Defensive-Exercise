#!/usr/bin/env python3
"""탄력적 N팀 A/D 게임넷 프로비저닝 제너레이터.

docker-compose.yml 은 A/D 팀을 정확히 3개(ad_team_01/02/03)로 하드와이어하고,
infra/match/ad_target_gateway.conf 는 그 3팀의 nginx 업스트림만 나열한다. 대회 규모(N팀)로
확장하려면 수작업으로 동일 블록을 복제해야 했다 — 오타/포트충돌/격리 누락 위험.

이 제너레이터는 단일 소스(`--n N` 또는 `--teams-file <YAML>`)에서 다음을 **렌더**한다:
  1. N팀 A/D 서비스(notes/vault/grid)를 담은 compose **오버레이**
     (base 위에 `-f base -f <generated>` 로 얹는다 — 커밋된 3팀 베이스라인을 건드리지 않음).
  2. 전체 N팀 nginx 업스트림을 담은 ad_target_gateway.conf (게이트웨이 conf 는 전량 치환).
  3. (옵션) 기존 kubernetes_runtime.py 템플릿으로 팀별 네임스페이스/NetworkPolicy 매니페스트.

설계 불변식(베이스라인 패턴에서 보존):
  - 포트 오프셋: notes=9100+N, vault=9200+N, grid=9300+N (팀당 3포트, 1<=N<=99 비충돌).
  - internal 망 격리: 팀 서비스는 [ad_team_access, ad_game_attack] 에만 — host 직접 도달 불가.
  - host 발행은 ad_target_gateway(게임 포트 9000 만, 관리 9001 은 절대 비노출) 단일 지점.
  - 서비스키(ad_team_NN_svc) ≠ container_name: 베이스라인처럼 container_name 을 지정하지 않는다
    (compose 가 프로젝트명으로 유일화 → 매치/프로젝트 병렬 기동 시 충돌 없음).

사용:
  python3 scripts/provision/gen_ad_teams.py --n 5
  python3 scripts/provision/gen_ad_teams.py --teams-file teams.yaml --out-dir infra/match/generated
  docker compose -f docker-compose.yml -f infra/match/generated/docker-compose.ad-teams.gen.yml config
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML 은 저장소 표준 의존성
    raise SystemExit("PyYAML 필요: pip install pyyaml")

# 베이스라인에 이미 하드와이어된 팀 수(docker-compose.yml). 오버레이는 이 수를 초과하는
# 팀만 새로 정의한다(compose 는 서비스를 '제거'할 수 없으므로 축소는 베이스 수정이 필요).
BASELINE_TEAMS = 3

# notes/vault/grid 세 역할. (서비스키 접미사, host 포트 base, 이미지 태그, Dockerfile).
SERVICES = (
    ("notes", 9100, "cyber-range/ad-vulnerable-notes:base",
     "services/attack_defense/demo_services/vulnerable_notes/Dockerfile"),
    ("vault", 9200, "cyber-range/ad-file-vault:base",
     "services/attack_defense/demo_services/file_vault/Dockerfile"),
    ("grid", 9300, "cyber-range/ad-grid-scada:base",
     "services/attack_defense/demo_services/grid_scada/Dockerfile"),
)

GAME_PORT = 9000          # 팀 서비스 컨테이너 내부 게임 포트
MAX_TEAMS = 99            # 9100~9199 / 9200~9299 / 9300~9399 범위 내 비충돌 상한

# x-ad-service-security 앵커(docker-compose.yml L11) — 오버레이는 별도 YAML 문서라
# base 의 앵커를 참조할 수 없으므로 동일 값을 인라인한다.
SECURITY = {
    "read_only": True,
    "tmpfs": ["/tmp:rw,noexec,nosuid,size=32m"],
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "pids_limit": 128,
    "mem_limit": "256m",
    "cpus": 0.50,
    "restart": "unless-stopped",
}

# &ad-service-env 앵커(docker-compose.yml L580) 동일 값 인라인.
SERVICE_ENV = {
    "ATTACK_DEFENSE_MANAGEMENT_TOKEN":
        "${ATTACK_DEFENSE_MANAGEMENT_TOKEN:-attack-defense-dev-management-token}",
    "SIEM_LOG_DIR": "/var/log/siem/attack_defense",
    "SIEM_ASSET": "attack_defense",
}

GATEWAY_CONF_TARGET = "/etc/nginx/conf.d/default.conf"


def team_slug(n: int) -> str:
    """팀 번호 → 베이스라인 관례의 2자리 제로패딩 슬러그(ad_team_01 ...)."""
    return f"ad_team_{n:02d}"


def host_port(service_base: int, n: int) -> int:
    return service_base + n


def validate_n(n: int) -> None:
    if n < 1:
        raise ValueError("팀 수는 1 이상이어야 한다")
    if n > MAX_TEAMS:
        raise ValueError(
            f"팀 수 {n} > {MAX_TEAMS}: 포트 범위(91xx/92xx/93xx)가 충돌한다 — "
            "스킴 재설계 필요"
        )


def team_ids_from_args(args: argparse.Namespace) -> int:
    """소스(--n 또는 --teams-file)에서 총 팀 수를 도출한다."""
    if args.teams_file:
        data = yaml.safe_load(Path(args.teams_file).read_text(encoding="utf-8"))
        teams = data.get("teams") if isinstance(data, dict) else data
        if not isinstance(teams, list) or not teams:
            raise ValueError("teams-file 에 비어있지 않은 'teams' 리스트가 필요하다")
        return len(teams)
    return int(args.n)


# --------------------------------------------------------------------------- #
# compose 오버레이 렌더
# --------------------------------------------------------------------------- #
def _team_service(n: int, suffix: str, port_base: int, image: str,
                  dockerfile: str, build_context: str) -> dict[str, Any]:
    slug = team_slug(n)
    key = f"{slug}_{suffix}"
    env_var = f"AD_IMAGE_{key.upper()}"
    service: dict[str, Any] = {
        "depends_on": {
            "siem_logs_init": {"condition": "service_completed_successfully"},
        },
        **{k: (list(v) if isinstance(v, list) else v) for k, v in SECURITY.items()},
        "image": f"${{{env_var}:-{image}}}",
        "build": {"context": build_context, "dockerfile": dockerfile},
        "ports": [f"{host_port(port_base, n)}:{GAME_PORT}"],
        "environment": dict(SERVICE_ENV),
        "volumes": [
            f"{key}_data:/data",
            {
                "type": "volume",
                "source": "siem_logs",
                "target": "/var/log/siem/attack_defense",
                "volume": {"subpath": "attack_defense"},
            },
        ],
        "networks": ["ad_team_access", "ad_game_attack"],
    }
    return service


def render_compose_overlay(total: int, baseline: int, build_context: str) -> dict[str, Any]:
    """baseline 초과 팀(baseline+1 .. total)만 새 서비스로 정의하는 오버레이.

    베이스라인(1..baseline)은 docker-compose.yml 이 이미 정의하므로 건드리지 않는다.
    게이트웨이 ports(신규 팀 분)와 conf 마운트는 머지로 치환/합집합된다.
    """
    services: dict[str, Any] = {}
    volumes: dict[str, Any] = {}
    new_gateway_ports: list[str] = []

    new_teams = range(baseline + 1, total + 1)
    for n in new_teams:
        slug = team_slug(n)
        for suffix, port_base, image, dockerfile in SERVICES:
            key = f"{slug}_{suffix}"
            services[key] = _team_service(
                n, suffix, port_base, image, dockerfile, build_context
            )
            volumes[f"{key}_data"] = {}
            p = host_port(port_base, n)
            new_gateway_ports.append(f"{p}:{p}")

    # 게이트웨이: 신규 팀 포트 발행 + 전량 치환된 generated conf 마운트.
    # ports 는 compose 머지에서 합집합(base 1..baseline + overlay 신규) → 전체 1..total.
    # volumes 는 target 키로 머지되어 overlay 소스가 base 를 치환한다.
    gateway: dict[str, Any] = {
        "volumes": [f"./ad_target_gateway.gen.conf:{GATEWAY_CONF_TARGET}:ro"],
    }
    if new_gateway_ports:
        gateway["ports"] = new_gateway_ports
    services["ad_target_gateway"] = gateway

    overlay: dict[str, Any] = {"services": services}
    if volumes:
        overlay["volumes"] = volumes
    return overlay


# --------------------------------------------------------------------------- #
# nginx gateway conf 렌더 (전체 1..total — 전량 치환)
# --------------------------------------------------------------------------- #
CONF_HEADER = """# A/D 공격 타깃 게이트웨이 — GENERATED by scripts/provision/gen_ad_teams.py
# ================================================
# 이 파일은 N팀 프로비저닝 제너레이터가 렌더한 산출물이다. 직접 수정하지 말 것.
# 베이스라인 ad_target_gateway.conf 와 동일 관례:
#  - 팀 취약 서비스(notes/vault/grid)는 internal 망(ad_team_access)에 격리되어 host 직접 도달 불가.
#    이 게이트웨이만 internal↔host 를 잇는 단일 통제 지점으로 게임 포트(91xx/92xx/93xx)를 발행한다.
#  - 게임(공격) 포트 9000 만 프록시한다. 관리 포트 9001 은 절대 노출하지 않는다.
#  - 컨테이너명 대신 compose 서비스 별칭 + Docker 임베디드 DNS(127.0.0.11) 로 요청 시점 해석.
#  - 감사 S-9: X-Forwarded-For($remote_addr) 주입 → SIEM access 로그가 실 공격 출발지 IP 를
#    기록(게이트웨이 IP 로 뭉개지지 않음) → 팀 귀속 가능.
"""

SERVER_BLOCK = """server {{
    listen {port};
    resolver 127.0.0.11 valid=10s ipv6=off;
    location / {{ set $u {upstream}:{game_port}; proxy_pass http://$u; proxy_set_header Host $host; proxy_set_header X-Forwarded-For $remote_addr; proxy_read_timeout 15s; }}
}}"""


def render_gateway_conf(total: int) -> str:
    parts = [CONF_HEADER]
    for n in range(1, total + 1):
        slug = team_slug(n)
        parts.append(f"\n# team-{n:02d}")
        for suffix, port_base, _img, _df in SERVICES:
            parts.append(SERVER_BLOCK.format(
                port=host_port(port_base, n),
                upstream=f"{slug}_{suffix}",
                game_port=GAME_PORT,
            ))
    return "\n".join(parts) + "\n"


# --------------------------------------------------------------------------- #
# (옵션) Kubernetes 매니페스트 — 기존 kubernetes_runtime.py 템플릿 재사용
# --------------------------------------------------------------------------- #
def render_k8s_manifests(total: int) -> str:
    """팀×서비스 인스턴스를 build_manifests 로 렌더(기존 템플릿 재사용).

    실 클러스터 apply 경로가 아니라 '템플릿 산출물'이다 — 이미지는 자리표시 digest 로 핀.
    매니페스트는 validate_manifests 로 구조 검증한다. 실 apply 는 클러스터 필요(UNVERIFIED).
    """
    import sys
    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root))
    from services.attack_defense.kubernetes_runtime import (  # noqa: E402
        KubernetesRuntimeConfig, build_manifests, validate_manifests,
    )

    registry = "registry.local:5000"
    # 자리표시 핀 이미지(sha256). 실 배포 시 런타임이 빌드 digest 로 치환한다.
    placeholder_digest = "sha256:" + "0" * 64
    config = KubernetesRuntimeConfig(
        allowed_registry=registry,
        image_registry=registry,
        management_master_token="gen-placeholder-master-token",  # training-only
        dry_run=True,
    )

    docs: list[str] = [
        "# GENERATED by scripts/provision/gen_ad_teams.py --k8s\n"
        "# 팀별 네임스페이스 + default-deny-all NetworkPolicy + scoped ingress 를 포함한다.\n"
        "# 실 apply: kubectl apply -f <this-file>  (클러스터 필요 — 여기서는 UNVERIFIED)\n"
    ]
    for n in range(1, total + 1):
        slug = team_slug(n)
        for suffix, _pb, image, _df in SERVICES:
            instance = {
                "match_id": "match",
                "team_slug": slug,
                "service_slug": f"{slug}-{suffix}",
                "runtime_id": f"{slug}-{suffix}",
                "internal_port": GAME_PORT,
                "image_reference": f"{registry}/{image.rsplit(':', 1)[0]}@{placeholder_digest}",
            }
            resources = build_manifests(instance, config)
            violations = validate_manifests(resources, config, sandbox=False)
            if violations:
                raise ValueError(
                    f"{slug}/{suffix} k8s 매니페스트 검증 실패: {violations}"
                )
            for res in resources:
                docs.append(yaml.safe_dump(res, sort_keys=False, allow_unicode=True))
    return "---\n".join(docs)


# --------------------------------------------------------------------------- #
def generate(total: int, out_dir: Path, baseline: int = BASELINE_TEAMS,
             k8s: bool = False, repo_root: Path | None = None) -> dict[str, Path]:
    """산출물을 out_dir 에 쓰고 {이름: 경로} 를 반환한다."""
    validate_n(total)
    out_dir.mkdir(parents=True, exist_ok=True)

    root = (repo_root or Path(__file__).resolve().parents[2]).resolve()
    # 오버레이 내 build context 는 '오버레이 파일 위치' 기준으로 해석된다(compose 규칙) →
    # out_dir 에서 repo_root 로의 상대경로를 계산해 넣는다.
    build_context = os.path.relpath(root, out_dir.resolve()) or "."

    written: dict[str, Path] = {}

    overlay = render_compose_overlay(total, baseline, build_context)
    overlay_path = out_dir / "docker-compose.ad-teams.gen.yml"
    overlay_path.write_text(
        "# GENERATED by scripts/provision/gen_ad_teams.py — 직접 수정 금지.\n"
        f"# 팀 수={total} (베이스라인 {baseline}팀은 docker-compose.yml 정의, 여기선 초과분만).\n"
        "# 사용: docker compose -f docker-compose.yml -f <this> config\n"
        + yaml.safe_dump(overlay, sort_keys=False, allow_unicode=True, width=4096),
        encoding="utf-8",
    )
    written["compose"] = overlay_path

    conf_path = out_dir / "ad_target_gateway.gen.conf"
    conf_path.write_text(render_gateway_conf(total), encoding="utf-8")
    written["gateway_conf"] = conf_path

    if k8s:
        k8s_path = out_dir / "ad-teams.k8s.gen.yaml"
        k8s_path.write_text(render_k8s_manifests(total), encoding="utf-8")
        written["k8s"] = k8s_path

    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="N팀 A/D 게임넷 compose 오버레이 + nginx conf 제너레이터"
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--n", type=int, help="A/D 팀 수(1..99)")
    src.add_argument("--teams-file", help="'teams' 리스트를 담은 YAML(길이=팀 수)")
    parser.add_argument(
        "--out-dir", default="infra/match/generated",
        help="산출물 디렉터리(기본: infra/match/generated)",
    )
    parser.add_argument(
        "--baseline", type=int, default=BASELINE_TEAMS,
        help=f"docker-compose.yml 에 하드와이어된 팀 수(기본 {BASELINE_TEAMS})",
    )
    parser.add_argument("--k8s", action="store_true",
                        help="추가로 k8s 매니페스트 렌더(기존 템플릿 재사용)")
    args = parser.parse_args(argv)

    total = team_ids_from_args(args)
    written = generate(total, Path(args.out_dir), baseline=args.baseline, k8s=args.k8s)

    print(f"✅ {total}팀 렌더 완료:")
    for name, path in written.items():
        print(f"  [{name}] {path}")
    print("\n검증:")
    print("  docker compose -f docker-compose.yml "
          f"-f {written['compose']} config >/dev/null && echo OK")
    print(f"  nginx -t -c <(cat {written['gateway_conf']})   # 또는 구조 파싱")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
