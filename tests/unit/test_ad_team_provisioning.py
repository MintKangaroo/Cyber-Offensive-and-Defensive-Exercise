"""N팀 A/D 게임넷 프로비저닝 제너레이터 회귀 테스트.

대회급 격차 #1(탄력적 N팀 프로비저닝): docker-compose.yml 의 하드와이어 3팀을
config-driven N팀으로 확장하는 scripts/provision/gen_ad_teams.py 를 고정한다.

도커/nginx 불필요(순수 파이썬). 실제 `docker compose config` / `nginx -t` 는 PR 설명의
수동 검증 절차로 분리한다(유닛 CI 잡은 도커 없이 돈다).
"""
import importlib.util
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
GEN_PATH = REPO_ROOT / "scripts" / "provision" / "gen_ad_teams.py"


def _load_generator():
    spec = importlib.util.spec_from_file_location("gen_ad_teams", GEN_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gen = _load_generator()


# --------------------------------------------------------------------------- #
# 출력 형태 / N팀 렌더
# --------------------------------------------------------------------------- #
def test_outputs_written(tmp_path):
    written = gen.generate(5, tmp_path)
    assert written["compose"].is_file()
    assert written["gateway_conf"].is_file()
    # k8s 는 기본 미생성.
    assert "k8s" not in written


def test_overlay_renders_only_teams_beyond_baseline(tmp_path):
    written = gen.generate(5, tmp_path, baseline=3)
    overlay = yaml.safe_load(written["compose"].read_text())
    team_services = sorted(
        k for k in overlay["services"] if k.startswith("ad_team_")
    )
    # baseline=3 → 신규 팀 4,5 × 3서비스 = 6개. 1~3은 base 가 정의하므로 포함 안 함.
    assert team_services == [
        "ad_team_04_grid", "ad_team_04_notes", "ad_team_04_vault",
        "ad_team_05_grid", "ad_team_05_notes", "ad_team_05_vault",
    ]
    # 신규 팀 데이터 볼륨 6개.
    assert len(overlay["volumes"]) == 6


def test_gateway_conf_has_all_teams(tmp_path):
    written = gen.generate(5, tmp_path)
    conf = written["gateway_conf"].read_text()
    # notes/vault/grid × 5팀 = 15 업스트림.
    locations = [ln for ln in conf.splitlines() if "proxy_pass" in ln]
    assert len(locations) == 15
    listens = sorted(int(m.group(1)) for m in re.finditer(r"listen (\d+);", conf))
    expected = sorted(
        [9100 + n for n in range(1, 6)]
        + [9200 + n for n in range(1, 6)]
        + [9300 + n for n in range(1, 6)]
    )
    assert listens == expected


# --------------------------------------------------------------------------- #
# 포트 비충돌 / 격리 불변식
# --------------------------------------------------------------------------- #
def test_ports_never_collide_up_to_max(tmp_path):
    # 전체 범위(1..MAX_TEAMS)에서 host 포트가 겹치지 않는다.
    ports = []
    for n in range(1, gen.MAX_TEAMS + 1):
        for _suffix, base, _img, _df in gen.SERVICES:
            ports.append(gen.host_port(base, n))
    assert len(ports) == len(set(ports)), "host 포트 충돌 발생"


def test_overlay_gateway_ports_match_new_teams(tmp_path):
    written = gen.generate(5, tmp_path, baseline=3)
    overlay = yaml.safe_load(written["compose"].read_text())
    gw_ports = overlay["services"]["ad_target_gateway"]["ports"]
    published = sorted(int(p.split(":")[0]) for p in gw_ports)
    # 신규 팀 4,5 분만 오버레이에 발행(base 1~3 과 머지되어 합집합).
    assert published == [9104, 9105, 9204, 9205, 9304, 9305]


def test_team_services_are_network_isolated(tmp_path):
    written = gen.generate(4, tmp_path, baseline=3)
    overlay = yaml.safe_load(written["compose"].read_text())
    svc = overlay["services"]["ad_team_04_notes"]
    # internal 망에만 — host 직접 도달 불가(격리). ad_target_ingress 금지.
    assert sorted(svc["networks"]) == ["ad_game_attack", "ad_team_access"]
    assert "ad_target_ingress" not in svc["networks"]
    # 하드닝 불변식 유지.
    assert svc["read_only"] is True
    assert svc["cap_drop"] == ["ALL"]
    assert svc["security_opt"] == ["no-new-privileges:true"]


def test_gateway_never_exposes_management_port(tmp_path):
    # 회귀: 생성 conf 가 관리 포트 9001 로 프록시하지 않는다.
    written = gen.generate(7, tmp_path)
    conf = written["gateway_conf"].read_text()
    directives = [
        ln.strip() for ln in conf.splitlines() if not ln.strip().startswith("#")
    ]
    for ln in directives:
        if ln.startswith("listen"):
            assert ":9001" not in ln and " 9001;" not in ln
        if "set $u" in ln:
            assert ":9000;" in ln, f"게임 포트 9000 이외로 프록시: {ln}"


def test_gateway_conf_injects_xff_everywhere(tmp_path):
    # S-9 회귀: 모든 proxy location 이 실 클라이언트 IP 로 X-Forwarded-For 주입.
    written = gen.generate(6, tmp_path)
    conf = written["gateway_conf"].read_text()
    locations = [ln for ln in conf.splitlines() if "proxy_pass" in ln]
    assert locations
    for ln in locations:
        assert re.search(r"X-Forwarded-For\s+\$remote_addr", ln), ln


# --------------------------------------------------------------------------- #
# 멱등성 / 소스 / 경계
# --------------------------------------------------------------------------- #
def test_idempotent(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    first = gen.generate(5, a)
    second = gen.generate(5, b)
    assert first["compose"].read_bytes() == second["compose"].read_bytes()
    assert first["gateway_conf"].read_bytes() == second["gateway_conf"].read_bytes()


def test_build_context_points_to_repo_root(tmp_path):
    # 오버레이 build context 는 '오버레이 파일 위치' 기준 상대경로로 repo 루트를 가리켜야
    # compose 다중파일 context 해석 규칙에서 Dockerfile 을 찾을 수 있다.
    out = REPO_ROOT / "infra" / "match" / "generated"
    overlay = gen.render_compose_overlay(4, 3, build_context="../../..")
    ctx = overlay["services"]["ad_team_04_notes"]["build"]["context"]
    # 기본 out-dir(infra/match/generated)에서 루트까지는 ../../.. 3단계.
    resolved = (out / ctx).resolve()
    assert resolved == REPO_ROOT


def test_teams_file_source(tmp_path):
    tf = tmp_path / "teams.yaml"
    tf.write_text("teams:\n  - alpha\n  - bravo\n  - charlie\n  - delta\n")
    import argparse
    ns = argparse.Namespace(n=None, teams_file=str(tf))
    assert gen.team_ids_from_args(ns) == 4


def test_rejects_out_of_range(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        gen.generate(0, tmp_path)
    with pytest.raises(ValueError):
        gen.generate(gen.MAX_TEAMS + 1, tmp_path)


def test_slug_is_zero_padded():
    assert gen.team_slug(1) == "ad_team_01"
    assert gen.team_slug(12) == "ad_team_12"
