from __future__ import annotations

from fastapi.testclient import TestClient

from services.attack_defense.checker import ManagementSigner
from services.attack_defense.demo_services import common
from services.attack_defense.demo_services.grid_scada import main


def _login(client: TestClient, username: str) -> str:
    password = "correct-horse-battery"
    assert client.post(
        "/api/register", json={"username": username, "password": password}
    ).status_code == 201
    return client.post(
        "/api/login", json={"username": username, "password": password}
    ).json()["access_token"]


def _place_flag(flag: str) -> None:
    management = TestClient(main.management_app)
    signer = ManagementSigner("attack-defense-dev-management-token")
    body = {"slot": "round-slot", "value": flag}
    assert management.post(
        "/management/flags", json=body,
        headers=signer.headers("POST", "/management/flags", body),
    ).status_code == 200


def test_missing_authz_leaks_restricted_point(tmp_path, monkeypatch):
    """의도된 취약점: 인가 누락 → 공격자가 restricted 제어포인트(플래그)를 id 로 탈취."""
    monkeypatch.setattr(common, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "PATCH_ICS_AUTHZ", False)
    flag = "FLAG{gridpwn0000000000000000000000000}"
    _place_flag(flag)
    game = TestClient(main.game_app)
    attacker = _login(game, "attacker_op")
    # 포인트 id 를 훑어 restricted 포인트를 찾아낸다(enumeration).
    found = None
    for pid in range(1, 10):
        r = game.get(f"/api/points/{pid}", headers={"Authorization": f"Bearer {attacker}"})
        if r.status_code == 200 and r.json().get("value") == flag:
            found = r.json()
            break
    assert found is not None and found["restricted"] == 1


def test_patch_blocks_read_but_benign_and_flag_survive(tmp_path, monkeypatch):
    """방어 패치: 남의 restricted 포인트 열람 차단, 그러나 정상 운영(자기 포인트)·체커 검증은 유지."""
    monkeypatch.setattr(common, "DATA_DIR", tmp_path)
    monkeypatch.setattr(main, "PATCH_ICS_AUTHZ", True)
    flag = "FLAG{gridpwn1111111111111111111111111}"
    _place_flag(flag)
    game = TestClient(main.game_app)
    owner = _login(game, "grid_owner")
    attacker = _login(game, "grid_attacker")
    # 정상 운영: 자기 포인트 등록·읽기는 그대로 동작(benign SLA 보존).
    pid = game.post(
        "/api/points", json={"label": "SETPOINT_A", "value": "60.0Hz"},
        headers={"Authorization": f"Bearer {owner}"},
    ).json()["id"]
    assert game.get(
        f"/api/points/{pid}", headers={"Authorization": f"Bearer {owner}"}
    ).json()["value"] == "60.0Hz"
    # 공격자는 restricted 시스템 포인트(플래그)를 더 이상 못 읽는다.
    leaked = False
    for scan in range(1, 10):
        r = game.get(f"/api/points/{scan}", headers={"Authorization": f"Bearer {attacker}"})
        if r.status_code == 200 and r.json().get("value") == flag:
            leaked = True
    assert not leaked
    # 체커의 플래그 검증은 여전히 성공(관리 경로는 패치와 무관).
    management = TestClient(main.management_app)
    signer = ManagementSigner("attack-defense-dev-management-token")
    body = {"slot": "round-slot", "value": flag}
    assert management.post(
        "/management/flags/verify", json=body,
        headers=signer.headers("POST", "/management/flags/verify", body),
    ).json() == {"verified": True}


def test_browser_workbench_origin_is_allowed(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "DATA_DIR", tmp_path)
    response = TestClient(main.game_app).options(
        "/api/version",
        headers={
            "Origin": "http://localhost:5176",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5176"
